"""`build_tools(mandate, session)` — a browser-use `Tools()` whose ONLY effect-bearing
actions are guarded by the frozen `WebMandate`.

INTERCEPTION = CUSTOM GUARDED TOOLS, NOT LIFECYCLE HOOKS (Spec 01 locked decision).
We register our own `navigate` / `click` / `type` / `extract` actions and then PRUNE
the registry down to just these four plus `done`, so the agent has NO ungated path to
a browser effect. The gate (`gate.decide`) runs at the FRONT of every tool body, before
any effect is dispatched. (`on_step_start` is used only to snapshot state into the
session log — never for enforcement; see run.py.)

How each tool performs its REAL effect (browser-use 0.13.1, confirmed against the
installed package — reality wins over the spec's assumptions):
  * navigate -> dispatch `NavigateToUrlEvent(url=...)` on `browser_session.event_bus`
                (exactly what the built-in `navigate` action does).
  * click    -> resolve the DOM node by index (`browser_session.get_element_by_index`)
                then dispatch `ClickElementEvent(node=...)`.
  * type     -> resolve the node by index then dispatch `TypeTextEvent(node=..., text=...)`.
  * extract  -> read-only: `get_current_page_title()` + `get_state_as_text()`.
`browser_session` is dependency-injected by the registry by PARAMETER NAME — the same
mechanism the built-in actions use.

On ALLOW: perform the effect, mint+record an `allow` receipt, return the result.
On BLOCK: perform NOTHING, mint+record a `block` receipt, and return a structured
refusal string ("BLOCKED: ...") that the model reads and re-plans around. We return it
as `extracted_content` (not `error`) so a policy block is a normal, re-plannable result,
not a hard agent failure.
"""
# NOTE: deliberately NO `from __future__ import annotations` here. browser-use's action
# registry compares each parameter's annotation OBJECT against its injected special types
# (e.g. `browser_session: BrowserSession`); PEP 563 string annotations break that check.
from typing import Optional
from urllib.parse import urljoin

from browser_use import Tools
from browser_use.agent.views import ActionResult
from browser_use.browser.events import (
    ClickElementEvent,
    NavigateToUrlEvent,
    TypeTextEvent,
)
from browser_use.browser.session import BrowserSession
from pydantic import BaseModel

from . import gate
from .session import Session
from .web_mandate import FrozenWebMandate

# Built-in actions we KEEP after pruning. `done` lets the agent finish; everything else
# that could touch the browser is removed, leaving only our four guarded actions.
_KEEP_BUILTINS = {"done"}

_MAX_EXTRACT_CHARS = 4000


# ---------- param models (explicit, so the registry never guesses a schema) ----------
class NavigateParams(BaseModel):
    url: str


class ClickParams(BaseModel):
    index: int


class TypeParams(BaseModel):
    index: int
    text: str
    clear: bool = True


class ExtractParams(BaseModel):
    query: str = ""


def _refusal(decision: gate.Decision, action: str, target: str) -> str:
    return f"BLOCKED: {action} to {target!r} refused — {decision.reason}. " \
           f"This target is outside the active scope; choose an in-scope action instead."


def resolve_click_destination(node, current_url: str) -> Optional[str]:
    """Read a click target's NAVIGABLE DESTINATION from a browser-use EnhancedDOMTreeNode
    (0.13.1). Returns an ABSOLUTE URL if the element (or a nearby ancestor) is an anchor with
    a resolvable href; returns None for JS/SPA elements with no static destination (the gate
    then falls back to the scope's click_policy).

    Walks up `parent_node` a bounded number of hops so a click on a <span> inside an <a> still
    finds the link. `href` lives in `node.attributes` (dict[str,str]); relative hrefs and
    fragments are resolved against the current page URL via urljoin. `javascript:`/`#`/empty
    hrefs are treated as non-navigations (None)."""
    cur = node
    for _ in range(8):
        if cur is None:
            break
        tag = (getattr(cur, "tag_name", "") or "").lower()
        attrs = getattr(cur, "attributes", None) or {}
        href = (attrs.get("href") or "").strip()
        if tag == "a" and href:
            low = href.lower()
            if low.startswith("javascript:") or href.startswith("#"):
                return None                                   # not a navigation
            try:
                return urljoin(current_url, href)             # absolute (handles relative/path)
            except Exception:
                return None
        cur = getattr(cur, "parent_node", None) or getattr(cur, "parent", None)
    return None


def build_tools(mandate: FrozenWebMandate, session: Session) -> Tools:
    """Return a `Tools()` exposing only the four guarded actions (+ `done`)."""
    tools = Tools()

    # PRUNE: drop every built-in effect action; the agent keeps no ungated door.
    actions = tools.registry.registry.actions
    for name in list(actions):
        if name not in _KEEP_BUILTINS:
            del actions[name]

    step = {"n": 0}   # closure counter: the proposed-effect ordinal recorded into the session

    def _decide_and_mint(action_type: str, target: str, *, provenance: str,
                         click_destination: Optional[str] = None):
        """Gate the decision (against the mandate's ACTIVE scope, read fresh) and mint its
        receipt. ALWAYS recorded afterwards — whether the decision is BLOCK, the effect
        succeeds, or the effect raises — so the authorization decision is never silently
        dropped because a downstream browser error occurred."""
        step["n"] += 1
        decision = gate.decide(mandate, action_type, target, provenance=provenance,
                               click_destination=click_destination)
        receipt = session.mint_receipt(action=action_type, target=target,
                                       outcome=decision.outcome, active_scope=mandate.active)
        return decision, receipt, step["n"]

    def _blocked(decision: gate.Decision, action: str, target: str) -> ActionResult:
        msg = _refusal(decision, action, target)
        # extracted_content (not error) so a policy block is a normal, re-plannable result.
        return ActionResult(extracted_content=msg, include_in_memory=True, long_term_memory=msg)

    async def _dispatch(browser_session: BrowserSession, event_obj):
        """Dispatch a browser event and surface any handler error (DNS failure, dead node, …)."""
        event = browser_session.event_bus.dispatch(event_obj)
        await event
        await event.event_result(raise_if_any=True, raise_if_none=False)

    # ---- navigate -------------------------------------------------------------------------
    async def navigate(params: NavigateParams, browser_session: BrowserSession):
        url = params.url
        # Agent-supplied navigation targets are page-provenance (untrusted): they may have come
        # from scraped page content and can only be denied, never used to expand the allowlist.
        decision, receipt, n = _decide_and_mint("navigate", url, provenance="page")
        domain = gate.resolve_domain(url) or url
        args = {"url": url}
        if not decision.allowed:
            session.record(n, "navigate", args, decision, receipt,
                           target=domain, performed={"browser": "blocked"})
            return _blocked(decision, "navigate", url)
        try:
            await _dispatch(browser_session, NavigateToUrlEvent(url=url))
        except Exception as e:
            session.record(n, "navigate", args, decision, receipt, target=domain,
                           performed={"browser": f"allowed; effect failed ({type(e).__name__})"})
            msg = f"navigate to {url} was ALLOWED by the mandate but the browser failed: {e}"
            return ActionResult(error=msg, long_term_memory=msg)
        session.record(n, "navigate", args, decision, receipt,
                       target=domain, performed={"browser": f"navigated to {domain}"})
        msg = f"navigated to {url}"
        return ActionResult(extracted_content=msg, include_in_memory=True, long_term_memory=msg)

    # ---- click ----------------------------------------------------------------------------
    async def click(params: ClickParams, browser_session: BrowserSession):
        current = await browser_session.get_current_page_url()
        args = {"index": params.index}
        # Resolve the element FIRST so the gate decides on the click's NAVIGABLE DESTINATION
        # (Spec 02 Part A): an off-scope link is blocked AT the click — ClickElementEvent is
        # never dispatched, so the browser never leaves the site.
        node = await browser_session.get_element_by_index(params.index)
        dest = resolve_click_destination(node, current) if node is not None else None
        decision, receipt, n = _decide_and_mint("click", current, provenance="page",
                                                click_destination=dest)
        cur_domain = gate.resolve_domain(current) or current
        dest_domain = (gate.resolve_domain(dest) or dest) if dest else None
        rec_target = dest_domain or cur_domain
        if not decision.allowed:
            session.record(n, "click", args, decision, receipt, target=rec_target,
                           performed={"browser": "blocked (off-scope link)" if dest else "blocked"})
            return _blocked(decision, "click", dest or cur_domain)
        if node is None:
            msg = f"element index {params.index} not available — page may have changed"
            session.record(n, "click", args, decision, receipt,
                           target=cur_domain, performed={"browser": "no-op (element gone)"})
            return ActionResult(extracted_content=msg, include_in_memory=True)
        try:
            await _dispatch(browser_session, ClickElementEvent(node=node))
        except Exception as e:
            session.record(n, "click", args, decision, receipt, target=rec_target,
                           performed={"browser": f"allowed; effect failed ({type(e).__name__})"})
            msg = f"click {params.index} was ALLOWED but the browser failed: {e}"
            return ActionResult(error=msg, long_term_memory=msg)
        perf = f"clicked index {params.index}" + (f" -> {dest_domain}" if dest_domain else "")
        session.record(n, "click", args, decision, receipt, target=rec_target,
                       performed={"browser": perf})
        msg = f"clicked element {params.index}" + (f" (-> {dest_domain})" if dest_domain else "")
        return ActionResult(extracted_content=msg, include_in_memory=True, long_term_memory=msg)

    # ---- type -----------------------------------------------------------------------------
    # NB: named `type_action`, not `type`, so it does NOT shadow the builtin `type` inside this
    # scope (the except handlers below call `type(e)`). It is registered under the name "type".
    async def type_action(params: TypeParams, browser_session: BrowserSession):
        current = await browser_session.get_current_page_url()
        decision, receipt, n = _decide_and_mint("type", current, provenance="agent")
        domain = gate.resolve_domain(current) or current
        args = {"index": params.index, "text": params.text}
        if not decision.allowed:
            session.record(n, "type", args, decision, receipt,
                           target=domain, performed={"browser": "blocked"})
            return _blocked(decision, "type", domain)
        node = await browser_session.get_element_by_index(params.index)
        if node is None:
            msg = f"element index {params.index} not available — page may have changed"
            session.record(n, "type", args, decision, receipt,
                           target=domain, performed={"browser": "no-op (element gone)"})
            return ActionResult(extracted_content=msg, include_in_memory=True)
        try:
            await _dispatch(browser_session,
                            TypeTextEvent(node=node, text=params.text, clear=params.clear))
        except Exception as e:
            session.record(n, "type", args, decision, receipt, target=domain,
                           performed={"browser": f"allowed; effect failed ({type(e).__name__})"})
            msg = f"type into {params.index} was ALLOWED but the browser failed: {e}"
            return ActionResult(error=msg, long_term_memory=msg)
        session.record(n, "type", args, decision, receipt,
                       target=domain, performed={"browser": f"typed into index {params.index}"})
        msg = f"typed into element {params.index}"
        return ActionResult(extracted_content=msg, include_in_memory=True, long_term_memory=msg)

    # ---- extract (read-only) --------------------------------------------------------------
    async def extract(params: ExtractParams, browser_session: BrowserSession):
        current = await browser_session.get_current_page_url()
        decision, receipt, n = _decide_and_mint("extract", current, provenance="agent")
        domain = gate.resolve_domain(current) or current
        args = {"query": params.query}
        if not decision.allowed:
            session.record(n, "extract", args, decision, receipt,
                           target=domain, performed={"browser": "blocked"})
            return _blocked(decision, "extract", domain)
        try:
            title = await browser_session.get_current_page_title()
            text = await browser_session.get_state_as_text()
        except Exception as e:
            session.record(n, "extract", args, decision, receipt, target=domain,
                           performed={"browser": f"allowed; effect failed ({type(e).__name__})"})
            msg = f"extract on {domain} was ALLOWED but the browser failed: {e}"
            return ActionResult(error=msg, long_term_memory=msg)
        content = f"# {title}\n{text}"[:_MAX_EXTRACT_CHARS]
        session.record(n, "extract", args, decision, receipt,
                       target=domain, performed={"browser": f"read {len(content)} chars"})
        return ActionResult(extracted_content=content, include_in_memory=True,
                            long_term_memory=f"extracted from {domain}: {title}")

    # Register the four guarded actions under their exact mandate action-type names.
    tools.action("Navigate the browser to a URL (gated by the frozen WebMandate).",
                 param_model=NavigateParams)(navigate)
    tools.action("Click the interactive element with the given index (gated).",
                 param_model=ClickParams)(click)
    type_action.__name__ = "type"   # register under the mandate action-type name "type"
    tools.action("Type text into the element with the given index (gated).",
                 param_model=TypeParams)(type_action)
    tools.action("Read/extract the current page's content (gated, read-only).",
                 param_model=ExtractParams)(extract)

    return tools
