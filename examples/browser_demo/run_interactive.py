"""Interactive Spec 02 demo: `python -m examples.browser_demo.run_interactive`.

One live run that demonstrates the whole arc:

  start in `tour`
    -> navigate/extract Wikipedia                         (ALLOW)
    -> click the link to ycombinator.com                  (BLOCK at the click — off-scope under tour)
    -> run HALTS between steps; OPERATOR types a request  (Spec 04 Part 1 — a real human)
    -> select_scope maps it to a frozen menu key          (flip tour -> learn_more, scope_switch receipt)
    -> retry the same YC click                            (ALLOW — runtime selection changed the decision)
    -> navigate google.com                                (BLOCK under EVERY scope — the ceiling wall)

Spec 04 Part 1 — OPERATOR-DRIVEN scope control (the default). When a click is BLOCKED under
`tour`, the `on_step_start` hook (which is `await`ed by the run loop, so blocking in it is an
exact between-steps barrier) prompts a human on stdin and feeds the typed request to the
UNCHANGED `select_scope`. The operator cannot exceed the ceiling: `select_scope` still maps the
text to a frozen menu key and the validated setter clamps it ⊆ ceiling. The gate reads
`mandate.active` fresh, so the agent's next-step retry of the same click now passes — no restart.

Spec 04 flags (all additive, OFF by default — the Spec 01-03 flow is unchanged with them off):
  SIGNET_AUTO_GRANT=1   restore the old hands-free arc (hook fires select_scope, no human).
  SIGNET_INPAGE_PANEL=1 also paint the policy as an inert overlay ON the agent's page (Part 2).
  SIGNET_VOICE=1        push-to-talk voice intake for the operator request, typed fallback (Part 3).
  SIGNET_NO_SIDEBAR=1   skip the separate-page Spec 03 sidebar.

LLM: full OpenAI models (primary + fallback), reading OPENAI_API_KEY from the repo-root .env.
"""
from __future__ import annotations

import asyncio
import functools
import http.server
import os
import socketserver
import sys
import threading
import webbrowser
from pathlib import Path

from dotenv import load_dotenv

from browser_use import Agent, BrowserProfile, ChatOpenAI

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

HERE = Path(__file__).resolve().parent          # examples/browser_demo (served as the static root)

from . import inpage_panel
from .guarded_tools import build_tools
from .operator import acquire_operator_request
from .scopes import select_scope
from .session import Session
from .web_mandate import WebMandate

# ---- hardcoded demo config (swap freely) --------------------------------------------------
START_URL = "https://en.wikipedia.org/wiki/Y_Combinator"
TASK = (
    f"You are browsing under a security mandate. Use `navigate` to open {START_URL}, then "
    f"`extract` to read it and report the article's title and first sentence. Next, find and "
    f"`click` the link to Y Combinator's official website (its visible text is 'ycombinator.com', "
    f"in the infobox). If any click or navigation is BLOCKED, do NOT give up — report the block, "
    f"then try the SAME action again on your next step. Finally, try to `navigate` to "
    f"https://www.google.com . Report everything you did and what was blocked, then call `done`."
)
MODEL = os.environ.get("SIGNET_DEMO_MODEL", "gpt-5.5")
FALLBACK_MODEL = os.environ.get("SIGNET_DEMO_FALLBACK_MODEL", "gpt-5.4")
# browser-use's own belt; our gate is the advisory enforcer of record. Note: NO google here.
BROWSER_ALLOWED_DOMAINS = ["*.wikipedia.org", "https://*.wikipedia.org",
                           "*.ycombinator.com", "https://*.ycombinator.com"]


def build_mandate() -> "WebMandate":
    return (
        WebMandate("demo-agent", task_id="browse-scopes-001")
        .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "click", "extract"])
        .scope("tour",       domains=["wikipedia.org"],                   actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .scope("learn_more", domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .default_scope("tour")
        .build()
    )


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Static file server rooted at examples/browser_demo (serves viewer/ + session.json).
    Silent (no per-request stderr spam) and no-cache so each poll sees the latest file."""

    def log_message(self, *a):           # silence request logging during the demo
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def _start_sidebar() -> str | None:
    """Start a tiny daemon static server and return the viewer URL (or None if disabled).
    Read-only: it only serves files; it never touches the run. SIGNET_NO_SIDEBAR=1 skips it."""
    if os.environ.get("SIGNET_NO_SIDEBAR"):
        return None
    handler = functools.partial(_QuietHandler, directory=str(HERE))
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)  # port 0 -> OS picks a free one
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}/viewer/"
    try:
        webbrowser.open(url)
    except Exception:
        pass
    return url


async def _run() -> int:
    openai_key = os.environ.get("OPENAI_API_KEY")
    if not openai_key:
        print("ERROR: OPENAI_API_KEY is not set. Set it in .env and re-run.", file=sys.stderr)
        return 2

    mandate = build_mandate()
    session = Session(mandate, session_id="browser-scopes-demo")
    tools = build_tools(mandate, session)
    session.write()                          # initial file: ceiling + lanes render before step 1

    llm = ChatOpenAI(model=MODEL, api_key=openai_key)
    fallback = ChatOpenAI(model=FALLBACK_MODEL, api_key=openai_key)

    sidebar_url = _start_sidebar()
    print(f"[signet] two-tier WebMandate  ceiling={sorted(mandate.ceiling.allowed_domains)}  "
          f"scopes={list(mandate.menu)}  active={mandate.active!r}  (tier 0 / advisory)")
    print(f"[signet] guarded tools: {sorted(tools.registry.registry.actions)}")
    if sidebar_url:
        print(f"[signet] live sidebar: {sidebar_url}   (opening in your browser; SIGNET_NO_SIDEBAR=1 to skip)")

    auto_grant = bool(os.environ.get("SIGNET_AUTO_GRANT"))
    switched = {"done": False}
    panel = {"obj": None}                            # Spec 04 Part 2 in-page panel (flag-gated)

    async def push_panel(a: "Agent") -> None:
        """Best-effort: attach the in-page panel once, then push current state. Never raises —
        a panel failure must not change or abort a step (Acceptance 2: identical run on/off)."""
        if not inpage_panel.enabled():
            return
        try:
            if panel["obj"] is None:
                panel["obj"] = await inpage_panel.maybe_attach(a.browser_session)
            if panel["obj"] is not None:
                await panel["obj"].push(inpage_panel.panel_state(session))
        except Exception:
            pass

    async def driver(a: "Agent") -> None:
        """on_step_start: state snapshot + the ONE-TIME scope switch (operator-driven by default).

        No enforcement happens here — the gate inside the guarded tools is authoritative. This
        hook only snapshots state and, on the first recorded BLOCK click under `tour`, opens the
        operator channel (or auto-fires under SIGNET_AUTO_GRANT=1)."""
        try:
            step = getattr(getattr(a, "state", None), "n_steps", None)
            url = await a.browser_session.get_current_page_url()
            title = await a.browser_session.get_current_page_title()
            session.snapshot(step=step, url=url, title=title)
            print(f"[step {step}] at {url}  (active scope: {mandate.active})")
        except Exception:
            pass

        await push_panel(a)                          # install (once) + refresh the in-page panel

        if mandate.active != "tour" or switched["done"]:
            return
        blocked = next((e for e in session.to_dict()["effects"]
                        if e["proposed"]["action"] == "click" and e["decision"] == "BLOCK"), None)
        if blocked is None:
            return
        switched["done"] = True                      # open the channel exactly once

        if auto_grant:                               # legacy hands-free arc (flag-gated)
            d = select_scope(mandate, "show me Y Combinator's official website", session=session)
            print(f"[signet] AUTO-GRANT select_scope -> {d.outcome.upper()}  active is now {mandate.active!r}")
            return

        # OPERATOR-DRIVEN (default): halt between steps and let a human decide. Blocking on stdin
        # inside this awaited hook IS the pause — no step proceeds until the operator answers.
        target = blocked["proposed"]["target"]
        print(f"\n>>> [operator] agent was blocked on click -> {target}")
        request = await acquire_operator_request(
            ">>> [operator] type a scope request (or ENTER to deny): ")
        if not request:
            print("[signet] operator denied — no scope granted; agent remains blocked.")
            session.record_scope_switch("(operator declined)", None, "block",
                                        reason="operator pressed ENTER; active scope unchanged", step=step)
            return
        d = select_scope(mandate, request, session=session)
        print(f"[signet] operator request {request!r} -> select_scope {d.outcome.upper()}  "
              f"active is now {mandate.active!r}")

    await agent_run(Agent(
        task=TASK, llm=llm, fallback_llm=fallback, tools=tools,
        browser_profile=BrowserProfile(headless=False, allowed_domains=BROWSER_ALLOWED_DOMAINS),
        directly_open_url=False,   # Agent kwarg; first hop must go through the guarded navigate
    ), driver, push_panel)

    print("\n[signet] decisions (each backed by a signed receipt):")
    for e in session.to_dict()["effects"]:
        ok = "✓" if e["receipt_verified"] else "✗"
        print(f"  #{e['seq']:>2} [{e['active_scope']:>10}] {e['decision']:<5} "
              f"{e['proposed']['action']:<13} {str(e['proposed']['target']):<22} "
              f"receipt {e['receipt_id'][:10]} {ok}")
    print(f"\n[signet] wrote {session.out_path}  ({len(session.to_dict()['effects'])} decisions)")
    return 0


async def agent_run(agent: "Agent", driver, on_step_end=None) -> None:
    await agent.run(on_step_start=driver, on_step_end=on_step_end, max_steps=18)


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
