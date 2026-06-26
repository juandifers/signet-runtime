"""`decide(...)` — the pure, default-deny gate decision function for the browser spine.

This is the whole enforcement logic, isolated and standalone (no kernel, no broker,
no capability token — a browser action is an effect-performing door, like egress; there
is nothing to mint). The guarded tools call this at the FRONT of every tool body, before
any browser effect runs.

Spec 02 decides against the mandate's ACTIVE scope (not a flat allowlist) and adds an
ELEMENT-LEVEL click check: a click is decided on its *navigable destination*, so an
off-scope click is blocked AT the click — not on the following action.

Rules (in order; first failure wins; default-deny on anything unrecognized):
  1. `action_type` must be a known action type (navigate|click|type|extract).
  2. `action_type` must be in the active scope's `allowed_actions`.
  3. For `navigate`: the resolved domain of `target` must be in the scope's `allowed_domains`.
     For `click`:
       - if `click_destination` is given (a resolvable href): its domain must be in scope,
         else BLOCK the click (provenance="page" — the href is untrusted page content, so
         it may only deny, never widen the allowlist);
       - if `click_destination` is None (a JS/SPA element with no statically resolvable
         destination): fall back to the scope's `click_policy` — `in_domain_only` denies,
         `allow_unresolved` allows with a note. (Honesty: this is a documented best-effort
         gap; the navigate-domain gate is the backstop for anything that slips through.)
     For `type`/`extract`: the current page domain (`target`) must be in `allowed_domains`.

`scope` may be a `Scope` or a `FrozenWebMandate` (duck-typed). When a mandate is passed, its
`active_scope` is read FRESH on every call, so flipping `mandate.active` changes the next
decision with no agent restart.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .web_mandate import ACTION_TYPES


@dataclass(frozen=True)
class Decision:
    outcome: str   # "allow" | "block"
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"


def resolve_domain(target: str) -> str | None:
    """Bare lower-case host from a URL or bare hostname. Returns None if unresolvable."""
    if not isinstance(target, str) or not target.strip():
        return None
    t = target.strip()
    if "://" not in t:
        t = "https://" + t          # bare host or host/path
    netloc = urlparse(t).netloc.lower()
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    host = netloc.split(":", 1)[0]
    return host or None


def _domain_allowed(domain: str, allowed: frozenset[str]) -> bool:
    """Exact host match, or a subdomain of an allowlisted registrable domain."""
    return any(domain == a or domain.endswith("." + a) for a in allowed)


def _active_scope(scope):
    """Accept a Scope or a FrozenWebMandate; resolve the latter to its active scope FRESH."""
    return scope.active_scope if hasattr(scope, "active_scope") else scope


def decide(scope, action_type: str, target: str, *, provenance: str = "agent",
           click_destination: str | None = None) -> Decision:
    """Default-deny decision against the active scope. `target` is a URL for `navigate`; for
    click/type/extract it is the CURRENT page URL. `click_destination` (a click's resolved
    href, absolute) drives the click decision when present."""
    s = _active_scope(scope)

    if action_type not in ACTION_TYPES:
        return Decision("block", f"unrecognized action type {action_type!r} (default-deny)")

    if action_type not in s.allowed_actions:
        return Decision(
            "block",
            f"action {action_type!r} not in scope {s.name!r} actions {sorted(s.allowed_actions)}")

    if action_type == "click":
        return _decide_click(s, target, click_destination)

    domain = resolve_domain(target)
    if domain is None:
        return Decision("block", f"could not resolve a domain from target {target!r}")
    if not _domain_allowed(domain, s.allowed_domains):
        return Decision(
            "block",
            f"{action_type} to {domain} not in scope {s.name!r} domains {sorted(s.allowed_domains)}")
    return Decision("allow", f"{action_type} on {domain} within scope {s.name!r}")


def _decide_click(s, current: str, click_destination: str | None) -> Decision:
    """Element-level click policy: decide on the click's navigable destination (Spec 02 Part A)."""
    if click_destination is not None:
        dest = resolve_domain(click_destination)
        if dest is None:
            return Decision("block", f"click destination {click_destination!r} is unresolvable")
        if _domain_allowed(dest, s.allowed_domains):
            return Decision("allow", f"click -> {dest} within scope {s.name!r}")
        # page-provenance href: untrusted, may only deny, never widen the allowlist.
        return Decision(
            "block",
            f"click navigates off-scope to {dest} (page-provenance link; not in scope "
            f"{s.name!r} domains {sorted(s.allowed_domains)})")

    # Destination not statically resolvable (JS/SPA element) -> scope click_policy fallback.
    if s.click_policy == "allow_unresolved":
        return Decision(
            "allow",
            f"click with unresolved destination allowed by scope {s.name!r} "
            f"click_policy=allow_unresolved (advisory — navigate gate is the backstop)")
    return Decision(
        "block",
        f"click with unresolved destination denied by scope {s.name!r} "
        f"click_policy=in_domain_only (default-deny; cannot confirm it stays in scope)")
