"""Constrained, endorsed VALUE resolution for tau-bench retail (the FIDES/CaMeL
move). No signet/ kernel edits -- this is pure adapter logic that turns a TRUSTED
target PREDICATE (``retail_intent.TargetPredicate``, built from the instruction
only) into a single ENDORSED order id, or routes to review / block.

The discipline (why this is safe, not just convenient)
------------------------------------------------------
* BOUNDED SET -- candidates are ONLY the authenticated principal's OWN orders
  (``users[principal]['orders']``, re-checked ``order.user_id == principal``).
  Ownership is the hard bound: a foreign / planted order can never enter the set,
  even if it perfectly matches the predicate. This caps the exposure of a wrong
  resolution to the principal's own resources -- never an attacker's target.
* CONTROL FLOW FROM TRUSTED, VALUES MAY BE RUNTIME (CaMeL) -- the MATCH CRITERIA
  (effect class, named id, item keywords, status, selector) come ONLY from the
  frozen predicate. The DB is read solely to supply candidate orders' contents to
  test against those criteria; tool data can never WIDEN what is authorized, only
  fail to match.
* LOW-CAPACITY OUTPUT -- resolution returns an order id drawn from that bounded set
  (an enum over the principal's orders), never free text that could carry an
  injected instruction downstream.
* DISAMBIGUATORS RESOLVE; GENUINE AMBIGUITY REVIEWS -- 'only'/'most_recent' are
  user-supplied disambiguators and resolve to the single target (most_recent over
  the principal's OWN, fixed order-history list -- an attacker can't reorder it).
  'unspecified' (or 'only' with >1 owned match) is genuine ambiguity -> REVIEW; the
  resolver NEVER silently picks. 'all' authorizes every owned match.

The single endorsed id is then handed to the UNCHANGED kernel as the bound effect
(``gate.py``), which still does context-binding (proposed vs endorsed) +
consume-once. The block of a non-endorsed proposal is the verifier's, as before.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .retail_intent import (TargetPredicate, SELF_TARGET, effect_action,
                            _REQUIRES_STATUS, SEL_ALL, SEL_MOST_RECENT,
                            SEL_ONLY, SEL_UNSPECIFIED)

ENDORSE = "ENDORSE"   # a trusted, unique (or selector=all) owned target was promoted
REVIEW = "REVIEW"     # genuine ambiguity -> escalate to a human; do NOT pick
BLOCK = "BLOCK"       # out-of-predicate / effect class not authorized


@dataclass
class Resolution:
    kind: str                       # ENDORSE | REVIEW | BLOCK
    endorsed: Optional[str] = None  # the single endorsed order id (or SELF_TARGET)
    matched: tuple = ()             # all owned order ids matching the predicate
    selector_all: bool = False      # selector='all' -> every matched id is authorized
    reason: str = ""


def _own_orders(principal: str, data: dict) -> list:
    """The principal's OWN orders (the bounded set), as (order_id, order) pairs,
    re-checking ownership defensively."""
    own_ids = list((data.get("users", {}).get(principal, {}) or {}).get("orders", []) or [])
    out = []
    for oid in own_ids:
        o = data.get("orders", {}).get(oid)
        if o and o.get("user_id") == principal:   # ownership hard bound
            out.append((oid, o))
    return out


def resolve_target(pred: Optional[TargetPredicate], tool: str, principal: str,
                   data: dict) -> Resolution:
    """Resolve a proposed high-impact action's target from its TRUSTED predicate over
    the principal's OWN orders. Returns an ENDORSE/REVIEW/BLOCK Resolution."""
    # Effect class not authorized at all -> out-of-envelope (the agent proposed an
    # effect the user never asked for).
    if pred is None:
        return Resolution(BLOCK, reason="out-of-envelope: effect class not authorized")

    # modify_user_address acts on the principal's OWN profile; the target is
    # definitionally self (trusted), validated structurally (user_id == principal)
    # at the gate. No order resolution needed.
    if tool == "modify_user_address" or pred.self_target:
        return Resolution(ENDORSE, endorsed=SELF_TARGET, matched=(SELF_TARGET,),
                          reason="self profile (structural ownership)")

    cands = _own_orders(principal, data)               # BOUNDED SET (ownership)
    own_pos = {oid: i for i, (oid, _) in enumerate(cands)}   # profile history order

    # Tool's required status precondition (trusted standing config).
    need = _REQUIRES_STATUS.get(tool)
    if need is not None:
        cands = [(i, o) for i, o in cands if o.get("status") == need]

    # Predicate filters -- CRITERIA FROM TRUSTED PREDICATE ONLY.
    if pred.order_id:
        want = str(pred.order_id).strip().upper()
        cands = [(i, o) for i, o in cands if i.upper() == want]
    if pred.status:
        cands = [(i, o) for i, o in cands if o.get("status") == pred.status]
    for kw in pred.item_keywords:
        k = str(kw).strip().lower()
        if not k:
            continue
        cands = [(i, o) for i, o in cands
                 if any(k in (it.get("name", "") or "").lower()
                        for it in o.get("items", []))]

    matched = tuple(i for i, _ in cands)

    # selector='all' -> every owned match is authorized (multi-endorse).
    if pred.selector == SEL_ALL:
        if not matched:
            return Resolution(BLOCK, matched=(), selector_all=True,
                              reason="out-of-predicate: no owned order matches")
        return Resolution(ENDORSE, endorsed=None, matched=matched, selector_all=True,
                          reason=f"selector=all: {len(matched)} owned matches")

    if not matched:
        return Resolution(BLOCK, matched=(),
                          reason="out-of-predicate: no owned order matches")
    if len(matched) == 1:
        return Resolution(ENDORSE, endorsed=matched[0], matched=matched,
                          reason="unique owned match")

    # >1 owned match: 'most_recent' disambiguates over the principal's OWN, fixed
    # order-history list (attacker can't reorder it -> safe). Everything else
    # (unspecified, or 'only' with >1) is GENUINE ambiguity -> review; never pick.
    if pred.selector == SEL_MOST_RECENT:
        chosen = max(matched, key=lambda i: own_pos.get(i, -1))
        return Resolution(ENDORSE, endorsed=chosen, matched=matched,
                          reason=f"most_recent disambiguator over {len(matched)} owned")
    return Resolution(REVIEW, matched=matched,
                      reason=f"ambiguous: {len(matched)} owned orders match "
                             f"(selector={pred.selector})")
