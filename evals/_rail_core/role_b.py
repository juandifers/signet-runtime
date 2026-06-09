"""Rail-AGNOSTIC Role-B orchestration — the FULL three-stage control flow (now INCLUDING the
containment gate as Stage 3) + the escalation-source attribution enum, shared by every rail-bridge.

Stages 1-2 were always shared; Stage 3 (the gate) used to be re-implemented per rail. It now lives
HERE, so a caller can NEVER receive a "RESOLVED, act on it" verdict without the gate having run, in
order, fail-closed. A new rail INHERITS containment: it supplies two boolean predicates (the FIELDS
differ per rail) and physically cannot reorder the gate or skip a stage.

  Stage 1  Layer A structural pre-filter (no LLM): rail-supplied closure -> escalate or pass.
  Stage 2  set-valued Role B + the CARDINALITY rule: resolve iff exactly ONE owned id survives;
           escalate the moment two+ (or zero) survive.
  Stage 3  THE GATE (order + fail-closed, in this module):
             1. candidate in owned_ids       else -> escalate(ESC_GATE, "not-owned")
             2. within_allowlist(candidate)  else -> escalate(ESC_GATE, "off-allowlist")
             3. within_fence(candidate)      else -> escalate(ESC_GATE, "off-fence")
           pass all 3 -> ESC_RESOLVED. A predicate that RAISES is caught and treated as failure
           (never crash-through). The rejecting stage rides on `cause`.

Role B is assumed possibly-fooled; the cardinality rule + the gate contain it. Its untrusted
narrative is stored apart (the optional `trace_store`) and only its HASH is carried forward.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .ambiguity import apply_cardinality

# Escalation-source vocabulary — set AT the decision point, never inferred post hoc.
ESC_RESOLVED = "resolved"
ESC_LAYER_A = "layer_a_structural"
ESC_CARDINALITY = "layer_b_cardinality"
ESC_GATE = "gate_contained"
ESC_NO_MATCH = "no_match"
ESCALATION_SOURCES = (ESC_RESOLVED, ESC_LAYER_A, ESC_CARDINALITY, ESC_GATE, ESC_NO_MATCH)


@dataclass
class RoleBStages:
    """The outcome of the full Role-B pipeline (stages 1-3). `status` is "escalate" or "resolve".
    On "resolve" the gate PASSED and `chosen_id` is the single owned survivor — the caller binds it
    to a ClosedMandate (it may NOT re-gate). On "escalate", `escalation_source` names the layer and
    `surviving_ids` lists the owned ids to record for the audit trail (the cardinality survivors,
    or the single gate-rejected candidate)."""
    status: str
    chosen_id: Optional[int] = None
    cause: str = ""
    escalation_source: Optional[str] = None
    surviving_ids: Tuple[int, ...] = ()
    raw: str = ""
    trace_hash: Optional[str] = None


def run_gate(chosen, owned_ids, within_allowlist, within_fence) -> Optional[str]:
    """The shared containment gate: ORDER + fail-closed. Returns a rejection cause string naming the
    rejecting stage, or None if the candidate passes all three. A predicate that RAISES is caught
    and treated as a rejection (never a crash-through). Reusable directly by a rail's deterministic
    Role-A path (the Role-B path gets it inside `run_role_b_stages`)."""
    if chosen not in set(owned_ids):
        return "not-owned (resolver pick is not an owned candidate)"
    try:
        if not within_allowlist(chosen):
            return "off-allowlist (universe ceiling: repo/service + base/environment)"
    except Exception as e:                                 # fail closed on a broken predicate
        return f"off-allowlist (gate predicate raised: {e})"
    try:
        if not within_fence(chosen):
            return "off-fence (scope/protected)"
    except Exception as e:
        return f"off-fence (gate predicate raised: {e})"
    return None


def run_role_b_stages(criterion: str, candidates: List, owned_ids, *, resolver,
                      within_allowlist: Callable[[int], bool],
                      within_fence: Callable[[int], bool],
                      structural_prefilter: Optional[Callable[[], Optional[Tuple[str, str]]]] = None,
                      trace_store=None) -> RoleBStages:
    """Run all three stages. `structural_prefilter` is a zero-arg rail closure returning
    ("escalate", cause) or None (Stage 1). `resolver` is the set-valued Role B (Stage 2).
    `within_allowlist` / `within_fence` are rail boolean predicates over a candidate id (Stage 3) —
    the FIELDS are per-rail, the ORDER + fail-closed are here. `owned_ids` is the bounded-to-own id
    set. `trace_store` (optional) stashes the untrusted narrative and returns its hash.

    A "resolve" result is only ever returned AFTER the gate passes — the caller cannot act on an
    ungated candidate."""
    # Stage 1 — Layer A: structural pre-filter, BEFORE any LLM call (no trace exists yet).
    if structural_prefilter is not None:
        pre = structural_prefilter()
        if pre is not None:
            return RoleBStages("escalate", cause=pre[1], escalation_source=ESC_LAYER_A)

    # Stage 2 — set-valued Role B + the cardinality override.
    rset = resolver.resolve(criterion, candidates)
    trace_hash = None
    if trace_store is not None and rset.raw:
        trace_hash = trace_store.put(rset.raw)            # stash the untrusted trace, keep the hash

    verdict, payload = apply_cardinality(rset, set(owned_ids))
    if verdict in ("ambiguous", "no_match"):
        source = ESC_CARDINALITY if verdict == "ambiguous" else ESC_NO_MATCH
        return RoleBStages("escalate", cause=str(payload), escalation_source=source,
                           surviving_ids=tuple(sorted(rset.ids)), raw=rset.raw,
                           trace_hash=trace_hash)

    # Stage 3 — THE GATE (order + fail-closed). One owned id survived cardinality; gate it.
    chosen = payload
    reject = run_gate(chosen, owned_ids, within_allowlist, within_fence)
    if reject is not None:
        # gate_contained: surface the single rejected candidate for the audit trail.
        return RoleBStages("escalate", chosen_id=chosen, cause=reject,
                           escalation_source=ESC_GATE, surviving_ids=(chosen,),
                           raw=rset.raw, trace_hash=trace_hash)

    return RoleBStages("resolve", chosen_id=chosen, escalation_source=ESC_RESOLVED,
                       raw=rset.raw, trace_hash=trace_hash)
