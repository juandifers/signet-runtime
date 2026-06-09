"""Rail-AGNOSTIC structural, selective-prediction ABSTENTION for Role B.

Abstention is decided on candidate-set CARDINALITY — never on the model's self-reported
confidence or a lone pick. Two deterministic layers (neither an LLM) wrap Role B:

  * LAYER A — a STRUCTURAL pre-filter that runs BEFORE any LLM call. Where the criterion is
    structurally decidable, the rail counts the owned candidates that LITERALLY satisfy it (a
    low-capacity, non-injectable own field). Two or more => structurally ambiguous => escalate
    without ever calling the model. The COUNT is rail-specific (GitHub: PRs that close issue #N;
    deploy: builds that carry the named approval); the cardinality DECISION is shared — that is
    `structural_match_prefilter` below, which each rail feeds its own match list.

  * The CARDINALITY RULE — `apply_cardinality`: the override applied to Role B's set-valued
    output AFTER the clamp. Let s = returned set ∩ owned ids:
        |s| == 1  -> resolve that one id, THEN the existing fence/gate runs on it.
        |s| >= 2  -> unresolved_constraint -> REVIEW (hard; no tie-break).
        |s| == 0  -> unresolved_constraint / no-op.

This is a CORRECTNESS layer. It does NOT weaken or replace the rail's containment gate
(bounded-to-own -> allow-list -> scope/protected fence), which still runs on the single
survivor. agentdojo-free: stdlib only. Promoted from `evals/github_railbridge/ambiguity.py`.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

# Reuse AP2's cause term so the audit string matches the rest of the mandate path.
UNRESOLVED_CONSTRAINT = "unresolved_constraint"


def structural_match_prefilter(match_ids: List[int], *, what: str) -> Optional[Tuple[str, str]]:
    """Layer A, rail-AGNOSTIC core. Given the owned-candidate ids that LITERALLY satisfy a
    structurally-decidable criterion (the rail computes this list from a non-injectable own
    field), return ("escalate", cause) when two or more satisfy it (structurally ambiguous),
    else None (pass through to Role B). The rail decides WHAT to count; this decides the
    cardinality. `what` is a short human label for the cause string (e.g. "close issue #7",
    "carry approval 'rc-blessed'")."""
    ids = sorted(set(int(i) for i in match_ids))
    if len(ids) >= 2:
        listed = ", ".join(f"#{n}" for n in ids)
        return ("escalate",
                f"structurally ambiguous: {len(ids)} owned candidates ({listed}) {what}")
    return None


def apply_cardinality(resolver_set, owned_ids) -> Tuple[str, object]:
    """The cardinality override. Given Role B's clamped `ResolverSet` and the owned-id set,
    decide structurally on |s|, returning a verdict that NAMES the escalation source so the
    caller can attribute the outcome without inferring it post hoc:
        ("resolve", cid)         exactly one owned id survives -> resolve (then the gate runs),
        ("ambiguous", cause)     two or more survive -> escalate (Layer B cardinality),
        ("no_match", cause)      none survive -> escalate (the resolver matched nothing).
    `resolver_set.ids` is already clamped to the owned set by `parse_set`; intersecting again
    with `owned_ids` is defensive (so a wrapped/stubbed resolver can't slip an id through)."""
    s = set(resolver_set.ids) & set(owned_ids)
    if len(s) == 1:
        return ("resolve", next(iter(s)))
    if len(s) >= 2:
        ids = ", ".join(f"#{n}" for n in sorted(s))
        return ("ambiguous",
                f"ambiguous: {len(s)} owned candidates ({ids}) plausibly match the criterion")
    return ("no_match", "no owned candidate matched the criterion")
