"""Structural, selective-prediction ABSTENTION for Role B on the GitHub merge rail.

The problem this fixes: a single-pick resolver silently resolved genuine ambiguity by guessing
— for an "ambiguous" criterion that two owned PRs equally satisfy, it committed to one, and the
scope/protected GATE could not catch that (both picks are in-scope owned PRs). The fix is to
make abstention STRUCTURAL, decided on candidate-set CARDINALITY, never on the model's
self-reported confidence or a lone pick.

Two deterministic layers wrap Role B (neither is an LLM):

  * LAYER A — `structural_prefilter`: runs FIRST, before any LLM call. Where the criterion is
    structurally decidable (a closing-issue reference: "...issue #N"), count the owned PRs that
    LITERALLY close #N (a low-capacity, non-injectable own field). Two or more closers => the
    criterion is structurally ambiguous => escalate to REVIEW without ever calling the model.
    One or zero closers => pass through (let Role B do the fuzzy resolution; we do NOT
    auto-endorse on a single structural match — the fuzzy path stays authoritative).

  * The CARDINALITY RULE — `apply_cardinality`: the override applied to Role B's set-valued
    output AFTER the clamp. Let s = returned set ∩ owned ids:
        |s| == 1  -> resolve that one PR, THEN the existing fence/gate runs on it as before.
        |s| >= 2  -> unresolved_constraint -> REVIEW (hard; no tie-break for now).
        |s| == 0  -> unresolved_constraint / no-op.

This is a CORRECTNESS layer. It does NOT weaken or replace the existing containment gate
(bounded-to-own -> allow-list -> scope/protected fence), which still runs independently on the
single surviving id. agentdojo-free: stdlib only.
"""
from __future__ import annotations

from typing import Optional, Tuple

# Reuse AP2's cause term so the audit string matches the rest of the mandate path.
UNRESOLVED_CONSTRAINT = "unresolved_constraint"


def structural_prefilter(om, world) -> Optional[Tuple[str, str]]:
    """Layer A. Return ("escalate", cause) when the criterion is STRUCTURALLY ambiguous
    (two or more owned PRs literally close the criterion's issue), else None (pass through to
    Role B). Reads only `OpenMandate.criterion_issue()` (Role A, trusted) and each PR's
    `closes_issue` (a low-capacity own field) — never any PR body / title / injection channel.
    """
    issue = om.criterion_issue()
    if issue is None:
        return None                                  # not a closing-issue criterion -> defer
    closers = [n for n, rec in world.open_prs.items()
               if getattr(rec, "closes_issue", None) == issue]
    if len(closers) >= 2:
        ids = ", ".join(f"#{n}" for n in sorted(closers))
        return ("escalate",
                f"structurally ambiguous: {len(closers)} owned PRs ({ids}) close issue "
                f"#{issue}")
    return None


def apply_cardinality(resolver_set, owned_ids) -> Tuple[str, object]:
    """The cardinality override. Given Role B's clamped `ResolverSet` and the owned-id set,
    decide structurally on |s|:
        ("resolve", pr)        when exactly one owned id survives,
        ("escalate", cause)    when two or more survive (ambiguous) or none do (unresolved).
    `resolver_set.ids` is already clamped to the owned set by `_parse_set`; intersecting again
    with `owned_ids` is defensive (so a wrapped/stubbed resolver can't slip an id through)."""
    s = set(resolver_set.ids) & set(owned_ids)
    if len(s) == 1:
        return ("resolve", next(iter(s)))
    if len(s) >= 2:
        ids = ", ".join(f"#{n}" for n in sorted(s))
        return ("escalate",
                f"ambiguous: {len(s)} owned candidates ({ids}) plausibly match the criterion")
    return ("escalate", "no owned candidate matched the criterion")
