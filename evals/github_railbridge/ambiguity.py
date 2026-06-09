"""Structural, selective-prediction ABSTENTION for Role B on the GitHub MERGE rail.

The cardinality machinery is rail-AGNOSTIC and lives in `evals/_rail_core/ambiguity.py`
(`apply_cardinality`, `structural_match_prefilter`) — reused unchanged by every rail. What is
GitHub-shaped — and therefore stays here — is the Layer-A PREDICATE: which owned field counts as
a "structural match". For the merge rail that is the closing-issue reference: PRs that LITERALLY
close the criterion's issue (`closes_issue`, a low-capacity, non-injectable own field). The deploy
rail supplies its own predicate (builds carrying a named approval) over the same shared core.

  * `structural_prefilter(om, world)` — Layer A for merge: count owned PRs that close the
    criterion's issue, hand the count to the shared `structural_match_prefilter` (>= 2 -> escalate
    before any LLM call). Reads only `OpenMandate.criterion_issue()` (Role A, trusted) and each
    PR's `closes_issue` — never any PR body / title / injection channel.
  * `apply_cardinality` — re-exported from the shared core (the override on Role B's set output).
"""
from __future__ import annotations

from typing import Optional, Tuple

from evals._rail_core.ambiguity import (UNRESOLVED_CONSTRAINT, apply_cardinality,
                                        structural_match_prefilter)

__all__ = ["UNRESOLVED_CONSTRAINT", "apply_cardinality", "structural_prefilter"]


def structural_prefilter(om, world) -> Optional[Tuple[str, str]]:
    """Layer A for the merge rail. Return ("escalate", cause) when the criterion is STRUCTURALLY
    ambiguous (two or more owned PRs literally close the criterion's issue), else None (pass
    through to Role B). The COUNT is GitHub-specific (closing-issue); the cardinality DECISION is
    the shared `structural_match_prefilter`."""
    issue = om.criterion_issue()
    if issue is None:
        return None                                  # not a closing-issue criterion -> defer
    closers = [n for n, rec in world.open_prs.items()
               if getattr(rec, "closes_issue", None) == issue]
    return structural_match_prefilter(closers, what=f"close issue #{issue}")
