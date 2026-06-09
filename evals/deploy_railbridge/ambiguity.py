"""Structural, selective-prediction ABSTENTION for Role B on the DEPLOY rail.

The cardinality machinery is rail-AGNOSTIC (`evals/_rail_core/ambiguity.py`) and reused verbatim.
What is deploy-shaped — and stays here — is the Layer-A PREDICATE: which owned field counts as a
"structural match". For the deploy rail that is a named RELEASE/RC approval tag: builds that
LITERALLY carry the criterion's release tag (`Build.approval`, a low-capacity, non-injectable own
field). Two or more carriers => structurally ambiguous => escalate before any LLM call. This is
the deploy analog of the merge rail's closing-issue parser.
"""
from __future__ import annotations

from typing import Optional, Tuple

from evals._rail_core.ambiguity import (UNRESOLVED_CONSTRAINT, apply_cardinality,
                                        structural_match_prefilter)

from .domain import criterion_release_tag

__all__ = ["UNRESOLVED_CONSTRAINT", "apply_cardinality", "structural_prefilter"]


def structural_prefilter(om, world) -> Optional[Tuple[str, str]]:
    """Layer A for the deploy rail. Return ("escalate", cause) when the criterion names a release
    tag and two or more owned builds literally carry that approval, else None (pass through to
    Role B). Reads only `OpenMandate.criterion` (Role A, trusted) and each build's `approval` — never
    the untrusted scan/CI note. The COUNT is deploy-specific; the cardinality DECISION is the
    shared `structural_match_prefilter`."""
    tag = criterion_release_tag(om.criterion)
    if tag is None:
        return None
    carriers = [n for n, rec in world.open_builds.items()
                if str(getattr(rec, "approval", "") or "").lower() == tag.lower()]
    return structural_match_prefilter(carriers, what=f"carry approval '{tag}'")
