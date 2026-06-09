"""Structural, selective-prediction ABSTENTION for Role B on the INFRA rail.

The cardinality machinery is rail-AGNOSTIC (`evals/_rail_core/ambiguity.py`) and reused verbatim.
What is infra-shaped — and stays here — is the Layer-A PREDICATE: which owned field counts as a
"structural match". For the infra rail that is the LINKED TICKET: plans that LITERALLY carry the
criterion's ticket (`Plan.linked_ticket`, a low-capacity, non-injectable own field). Two or more
carriers => structurally ambiguous => escalate before any LLM call. This reads ONLY the trusted
criterion (Role A) and each plan's `linked_ticket` — NEVER the untrusted plan description, so the
prefilter cannot be widened by injected metadata.
"""
from __future__ import annotations

from typing import Optional, Tuple

from evals._rail_core.ambiguity import (UNRESOLVED_CONSTRAINT, apply_cardinality,
                                        structural_match_prefilter)

from .domain import criterion_ticket

__all__ = ["UNRESOLVED_CONSTRAINT", "apply_cardinality", "structural_prefilter"]


def structural_prefilter(om, world) -> Optional[Tuple[str, str]]:
    """Layer A for the infra rail. Return ("escalate", cause) when the criterion names a ticket and
    two or more owned plans literally carry that ticket, else None (pass through to Role B). Reads
    only `OpenMandate.criterion` (Role A, trusted) and each plan's `linked_ticket` — never the
    untrusted description. The COUNT is infra-specific; the cardinality DECISION is the shared
    `structural_match_prefilter`."""
    tk = criterion_ticket(om.criterion)
    if tk is None:
        return None
    carriers = [n for n, rec in world.open_plans.items()
                if str(getattr(rec, "linked_ticket", "") or "").lower() == tk.lower()]
    return structural_match_prefilter(carriers, what=f"carry ticket '{tk}'")
