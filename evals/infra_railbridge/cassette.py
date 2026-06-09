"""Record/replay ("cassette") seam for the INFRA rail's Role-B call — the infra candidate
FINGERPRINT + the infra prompt, bound into the rail-AGNOSTIC cassette machinery in
`evals/_rail_core/cassette.py` (the SAME store/key/replay-through-the-clamp the merge / deploy rails
use). agentdojo-free.
"""
from __future__ import annotations

from typing import List

from evals._rail_core import cassette as _core

from .resolver import PlanView, _SYSTEM, _build_user_prompt, _plan_id

CASSETTE_SCHEMA = "signet.infra.role_b_cassette.v1"


def _infra_fingerprint(c: PlanView) -> list:
    """The infra fingerprint: each candidate's low-capacity (non-injectable) plan fields. The
    untrusted `description` is INCLUDED so a poisoned vs clean variant key to different recordings."""
    return [c.plan_id, c.account, c.cluster, list(c.resource_set), c.plan_hash, c.title,
            c.add_count, c.change_count, c.destroy_count, c.blast_radius, c.linked_ticket,
            c.approval, c.status, c.description]


def cassette_key(criterion: str, candidates: List[PlanView]) -> str:
    return _core.cassette_key(criterion, candidates, _infra_fingerprint, id_of=_plan_id)


class Cassette(_core.Cassette):
    def __init__(self, path, *, model: str = "", provider: str = "") -> None:
        super().__init__(path, fingerprint=_infra_fingerprint, id_of=_plan_id,
                         model=model, provider=provider, schema=CASSETTE_SCHEMA)


class SampleCassette(_core.SampleCassette):
    def __init__(self, path, *, model: str = "", provider: str = "", temperature=None) -> None:
        super().__init__(path, fingerprint=_infra_fingerprint, id_of=_plan_id, model=model,
                         provider=provider, temperature=temperature, schema=CASSETTE_SCHEMA)


class CassetteResolver(_core.CassetteResolver):
    def __init__(self, cassette, *, record_from=None, label: str = "", save: bool = False) -> None:
        super().__init__(cassette, system=_SYSTEM, build_user=_build_user_prompt, id_of=_plan_id,
                         record_from=record_from, label=label, save=save)
