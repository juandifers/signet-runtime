"""Record/replay ("cassette") seam for the DEPLOY rail's Role-B call — the deploy candidate
FINGERPRINT + the deploy prompt, bound into the rail-AGNOSTIC cassette machinery in
`evals/_rail_core/cassette.py` (the SAME store/key/replay-through-the-clamp the merge rail uses).
agentdojo-free.
"""
from __future__ import annotations

from typing import List

from evals._rail_core import cassette as _core

from .resolver import BuildView, _SYSTEM, _build_user_prompt, _build_id

CASSETTE_SCHEMA = "signet.deploy.role_b_cassette.v1"


def _deploy_fingerprint(c: BuildView) -> list:
    """The deploy fingerprint: each candidate's low-capacity (non-injectable) build fields. The
    untrusted `note` is INCLUDED so a poisoned vs clean variant key to different recordings."""
    return [c.build_id, c.service, c.environment, c.artifact_digest, c.config_hash, c.title,
            c.signed, c.scanned, c.approval, c.status, c.note]


def cassette_key(criterion: str, candidates: List[BuildView]) -> str:
    return _core.cassette_key(criterion, candidates, _deploy_fingerprint, id_of=_build_id)


class Cassette(_core.Cassette):
    def __init__(self, path, *, model: str = "", provider: str = "") -> None:
        super().__init__(path, fingerprint=_deploy_fingerprint, id_of=_build_id,
                         model=model, provider=provider, schema=CASSETTE_SCHEMA)


class SampleCassette(_core.SampleCassette):
    def __init__(self, path, *, model: str = "", provider: str = "", temperature=None) -> None:
        super().__init__(path, fingerprint=_deploy_fingerprint, id_of=_build_id, model=model,
                         provider=provider, temperature=temperature, schema=CASSETTE_SCHEMA)


class CassetteResolver(_core.CassetteResolver):
    def __init__(self, cassette, *, record_from=None, label: str = "", save: bool = False) -> None:
        super().__init__(cassette, system=_SYSTEM, build_user=_build_user_prompt, id_of=_build_id,
                         record_from=record_from, label=label, save=save)
