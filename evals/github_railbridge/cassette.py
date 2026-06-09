"""Record/replay ("cassette") seam for the GitHub MERGE rail's Role-B call — the rail-specific
candidate FINGERPRINT + the merge prompt, bound into the rail-AGNOSTIC cassette machinery in
`evals/_rail_core/cassette.py`.

The store, the key derivation, `SampleCassette`, and the replay-through-the-clamp `CassetteResolver`
are all shared core, reused by every rail. What is GitHub-shaped — and stays here — is the
candidate fingerprint (which low-capacity PR fields key a recording) and the merge prompt the
recorder/replayer renders. The fingerprint is byte-identical to the historical one, so existing
committed merge-rail cassettes remain valid (no re-record needed).

agentdojo-free: imports only stdlib + signet.canonical + the (agentdojo-free) resolver.
"""
from __future__ import annotations

from typing import List

from evals._rail_core import cassette as _core
from evals._rail_core.cassette import CASSETTE_SCHEMA as _CORE_SCHEMA

from .resolver import CandidateView, _SYSTEM, _build_user_prompt, _pr_id

# Keep the GitHub-namespaced schema (so re-records stay self-describing as merge-rail recordings).
CASSETTE_SCHEMA = "signet.github.role_b_cassette.v1"


def _gh_fingerprint(c: CandidateView) -> list:
    """The historical merge-rail fingerprint: the criterion + each candidate's low-capacity PR
    fields. Byte-identical to the pre-extraction key, so committed cassettes still resolve."""
    return [c.pr, c.title, c.body, c.base, sorted(str(f) for f in c.files),
            c.closes_issue, c.branch]


def cassette_key(criterion: str, candidates: List[CandidateView]) -> str:
    """The merge-rail cassette key (criterion + PR fingerprints, sorted by PR number)."""
    return _core.cassette_key(criterion, candidates, _gh_fingerprint, id_of=_pr_id)


class Cassette(_core.Cassette):
    def __init__(self, path, *, model: str = "", provider: str = "") -> None:
        super().__init__(path, fingerprint=_gh_fingerprint, id_of=_pr_id,
                         model=model, provider=provider, schema=CASSETTE_SCHEMA)


class SampleCassette(_core.SampleCassette):
    def __init__(self, path, *, model: str = "", provider: str = "", temperature=None) -> None:
        super().__init__(path, fingerprint=_gh_fingerprint, id_of=_pr_id, model=model,
                         provider=provider, temperature=temperature, schema=CASSETTE_SCHEMA)


class CassetteResolver(_core.CassetteResolver):
    """Role B backed by a merge-rail cassette: replay through the clamp, or record on a miss."""

    def __init__(self, cassette, *, record_from=None, label: str = "", save: bool = False) -> None:
        super().__init__(cassette, system=_SYSTEM, build_user=_build_user_prompt, id_of=_pr_id,
                         record_from=record_from, label=label, save=save)
