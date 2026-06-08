"""Record/replay ("cassette") seam for the Role-B LLM call — real model behavior captured
ONCE to a fixture, then replayed deterministically in CI with no key and no network.

Why a cassette and not a mock: the deterministic + adversarial-stub tests already prove the
GATE (they ARE the constraint). What they cannot show is how a REAL model behaves on fuzzy /
ambiguous / poisoned input. We capture that behavior once, commit it, and replay it — so CI
exercises genuine Role-B outputs (including the model being organically pulled toward the
attacker) without ever calling the API.

The cassette is keyed by a stable hash of the RESOLVER INPUTS (criterion + the candidate set's
low-capacity fields), NOT the full prompt text — so re-wording the system prompt does not
invalidate recordings, but changing the scenario does. The replayed raw text is run through the
SAME `_parse_set` clamp the live `LLMResolver` uses, so replay tests the real output path.

agentdojo-free: imports only stdlib + signet.canonical + the (agentdojo-free) resolver.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from signet.canonical import hash_obj

from .resolver import (CandidateView, CompleteFn, LLMResolver, Resolver, ResolverSet,
                       _SYSTEM, _build_user_prompt, _parse_set)

CASSETTE_SCHEMA = "signet.github.role_b_cassette.v1"


def cassette_key(criterion: str, candidates: List[CandidateView]) -> str:
    """A stable key over the resolver's INPUTS: the criterion plus each candidate's
    low-capacity fields (sorted by id). Deterministic and prompt-wording-independent."""
    payload = {
        "criterion": str(criterion),
        "candidates": [
            [c.pr, c.title, c.body, c.base, sorted(str(f) for f in c.files),
             c.closes_issue, c.branch]
            for c in sorted(candidates, key=lambda c: c.pr)
        ],
    }
    return hash_obj(payload)


class Cassette:
    """A JSON-backed store of recorded Role-B raw responses, keyed by `cassette_key`."""

    def __init__(self, path, *, model: str = "", provider: str = "") -> None:
        self.path = Path(path)
        self.model = model
        self.provider = provider
        self._entries: dict = {}
        if self.path.is_file():
            data = json.loads(self.path.read_text())
            self._entries = data.get("entries", {})
            self.model = self.model or data.get("_meta", {}).get("model", "")
            self.provider = self.provider or data.get("_meta", {}).get("provider", "")

    def get(self, criterion: str, candidates: List[CandidateView]) -> Optional[str]:
        e = self._entries.get(cassette_key(criterion, candidates))
        return e.get("raw") if e else None

    def put(self, criterion: str, candidates: List[CandidateView], raw: str, *,
            label: str = "") -> str:
        k = cassette_key(criterion, candidates)
        self._entries[k] = {"label": label, "criterion": criterion, "raw": raw}
        return k

    def labels(self) -> List[str]:
        return [e.get("label", "") for e in self._entries.values()]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"_meta": {"schema": CASSETTE_SCHEMA, "model": self.model,
                         "provider": self.provider,
                         "note": "Recorded Role-B responses; replayed in CI (no key/network). "
                                 "Re-record with: python -m evals.github_railbridge.record_cassette "
                                 "--record (needs OPENAI_API_KEY)."},
               "entries": self._entries}
        self.path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


class CassetteResolver(Resolver):
    """Role B backed by a cassette. In REPLAY mode (default) it returns the recorded raw text
    for a scenario and runs it through `_parse_set` — exactly the live output path, minus the
    network. In RECORD mode (`record_from` set to a live CompleteFn) it calls the model on a
    miss, stores the raw, and continues; pass `save=True` to persist."""

    def __init__(self, cassette: Cassette, *, record_from: Optional[CompleteFn] = None,
                 label: str = "", save: bool = False) -> None:
        self._cas = cassette
        self._record_from = record_from
        self._label = label
        self._save = save

    def resolve(self, criterion: str, candidates: List[CandidateView]) -> ResolverSet:
        valid = {c.pr for c in candidates}
        raw = self._cas.get(criterion, candidates)
        if raw is None:
            if self._record_from is None:
                raise KeyError(
                    "no cassette entry for this (criterion, candidates); record it first with "
                    "`python -m evals.github_railbridge.record_cassette --record`")
            raw = self._record_from(_SYSTEM, _build_user_prompt(criterion, candidates))
            self._cas.put(criterion, candidates, raw, label=self._label)
            if self._save:
                self._cas.save()
        return _parse_set(raw, valid)
