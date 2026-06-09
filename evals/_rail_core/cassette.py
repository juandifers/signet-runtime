"""Rail-AGNOSTIC record/replay ("cassette") seam for the Role-B LLM call — real model behavior
captured ONCE to a fixture, then replayed deterministically in CI with no key and no network.
Promoted from `evals/github_railbridge/cassette.py`.

The cassette is keyed by a stable hash of the RESOLVER INPUTS (criterion + a rail-supplied
FINGERPRINT of each candidate's low-capacity fields), NOT the full prompt text — so re-wording
the system prompt does not invalidate recordings, but changing the scenario does. The replayed
raw text is run through the SAME `parse_set` clamp the live resolver uses, so replay tests the
real output path. The rail injects `fingerprint` (candidate -> jsonable) and `id_of` (for a
stable sort); everything else here is rail-agnostic.

agentdojo-free: imports only stdlib + signet.canonical + the (agentdojo-free) resolver core.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, List, Optional

from signet.canonical import hash_obj

from .resolver import CompleteFn, Resolver, ResolverSet, parse_set

CASSETTE_SCHEMA = "signet.role_b_cassette.v1"


def cassette_key(criterion: str, candidates: List, fingerprint: Callable, *, id_of) -> str:
    """A stable key over the resolver's INPUTS: the criterion plus each candidate's low-capacity
    fingerprint (sorted by id). Deterministic and prompt-wording-independent. The rail supplies
    `fingerprint` (candidate -> a jsonable list of its non-injectable fields) and `id_of`."""
    payload = {
        "criterion": str(criterion),
        "candidates": [fingerprint(c) for c in sorted(candidates, key=id_of)],
    }
    return hash_obj(payload)


class Cassette:
    """A JSON-backed store of recorded Role-B raw responses, keyed by `cassette_key`. The rail
    binds a `fingerprint` + `id_of` at construction (subclasses default them)."""

    def __init__(self, path, *, fingerprint: Callable, id_of: Callable,
                 model: str = "", provider: str = "", schema: str = CASSETTE_SCHEMA) -> None:
        self.path = Path(path)
        self._fingerprint = fingerprint
        self._id_of = id_of
        self._schema = schema
        self.model = model
        self.provider = provider
        self._entries: dict = {}
        if self.path.is_file():
            data = json.loads(self.path.read_text())
            self._entries = data.get("entries", {})
            self.model = self.model or data.get("_meta", {}).get("model", "")
            self.provider = self.provider or data.get("_meta", {}).get("provider", "")

    def _key(self, criterion, candidates):
        return cassette_key(criterion, candidates, self._fingerprint, id_of=self._id_of)

    def get(self, criterion: str, candidates: List) -> Optional[str]:
        e = self._entries.get(self._key(criterion, candidates))
        return e.get("raw") if e else None

    def put(self, criterion: str, candidates: List, raw: str, *, label: str = "") -> str:
        k = self._key(criterion, candidates)
        self._entries[k] = {"label": label, "criterion": criterion, "raw": raw}
        return k

    def labels(self) -> List[str]:
        return [e.get("label", "") for e in self._entries.values()]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"_meta": {"schema": self._schema, "model": self.model,
                         "provider": self.provider,
                         "note": "Recorded Role-B responses; replayed in CI (no key/network)."},
               "entries": self._entries}
        self.path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


class SampleCassette:
    """A cassette that stores k recorded raws PER key (not one) — for a borderline sweep, which
    samples the model k times at temperature > 0 to measure a DISTRIBUTION over enumeration
    variance. Same `cassette_key` (resolver INPUTS) as `Cassette`, so a case's k samples share one
    key. Replay yields the recorded list; CI never calls out."""

    def __init__(self, path, *, fingerprint: Callable, id_of: Callable,
                 model: str = "", provider: str = "", temperature: Optional[float] = None,
                 schema: str = CASSETTE_SCHEMA) -> None:
        self.path = Path(path)
        self._fingerprint = fingerprint
        self._id_of = id_of
        self._schema = schema
        self.model = model
        self.provider = provider
        self.temperature = temperature
        self._entries: dict = {}
        if self.path.is_file():
            data = json.loads(self.path.read_text())
            self._entries = data.get("entries", {})
            meta = data.get("_meta", {})
            self.model = self.model or meta.get("model", "")
            self.provider = self.provider or meta.get("provider", "")
            if self.temperature is None:
                self.temperature = meta.get("temperature")

    def _key(self, criterion, candidates):
        return cassette_key(criterion, candidates, self._fingerprint, id_of=self._id_of)

    def get_samples(self, criterion: str, candidates: List) -> Optional[List[str]]:
        e = self._entries.get(self._key(criterion, candidates))
        return list(e.get("raws", [])) if e else None

    def put_samples(self, criterion: str, candidates: List, raws: List[str], *,
                    label: str = "", meta: Optional[dict] = None) -> str:
        k = self._key(criterion, candidates)
        self._entries[k] = {"label": label, "criterion": criterion,
                            "meta": dict(meta or {}), "raws": list(raws)}
        return k

    def labels(self) -> List[str]:
        return [e.get("label", "") for e in self._entries.values()]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"_meta": {"schema": self._schema + ".samples", "model": self.model,
                         "provider": self.provider, "temperature": self.temperature,
                         "note": "Recorded Role-B SAMPLES (k per key) for a borderline sweep; "
                                 "replayed in CI (no key/network)."},
               "entries": self._entries}
        self.path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


class CassetteResolver(Resolver):
    """Role B backed by a cassette. In REPLAY mode (default) it returns the recorded raw text for
    a scenario and runs it through `parse_set` — exactly the live output path, minus the network.
    In RECORD mode (`record_from` set to a live CompleteFn) it calls the model on a miss, stores
    the raw, and continues; pass `save=True` to persist. The rail supplies the SYSTEM prompt, the
    user-prompt builder, and the id accessor."""

    def __init__(self, cassette: Cassette, *, system: str, build_user: Callable, id_of: Callable,
                 record_from: Optional[CompleteFn] = None, label: str = "",
                 save: bool = False) -> None:
        self._cas = cassette
        self._system = system
        self._build_user = build_user
        self._id_of = id_of
        self._record_from = record_from
        self._label = label
        self._save = save

    def resolve(self, criterion: str, candidates: List) -> ResolverSet:
        valid = {self._id_of(c) for c in candidates}
        raw = self._cas.get(criterion, candidates)
        if raw is None:
            if self._record_from is None:
                raise KeyError(
                    "no cassette entry for this (criterion, candidates); record it first")
            raw = self._record_from(self._system, self._build_user(criterion, candidates))
            self._cas.put(criterion, candidates, raw, label=self._label)
            if self._save:
                self._cas.save()
        return parse_set(raw, valid)
