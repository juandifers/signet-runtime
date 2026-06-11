"""The frozen task mandate (FORK D: a signed task-grant file) + the standing policy ceiling.

TRUSTED INPUT (DESIGN.md P3). The task mandate is the operator's per-task grant, captured and
frozen BEFORE the agent reads any untrusted content, dropped as a signed file the broker reads
and the agent CANNOT write (it lives in the self-protected set). The broker authorizes a
capability request only if the requested effect lies within:

    frozen task mandate  ∩  standing policy

Monotonic narrowing: the per-task mandate can only SHRINK what the standing policy permits, it
can never widen it — so even a maximally hostile task grant cannot reach beyond the standing
ceiling (e.g. writes to prod). This mirrors the GitHub rail's `MergePolicy.intersect` and the
local fence's LOCAL-MONOTONIC rule.

Signing reuses the kernel Ed25519 helpers (`signet.crypto`) as a library — the operator signs,
the broker holds only the operator's verify key, so the agent cannot forge a grant.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .. import crypto
from ..canonical import canonical_json, hash_obj
from ..rails.supabase.effect import OPS, DbEffect


@dataclass(frozen=True)
class DbGrant:
    """One allowed slice of the database: a schema, a table (exact or "*"), and ops."""
    schema: str
    table: str
    ops: Tuple[str, ...]

    def permits(self, eff: DbEffect) -> bool:
        if eff.schema != self.schema:
            return False
        if self.table != "*" and self.table != eff.table:
            return False
        return eff.op in self.ops

    def to_dict(self) -> dict:
        return {"schema": self.schema, "table": self.table, "ops": list(self.ops)}

    @staticmethod
    def from_dict(d: dict) -> "DbGrant":
        ops = tuple(d["ops"])
        for o in ops:
            if o not in OPS:
                raise ValueError(f"grant has unknown op {o!r}")
        return DbGrant(schema=d["schema"], table=d["table"], ops=ops)


@dataclass(frozen=True)
class StandingPolicy:
    """The operator's standing ceiling — what is EVER permitted for this agent, regardless of
    any per-task grant. A task mandate is intersected with this; it can only narrow it."""
    grants: Tuple[DbGrant, ...]

    def permits(self, eff: DbEffect) -> bool:
        return any(g.permits(eff) for g in self.grants)


@dataclass(frozen=True)
class TaskMandate:
    """The frozen per-task grant. `signature` is the operator's over `signing_payload()`."""
    task_id: str
    database: str
    grants: Tuple[DbGrant, ...]
    expires_at: Optional[str] = None      # ISO-8601, optional
    signature: Optional[str] = None

    # -- scope test --
    def permits(self, eff: DbEffect) -> bool:
        if eff.database != self.database:
            return False
        return any(g.permits(eff) for g in self.grants)

    def is_expired(self, now: _dt.datetime) -> bool:
        if not self.expires_at:
            return False
        return now >= _dt.datetime.fromisoformat(self.expires_at)

    # -- signing / identity --
    def signing_payload(self) -> dict:
        return {
            "task_id": self.task_id,
            "database": self.database,
            "grants": [g.to_dict() for g in self.grants],
            "expires_at": self.expires_at,
        }

    def mandate_hash(self) -> str:
        return "tm_" + hash_obj(self.signing_payload())[:16]

    def sign(self, operator_sk: str) -> "TaskMandate":
        sig = crypto.sign(operator_sk, canonical_json(self.signing_payload()))
        return TaskMandate(self.task_id, self.database, self.grants, self.expires_at, sig)

    def verify(self, operator_vk: str) -> bool:
        if self.signature is None:
            return False
        return crypto.verify(operator_vk, canonical_json(self.signing_payload()), self.signature)

    # -- file form (the operator drops this; the agent cannot write it) --
    def to_json(self) -> str:
        d = self.signing_payload()
        d["signature"] = self.signature
        return json.dumps(d, indent=2)

    @staticmethod
    def from_dict(d: dict) -> "TaskMandate":
        return TaskMandate(
            task_id=d["task_id"],
            database=d["database"],
            grants=tuple(DbGrant.from_dict(g) for g in d.get("grants", [])),
            expires_at=d.get("expires_at"),
            signature=d.get("signature"),
        )


# --- the monotonic intersect, surfaced as a single decision the broker calls ---

def effective_permits(eff: DbEffect, mandate: TaskMandate,
                      standing: StandingPolicy) -> Tuple[bool, str]:
    """Is `eff` inside (frozen mandate ∩ standing policy)? Returns (ok, cause).

    Order matters for the cause string: the standing ceiling is checked FIRST, so a grant that
    tries to exceed the ceiling reports "out-of-standing-policy" (the monotonic violation),
    while an in-ceiling-but-ungranted effect reports "out-of-mandate"."""
    if not standing.permits(eff):
        return False, "out-of-standing-policy"
    if not mandate.permits(eff):
        return False, "out-of-mandate"
    return True, "within mandate ∩ policy"


class MandateProvider:
    """Maps task_id -> a verified, frozen TaskMandate. The broker loads signed grant files at
    startup (operator-supplied, agent-unwritable); tests register mandates directly."""

    def __init__(self, operator_vk: Optional[str] = None):
        self._operator_vk = operator_vk
        self._by_task: Dict[str, TaskMandate] = {}

    def register(self, mandate: TaskMandate, *, require_signature: bool = False) -> None:
        if require_signature:
            if self._operator_vk is None or not mandate.verify(self._operator_vk):
                raise ValueError("task mandate signature invalid (refusing unsigned/forged grant)")
        self._by_task[mandate.task_id] = mandate

    def load_file(self, path: Path) -> TaskMandate:
        """Load + verify a signed task-grant file. The operator's verify key MUST be configured;
        an unsigned or wrongly-signed grant is refused (the agent cannot forge a grant)."""
        m = TaskMandate.from_dict(json.loads(Path(path).read_text()))
        self.register(m, require_signature=True)
        return m

    def get(self, task_id: str) -> Optional[TaskMandate]:
        return self._by_task.get(task_id)
