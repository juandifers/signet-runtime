"""The Supabase DB effect — the rail-specific `effect_params` of a capability request.

A `DbEffect` is the bound side effect the agent wants to perform on the database. It is
the unit the broker re-checks against the frozen task mandate and binds the minted JWT to
(via `signet_effect_hash`). The effect is canonicalized so the same logical operation
always hashes identically (consume-once + capability binding both rely on this).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ...canonical import hash_obj

OPS = ("select", "insert", "update", "delete")


@dataclass(frozen=True)
class DbEffect:
    database: str
    schema: str
    table: str
    op: str
    predicate: Optional[str] = None

    def __post_init__(self) -> None:
        if self.op not in OPS:
            raise ValueError(f"unknown op {self.op!r} (expected one of {OPS})")

    def op_class(self) -> str:
        """ro for reads, rw for writes — the granularity of a v0 restricted role (FORK F)."""
        return "ro" if self.op == "select" else "rw"

    def target(self) -> str:
        return f"{self.schema}.{self.table}"

    def to_dict(self) -> dict:
        return {
            "database": self.database,
            "schema": self.schema,
            "table": self.table,
            "op": self.op,
            "predicate": self.predicate,
        }

    @staticmethod
    def from_dict(d: dict) -> "DbEffect":
        return DbEffect(
            database=d["database"],
            schema=d["schema"],
            table=d["table"],
            op=d["op"],
            predicate=d.get("predicate"),
        )

    def effect_hash(self) -> str:
        """Stable hash of the bound effect. The minted JWT carries this as
        `signet_effect_hash`, binding the capability to exactly this operation."""
        return hash_obj(self.to_dict())
