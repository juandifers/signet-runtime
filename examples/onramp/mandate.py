"""`Mandate` — a fluent builder that emits a valid Signet mandate (spec §3).

Fit to the REAL schema (spec §0.1, the repo wins): the persisted DB mandate is
`signet.broker.mandate.TaskMandate` — `{task_id, database, grants:[{schema,table,ops}], expires_at,
signature}` (signet/broker/mandate.py:68-120, the exact shape of
examples/refund_triage/scenarios/mandate.clean.json). There is **no row-value field** because the
supabase door binds at `(schema, table, op)` only (DbGrant.permits, signet/broker/mandate.py:38-43)
— so this builder has **no `max_amount=`** helper (spec §0.3: the API must not over-promise).

A mandate may additionally carry **egress** grants (host + ports), which the egress proxy enforces
(signet/rails/egress/mandate.py:EgressGrant). Egress grants are NOT part of the persisted DB JSON
(that file is DB-only in the repo); `to_json()` round-trips the DB shape exactly, and `rails()`
reports both projections so `guard()` knows which doors to assemble.

`principal` maps to the demo's agent identity (AGENT_ID = "support-bot", agent.py:48), which is what
the session header renders; it is carried on the mandate, separate from the verified `task_id`.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Optional, Sequence, Union

from signet.broker.mandate import DbGrant, TaskMandate

from .errors import MalformedTargetError, UnknownRailError

DEFAULT_PRINCIPAL = "support-bot"        # agent.py:48 (AGENT_ID); the session principal
DEFAULT_DATABASE = "app"                 # scenarios/mandate.clean.json
DEFAULT_TASK_ID = "task-001"
DEFAULT_EGRESS_PORT = 443

KNOWN_RAILS = ("supabase", "egress")


class _EgressGrantSpec:
    """A builder-side egress grant (host + ports). Kept light so `Mandate` imports no rail crypto;
    materialised into `signet.rails.egress.mandate.EgressGrant` by `guard()` at wire time."""

    __slots__ = ("host", "ports")

    def __init__(self, host: str, ports: Sequence[int]) -> None:
        self.host = host
        self.ports = tuple(ports)


class Mandate:
    """Fluent builder for a Signet mandate spanning the supabase and/or egress rails.

        mandate = (
            Mandate("support-bot", task_id="refund-triage-001")
              .allow_db("public.credits", ops=("select", "insert"))
              .allow_egress("payments.internal")
              .build()
        )

    `build()` validates (non-empty scope, well-formed targets) and returns the mandate. Use
    `Mandate.from_json(path|dict)` to load an existing scenario mandate and `.to_json()` to emit the
    same DB artifact back (round-trips byte-for-byte against mandate.clean.json's fields)."""

    def __init__(self, principal: str = DEFAULT_PRINCIPAL, *, task_id: str = DEFAULT_TASK_ID,
                 database: str = DEFAULT_DATABASE) -> None:
        self.principal = principal
        self.task_id = task_id
        self.database = database
        self._db_grants: list[DbGrant] = []
        self._egress_grants: list[_EgressGrantSpec] = []
        self.expires_at: Optional[str] = None
        self._built = False

    # -- DB rail helpers (NO row-value kwarg — the door cannot back it) -------------------------
    def allow_db(self, target: str, *, ops: Sequence[str] = ("select", "insert")) -> "Mandate":
        """Grant `ops` on a `schema.table` (or `schema.*`). Mirrors one DbGrant."""
        schema, table = self._split_db_target(target)
        self._db_grants.append(DbGrant(schema=schema, table=table, ops=tuple(ops)))
        return self

    def allow_db_insert(self, target: str) -> "Mandate":
        """Convenience: grant `insert` on `schema.table` (the common write case)."""
        return self.allow_db(target, ops=("insert",))

    def allow_db_select(self, target: str) -> "Mandate":
        """Convenience: grant `select` on `schema.table`."""
        return self.allow_db(target, ops=("select",))

    # -- egress rail helper --------------------------------------------------------------------
    def allow_egress(self, host: str, *, port: int = DEFAULT_EGRESS_PORT,
                     ports: Optional[Sequence[int]] = None) -> "Mandate":
        """Allow CONNECT to `host` on the given port(s). `host` is a bare hostname (no scheme)."""
        self._check_egress_host(host)
        self._egress_grants.append(_EgressGrantSpec(host, tuple(ports) if ports else (port,)))
        return self

    # -- expiry --------------------------------------------------------------------------------
    def expires_in(self, *, minutes: float = 0, seconds: float = 0,
                   now: Optional[_dt.datetime] = None) -> "Mandate":
        base = now or _dt.datetime.now(_dt.timezone.utc)
        self.expires_at = (base + _dt.timedelta(minutes=minutes, seconds=seconds)).isoformat()
        return self

    def expires_at_iso(self, iso: Optional[str]) -> "Mandate":
        self.expires_at = iso
        return self

    # -- validate / finalize -------------------------------------------------------------------
    def build(self) -> "Mandate":
        """Validate the accumulated scope and return self. Raises a teaching error on empty scope."""
        if not self._db_grants and not self._egress_grants:
            raise UnknownRailError(
                "<empty>", KNOWN_RAILS)  # empty scope: nothing to guard
        self._built = True
        return self

    # -- projections ----------------------------------------------------------------------------
    def rails(self) -> set:
        r = set()
        if self._db_grants:
            r.add("supabase")
        if self._egress_grants:
            r.add("egress")
        return r

    def to_taskmandate(self) -> TaskMandate:
        """The DB-rail projection: the exact `TaskMandate` the seam freezes and the broker verifies."""
        return TaskMandate(task_id=self.task_id, database=self.database,
                           grants=tuple(self._db_grants), expires_at=self.expires_at)

    @property
    def egress_grants(self) -> tuple:
        return tuple(self._egress_grants)

    def granted_scope(self) -> list:
        """The flat (rail, action, target) allow-list the session header renders — supabase per-op
        plus one egress `connect` per (host, port). Mirrors session._combined_granted_scope."""
        scope = []
        for g in self._db_grants:
            for op in g.ops:
                scope.append({"rail": "supabase", "action": op, "target": f"{g.schema}.{g.table}"})
        for eg in self._egress_grants:
            for p in eg.ports:
                scope.append({"rail": "egress", "action": "connect", "target": f"{eg.host}:{p}"})
        return scope

    # -- JSON round-trip (DB artifact only — the repo's mandate files are DB-shaped) ------------
    def to_json(self) -> dict:
        """Emit the DB mandate artifact (TaskMandate.to_dict + signature:null) — the exact shape of
        scenarios/mandate.clean.json. Egress grants are not part of this file in the repo."""
        d = self.to_taskmandate().signing_payload()   # {task_id, database, grants, expires_at}
        d["signature"] = None
        return d

    def to_json_str(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_json(), indent=indent)

    def write_json(self, path: Union[str, Path]) -> Path:
        path = Path(path)
        path.write_text(self.to_json_str() + "\n")
        return path

    @classmethod
    def from_json(cls, src: Union[str, Path, dict], *, principal: str = DEFAULT_PRINCIPAL) -> "Mandate":
        """Load an existing DB mandate (path, JSON string, or dict) into a builder. Egress grants
        start empty (the DB files carry none); add them fluently if a second rail is wanted."""
        if isinstance(src, dict):
            d = src
        else:
            text = Path(src).read_text() if _looks_like_path(src) else str(src)
            d = json.loads(text)
        m = cls(principal, task_id=d["task_id"], database=d.get("database", DEFAULT_DATABASE))
        for g in d.get("grants", []):
            m._db_grants.append(DbGrant.from_dict(g))   # validates ops (signet/broker/mandate.py:51)
        m.expires_at = d.get("expires_at")
        return m

    # -- validation helpers --------------------------------------------------------------------
    @staticmethod
    def _split_db_target(target: str):
        if not isinstance(target, str) or "." not in target or "://" in target:
            raise MalformedTargetError.db(target)
        schema, _, table = target.partition(".")
        if not schema or not table:
            raise MalformedTargetError.db(target)
        return schema, table

    @staticmethod
    def _check_egress_host(host: str):
        if not isinstance(host, str) or not host or "://" in host or "/" in host:
            raise MalformedTargetError.egress(host)


def _looks_like_path(src) -> bool:
    s = str(src)
    return ("\n" not in s) and (s.endswith(".json") or Path(s).exists())
