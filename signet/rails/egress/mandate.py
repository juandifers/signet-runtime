"""The egress allow-set: frozen task mandate ∩ standing policy over (host, port).

Mirrors signet/broker/mandate.py (the DB rail), but the unit is a destination, not a DB slice.
Host match (FORK F-egress): exact host OR an explicit suffix wildcard ("*.allowed.test"); a bare
"*" is REJECTED at construction — it would void the rail. Monotonic: a per-task mandate can only
narrow the standing allow-set (the proxy intersects them; a grant can never widen the ceiling).
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Optional, Tuple

from ... import crypto
from ...canonical import canonical_json, hash_obj
from .effect import EgressEffect


def host_matches(pattern: str, host: str) -> bool:
    """Exact host, or a single explicit suffix wildcard '*.suffix'. Bare '*' never matches here
    (it is rejected at grant construction). Case-insensitive."""
    p, h = pattern.lower(), host.lower()
    if p == "*":
        return False  # defense in depth: a bare '*' must never be honored
    if p.startswith("*."):
        suffix = p[1:]                       # ".allowed.test"
        return h.endswith(suffix) and len(h) > len(suffix)
    return p == h


@dataclass(frozen=True)
class EgressGrant:
    host: str                 # exact or "*.suffix"
    ports: Tuple[int, ...]

    def __post_init__(self) -> None:
        if self.host.strip() == "*":
            raise ValueError("a bare '*' host grant would void the egress rail (FORK F-egress)")

    def permits(self, eff: EgressEffect) -> bool:
        return host_matches(self.host, eff.host) and eff.port in self.ports

    def to_dict(self) -> dict:
        return {"host": self.host, "ports": list(self.ports)}

    @staticmethod
    def from_dict(d: dict) -> "EgressGrant":
        return EgressGrant(host=d["host"], ports=tuple(int(p) for p in d["ports"]))


@dataclass(frozen=True)
class EgressStandingPolicy:
    grants: Tuple[EgressGrant, ...]

    def permits(self, eff: EgressEffect) -> bool:
        return any(g.permits(eff) for g in self.grants)


@dataclass(frozen=True)
class EgressMandate:
    task_id: str
    grants: Tuple[EgressGrant, ...]
    expires_at: Optional[str] = None
    signature: Optional[str] = None

    def permits(self, eff: EgressEffect) -> bool:
        return any(g.permits(eff) for g in self.grants)

    def is_expired(self, now: _dt.datetime) -> bool:
        if not self.expires_at:
            return False
        return now >= _dt.datetime.fromisoformat(self.expires_at)

    def signing_payload(self) -> dict:
        return {"task_id": self.task_id,
                "grants": [g.to_dict() for g in self.grants],
                "expires_at": self.expires_at}

    def mandate_hash(self) -> str:
        return "em_" + hash_obj(self.signing_payload())[:16]

    def sign(self, operator_sk: str) -> "EgressMandate":
        sig = crypto.sign(operator_sk, canonical_json(self.signing_payload()))
        return EgressMandate(self.task_id, self.grants, self.expires_at, sig)

    def verify(self, operator_vk: str) -> bool:
        if self.signature is None:
            return False
        return crypto.verify(operator_vk, canonical_json(self.signing_payload()), self.signature)

    @staticmethod
    def from_dict(d: dict) -> "EgressMandate":
        return EgressMandate(
            task_id=d["task_id"],
            grants=tuple(EgressGrant.from_dict(g) for g in d.get("grants", [])),
            expires_at=d.get("expires_at"), signature=d.get("signature"))


def effective_admits(eff: EgressEffect, mandate: EgressMandate,
                     standing: EgressStandingPolicy) -> Tuple[bool, str]:
    """Is `eff` inside (frozen mandate ∩ standing policy)? Standing ceiling checked first, so a
    grant exceeding it reports 'out-of-standing-policy'; an in-ceiling-but-ungranted destination
    reports 'out-of-mandate-destination'."""
    if not standing.permits(eff):
        return False, "out-of-standing-policy"
    if not mandate.permits(eff):
        return False, "out-of-mandate-destination"
    return True, "within mandate ∩ policy"
