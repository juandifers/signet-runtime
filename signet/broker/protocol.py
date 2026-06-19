"""The broker wire envelope — newline-delimited JSON over the Unix socket.

CapabilityRequest { effect_kind, effect_params, task_id, agent_id, request_nonce } -> broker ->
CapabilityResponse { granted, capability?, expires_at?, receipt_id, cause }.

`effect_params` is rail-specific (for the Supabase rail it is a DbEffect dict). `capability` is
opaque to the transport (for the Supabase rail it is the minted ES256 JWT). `request_nonce` is
optional: omit it and identical requests collide on chain_hash (consume-once replay protection);
supply a fresh value to legitimately re-request the same logical effect later.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class CapabilityRequest:
    effect_kind: str                 # e.g. "db.query"
    effect_params: dict
    task_id: str
    agent_id: str = "agent"
    request_nonce: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(s: str) -> "CapabilityRequest":
        d = json.loads(s)
        return CapabilityRequest(
            effect_kind=d["effect_kind"],
            effect_params=d["effect_params"],
            task_id=d["task_id"],
            agent_id=d.get("agent_id", "agent"),
            request_nonce=d.get("request_nonce", ""),
        )


@dataclass
class CapabilityResponse:
    granted: bool
    receipt_id: Optional[str] = None
    capability: Optional[str] = None      # the minted JWT, when granted
    expires_at: Optional[str] = None      # ISO-8601, when granted
    cause: str = ""
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(s: str) -> "CapabilityResponse":
        d = json.loads(s)
        return CapabilityResponse(
            granted=d["granted"],
            receipt_id=d.get("receipt_id"),
            capability=d.get("capability"),
            expires_at=d.get("expires_at"),
            cause=d.get("cause", ""),
            extra=d.get("extra", {}),
        )
