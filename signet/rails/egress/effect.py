"""The egress effect — the rail-specific bound side effect of an outbound connection.

The bound effect is the DESTINATION: host + port + protocol. `resolved_ip` is recorded for the
receipt/forwarding but is DELIBERATELY excluded from `effect_hash` and the chain — resolution is
the proxy's trusted act, and binding is by host+port (the egress analogue of binding the DB
target, not the row). Keeping the IP out of the hash means two connections to the same
host:port collide for consume-once regardless of which A-record they resolved to.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ...canonical import hash_obj

PROTOCOLS = ("http_connect", "tcp", "http")


@dataclass(frozen=True)
class EgressEffect:
    host: str                       # hostname OR an IP literal (raw-IP CONNECT)
    port: int
    protocol: str = "http_connect"
    resolved_ip: Optional[str] = None   # NOT part of the binding/hash; proxy's trusted result

    def __post_init__(self) -> None:
        if self.protocol not in PROTOCOLS:
            raise ValueError(f"unknown protocol {self.protocol!r} (expected {PROTOCOLS})")

    def target(self) -> str:
        return f"{self.host}:{self.port}"

    def bound_dict(self) -> dict:
        """The bound effect (no resolved_ip) — what rides in the AP2 chain + the hash."""
        return {"host": self.host, "port": self.port, "protocol": self.protocol}

    def effect_hash(self) -> str:
        return hash_obj(self.bound_dict())

    @staticmethod
    def from_bound_dict(d: dict) -> "EgressEffect":
        return EgressEffect(host=d["host"], port=int(d["port"]),
                            protocol=d.get("protocol", "http_connect"))
