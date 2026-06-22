"""`SignetConfig` — the on-ramp's deployment knob (spec §4).

The zero-config default is **Tier 0, advisory** (honest default, spec §0.4): the seam runs in-process
and the egress proxy is an inline/advisory door. `SignetConfig(tier=1, broker_socket=..., jwks_path=
...)` makes the DB rail **structural** (OS-separated broker over a Unix socket); `proxy="host:port"`
points the egress rail at a caller-run proxy instead of the demo's auto offline one.

The label is computed HONESTLY here, but the AUTHORITATIVE structural claim is still made at run time
by the demo's `detect_separation` (a same-uid peer or a non-Linux host degrades the label to
advisory regardless of what was requested — spec §0.4 / refund README "Platform requirement").
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SignetConfig:
    """How `guard()` should reach its doors.

    Attributes:
      tier:          0 = in-process advisory (default); 1 = structural (DB over an OS-separated broker).
      broker_socket: Tier-1 DB broker Unix-socket path (or via env SIGNET_BROKER_SOCK).
      jwks_path:     Tier-1 DB broker PUBLIC jwks path (or via env SIGNET_BROKER_JWKS).
      proxy:         egress proxy address "host:port"; if unset, the demo's auto offline proxy is used
                     (advisory). A caller-run proxy is still advisory until a netns forces it as the
                     sole route (structural egress is out of scope — refund README "Advisory").
    """
    tier: int = 0
    broker_socket: Optional[str] = None
    jwks_path: Optional[str] = None
    proxy: Optional[str] = None

    def __post_init__(self) -> None:
        if self.tier not in (0, 1):
            raise ValueError(f"SignetConfig.tier must be 0 or 1, got {self.tier!r}")

    @property
    def structural(self) -> bool:
        """True iff a structural DB boundary was REQUESTED (tier 1). Whether it is actually
        structural is confirmed at run time by detect_separation — the label never over-promises."""
        return self.tier == 1

    def label(self) -> str:
        """The honest tier label the on-ramp logs at wrap time. Egress is always advisory on this
        build; only the DB rail can be structural, and only when Tier 1 is verified at run time."""
        return "1 (structural, requested)" if self.tier == 1 else "0 (advisory)"

    def proxy_hostport(self) -> Optional[tuple]:
        if not self.proxy:
            return None
        host, _, port = self.proxy.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(
                f"SignetConfig.proxy {self.proxy!r} is malformed: expected 'host:port' "
                f"(e.g. '127.0.0.1:8443').")
        return host, int(port)
