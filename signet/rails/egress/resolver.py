"""The proxy's TRUSTED resolver — the egress analogue of the DB rail's server-side scope.

The proxy resolves destination hostnames ITSELF, never via the agent's resolver. This is what
defeats poisoned-resolver and raw-IP evasion: the agent cannot choose which IP a hostname maps
to, and a raw-IP target is admitted only if it matches the trusted resolution of an allowlisted
host. `Resolution.port` lets the offline sim map a hostname to a localhost upstream port; in
production it is None and forwarding uses the connection's own port.
"""
from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Resolution:
    ip: str
    port: Optional[int] = None      # sim: upstream localhost port; prod: None (use conn port)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class TrustedResolver(ABC):
    @abstractmethod
    def resolve(self, host: str) -> Resolution:
        ...


class SystemResolver(TrustedResolver):
    """Production default: the OS resolver under the broker's control (not the agent's)."""

    def resolve(self, host: str) -> Resolution:
        if is_ip_literal(host):
            return Resolution(ip=host, port=None)
        return Resolution(ip=socket.gethostbyname(host), port=None)
