"""The capability transport — the swappable backend BEHIND `SignetMiddleware`.

This is the seam that makes the security TIER a deployment choice, not a code change. The
middleware depends ONLY on the `CapabilityTransport` protocol; which concrete transport is
constructed decides where the signing key lives:

  * `BrokerTransport(socket_path)` — Tier 1 (structural). Wraps the agent-side `BrokerClient`
    and talks to the out-of-process broker over a Unix socket. The agent process holds NO key —
    only a socket path; peer identity is the OS's job (SO_PEERCRED). A socket error (broker
    down / unreachable / timeout) maps to a fail-closed `granted=False, cause="broker-unreachable"`.

  * `InProcessTransport(broker)` — Tier 0 (advisory). Calls an in-process `Broker` core directly.
    The decision logic is IDENTICAL to Tier 1 (same kernel verify + authorizer template), but the
    signing key is co-located in the agent process, so this tier is advisory: it is the dev/low-
    stakes backend, and the basis for the INVARIANT-INTERFACE property (same middleware, same
    control flow, only the key location differs).

The two transports share a return type, `CapabilityOutcome` — a transport-neutral view of the
broker's `CapabilityResponse`. The middleware never sees a socket or a `Broker`; it sees an
outcome. THIS MODULE HOLDS NO KEY: it imports no signing key, no key-issuing code, no service-
role credential, no DSN — only a socket path (Tier 1) or a runtime `Broker` object handed in
(Tier 0), whose key never crosses this seam.
"""
from __future__ import annotations

import socket as _socket
from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from signet.broker.client import BrokerClient
from signet.broker.protocol import CapabilityRequest


@dataclass(frozen=True)
class CapabilityOutcome:
    """A transport-neutral view of one capability decision. `granted=False` is always a
    fail-closed contain — the middleware never runs the tool on a non-granted outcome."""
    granted: bool
    cause: str = ""
    capability: Optional[str] = None      # the scoped, short-TTL JWT, when granted
    expires_at: Optional[str] = None      # ISO-8601, when granted
    receipt_id: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @staticmethod
    def from_response(resp) -> "CapabilityOutcome":
        return CapabilityOutcome(
            granted=resp.granted, cause=resp.cause, capability=resp.capability,
            expires_at=resp.expires_at, receipt_id=resp.receipt_id,
            extra=dict(resp.extra or {}))

    @staticmethod
    def blocked(cause: str) -> "CapabilityOutcome":
        return CapabilityOutcome(granted=False, cause=cause)


@runtime_checkable
class CapabilityTransport(Protocol):
    """The one method the middleware depends on. Concrete transports decide WHERE the key is."""

    def request(self, *, effect_kind: str, effect_params: dict, task_id: str,
                agent_id: str, request_nonce: str) -> CapabilityOutcome: ...


# Errors that mean "the broker could not be reached" — every one is fail-closed to a contain,
# never an implicit allow. (ConnectionRefused/FileNotFound = no listener; timeout = hung broker.)
_UNREACHABLE = (ConnectionRefusedError, FileNotFoundError, _socket.timeout, OSError)


class BrokerTransport:
    """Tier 1: the agent asks the out-of-process broker over a Unix socket. Holds only the
    socket path — NO signing key, NO DB credential. Fail-closed: if the broker is not listening,
    is unreachable, or times out, the outcome is a contain (`broker-unreachable`)."""

    def __init__(self, socket_path: str, *, timeout: float = 5.0):
        self._client = BrokerClient(socket_path)
        self._timeout = timeout

    def request(self, *, effect_kind: str, effect_params: dict, task_id: str,
                agent_id: str, request_nonce: str) -> CapabilityOutcome:
        if effect_kind != "db.query":
            return CapabilityOutcome.blocked(f"unsupported-effect-kind:{effect_kind}")
        req = CapabilityRequest(effect_kind=effect_kind, effect_params=dict(effect_params),
                                task_id=task_id, agent_id=agent_id, request_nonce=request_nonce)
        try:
            resp = self._client.request_capability(req, timeout=self._timeout)
        except _UNREACHABLE:
            # The boundary is unreachable -> contain. The tool must NEVER run on this path.
            return CapabilityOutcome.blocked("broker-unreachable")
        except Exception as e:  # any other transport-level surprise is still fail-closed
            return CapabilityOutcome.blocked(f"transport-error:{type(e).__name__}")
        return CapabilityOutcome.from_response(resp)


class InProcessTransport:
    """Tier 0 (advisory): call an in-process `Broker` core directly. Same decision code as Tier 1
    (kernel verify + authorizer template), but the key-issuing core is co-located -> the signing
    key is in the agent process. Dev / low-stakes only; the security upgrade to Tier 1 is swapping
    THIS for `BrokerTransport` plus running the broker as a separate uid — no middleware change.

    `peer_uid` defaults to the broker's own uid; a single-process Tier-0 broker is created with
    `allow_same_uid=True` so the in-process call authenticates (there is no OS boundary here — that
    is exactly what makes Tier 0 advisory)."""

    def __init__(self, broker, *, peer_uid: Optional[int] = None):
        self._broker = broker
        self._peer_uid = peer_uid if peer_uid is not None else getattr(broker, "broker_uid", 0)

    def request(self, *, effect_kind: str, effect_params: dict, task_id: str,
                agent_id: str, request_nonce: str) -> CapabilityOutcome:
        req = CapabilityRequest(effect_kind=effect_kind, effect_params=dict(effect_params),
                                task_id=task_id, agent_id=agent_id, request_nonce=request_nonce)
        try:
            resp = self._broker.handle_request(req, self._peer_uid)
        except Exception as e:  # the broker core is itself fail-closed, but belt-and-braces
            return CapabilityOutcome.blocked(f"broker-error:{type(e).__name__}")
        return CapabilityOutcome.from_response(resp)
