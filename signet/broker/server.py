"""The broker server: peer-credential auth + the Role-2 authorizer template over a transport.

Two layers:
  * `Broker` — transport-agnostic core. `handle_request(req, peer_uid)` does peer-uid auth,
    mints a token through the unchanged kernel verifier, runs the unchanged authorizer template,
    writes a signed receipt (grant) or a ConsideredRejected receipt (refusal), and returns a
    CapabilityResponse. Fail-closed on any internal error.
  * `UnixSocketBrokerServer` — wraps `Broker` on a Unix domain socket, reading SO_PEERCRED to
    authenticate the connecting process as an OS principal (never a bearer secret the agent
    could leak). Refuses to start, and refuses each connection, when the peer shares the
    broker's own uid — the only-door is void if the agent runs as the same OS user (P8).

The granted path requires the agent to be a SEPARATE OS user; that two-user deployment is
exercised at the `Broker` core level (with an injected distinct peer_uid) so the battery is
deterministic and offline, while the socket layer demonstrates the real same-uid refusal. This
is the repo's standing two-tier split: offline invariants vs. live measurements.
"""
from __future__ import annotations

import datetime as _dt
import os
import socket
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from ..cli.local_receipts import LocalReceiptLog
from ..rails.supabase.authorizer import SupabaseAuthorizer
from ..rails.supabase.chain_adapter import DbBrokerCore
from ..rails.supabase.effect import DbEffect
from ..rails.supabase.es256 import Es256Key
from ..rails.supabase.roles import role_for_effect
from .mandate import MandateProvider, StandingPolicy
from .protocol import CapabilityRequest, CapabilityResponse


def authenticate_peer(peer_uid: Optional[int], broker_uid: int,
                      allow_same_uid: bool = False) -> tuple[bool, str]:
    """Authenticate the connecting OS principal by its uid. Fail-closed.

    The agent MUST be a different OS user than the broker; if they share a uid the only-door is
    void (the agent could read the broker's signing key off disk), so we refuse — unless
    `allow_same_uid` is explicitly set (single-user dev/CI exercising the granted path)."""
    if peer_uid is None:
        return False, "no-peer-credential"
    if peer_uid == broker_uid and not allow_same_uid:
        return False, ("same-uid-as-broker (only-door void: the agent must run as a separate "
                       "OS user)")
    return True, "peer-authenticated"


def read_peer_uid(conn: socket.socket) -> Optional[int]:
    """Best-effort peer uid from the connected socket. Uses SO_PEERCRED on Linux; falls back to
    the broker's own uid elsewhere (which, for a single-user host, correctly triggers the
    same-uid refusal). A real multi-user Linux deployment gets the true peer uid."""
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            return uid
        except OSError:
            pass
    return os.getuid()


@dataclass
class Broker:
    """Transport-agnostic broker core."""
    core: DbBrokerCore
    mandates: MandateProvider
    standing: StandingPolicy
    minter: Es256Key
    receipts: LocalReceiptLog
    clock: Callable[[], _dt.datetime]
    ttl_seconds: int = 60
    broker_uid: int = 0
    allow_same_uid: bool = False

    @classmethod
    def create(cls, *, mandates: MandateProvider, standing: StandingPolicy,
               receipts: LocalReceiptLog, minter: Optional[Es256Key] = None,
               clock: Optional[Callable[[], _dt.datetime]] = None,
               ttl_seconds: int = 60, allow_same_uid: bool = False) -> "Broker":
        clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
        core = DbBrokerCore.create(clock=clock, token_ttl_seconds=ttl_seconds)
        return cls(core=core, mandates=mandates, standing=standing,
                   minter=minter or Es256Key.generate(), receipts=receipts,
                   clock=clock, ttl_seconds=ttl_seconds, broker_uid=os.getuid(),
                   allow_same_uid=allow_same_uid)

    # -- receipts --
    def _receipt(self, *, verdict: str, cause: str, effect_dict: dict,
                 policy_hash: Optional[str]) -> str:
        rec = self.receipts.append(
            repo=effect_dict.get("db", {}).get("database"),
            tool_name="broker.capability",
            effect=effect_dict,
            verdict=verdict, cause=cause, policy_hash=policy_hash)
        return rec["id"]

    def _refuse(self, req: CapabilityRequest, cause: str, *, channel: str,
                effect: Optional[DbEffect] = None, policy_hash: Optional[str] = None,
                chain_hash: Optional[str] = None) -> CapabilityResponse:
        """A refused request is a recorded rejection (ConsideredRejected): a signed deny receipt
        carrying the cause + channel. No capability is minted. Never raises."""
        eff_dict = {"kind": "db", "channel": channel,
                    "db": effect.to_dict() if effect else req.effect_params}
        if chain_hash:
            eff_dict["chain_hash"] = chain_hash
        rid = self._receipt(verdict="deny", cause=cause, effect_dict=eff_dict,
                            policy_hash=policy_hash)
        return CapabilityResponse(granted=False, receipt_id=rid, cause=cause)

    # -- the one entry point --
    def handle_request(self, req: CapabilityRequest, peer_uid: int) -> CapabilityResponse:
        try:
            ok, why = authenticate_peer(peer_uid, self.broker_uid, self.allow_same_uid)
            if not ok:
                return self._refuse(req, why, channel="transport")
            if req.effect_kind != "db.query":
                return self._refuse(req, f"unsupported-effect-kind:{req.effect_kind}",
                                    channel="broker")

            effect = DbEffect.from_dict(req.effect_params)

            # 1. UNCHANGED kernel verifier: bind + sign + consume-once on chain_hash.
            decision, token, exreq, verifier = self.core.mint_token(
                effect, req.task_id, req.agent_id, req.request_nonce)
            if not decision.approved or token is None:
                # The kernel refused (e.g. replay) — record + refuse.
                cause = "replay" if "Replay" in decision.reason else decision.reason
                return self._refuse(req, cause, channel="broker", effect=effect)

            # 2. UNCHANGED authorizer template: verify_token -> recheck (mandate ∩ policy) ->
            #    produce_capability (mint the scoped JWT).
            authorizer = SupabaseAuthorizer(
                verifier, self.core.enforcer_vk,
                mandate_provider=self.mandates, standing_policy=self.standing,
                minter=self.minter, ttl_seconds=self.ttl_seconds, clock=self.clock)
            result = authorizer.authorize(token, exreq)
            mandate_hash = authorizer.last_mandate_hash

            if not result.executed:
                return self._refuse(req, result.reason, channel="injection", effect=effect,
                                    policy_hash=mandate_hash, chain_hash=token.chain_hash)

            now = self.clock()
            exp = (now + _dt.timedelta(seconds=self.ttl_seconds)).isoformat()
            role = role_for_effect(effect)
            rid = self._receipt(
                verdict="pass", cause=result.reason, policy_hash=mandate_hash,
                effect_dict={"kind": "db", "channel": "resolver", "db": effect.to_dict(),
                             "role": role, "chain_hash": token.chain_hash})
            return CapabilityResponse(
                granted=True, receipt_id=rid, capability=result.payment_ref,
                expires_at=exp, cause=result.reason,
                extra={"role": role, "chain_hash": token.chain_hash})
        except Exception as e:  # fail-closed: any internal error refuses, never crashes
            return self._refuse(req, f"internal-error:{type(e).__name__}", channel="broker")


class UnixSocketBrokerServer:
    """A Unix-domain-socket front end for `Broker`, authenticating peers by SO_PEERCRED."""

    def __init__(self, broker: Broker, socket_path: str,
                 expected_agent_uid: Optional[int] = None):
        self._broker = broker
        self._path = socket_path
        self._sock: Optional[socket.socket] = None
        # Refuse to start in a config where the agent would be the same OS user as the broker.
        if expected_agent_uid is not None and expected_agent_uid == os.getuid() \
                and not broker.allow_same_uid:
            msg = (f"REFUSING TO START: agent uid {expected_agent_uid} == broker uid "
                   f"{os.getuid()}. The only-door is void if the agent runs as the broker's OS "
                   f"user (it could read the signing key). Run the broker as a dedicated user.")
            print(msg)
            raise RuntimeError(msg)

    def start(self) -> None:
        if os.path.exists(self._path):
            os.unlink(self._path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(self._path)
        s.listen(8)
        self._sock = s

    def serve_one(self, timeout: Optional[float] = None) -> None:
        """Accept and handle exactly one connection (used by tests)."""
        assert self._sock is not None, "call start() first"
        if timeout is not None:
            self._sock.settimeout(timeout)
        conn, _ = self._sock.accept()
        try:
            peer_uid = read_peer_uid(conn)
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            req = CapabilityRequest.from_json(data.decode().strip())
            resp = self._broker.handle_request(req, peer_uid)
            conn.sendall((resp.to_json() + "\n").encode())
        finally:
            conn.close()

    def stop(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if os.path.exists(self._path):
            os.unlink(self._path)
