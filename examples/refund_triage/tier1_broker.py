"""The Tier-1 broker process — hosts the UNCHANGED `Broker` over a Unix socket.

In the container this runs as **uid_broker**: it owns the ES256 signing key at a container-local
0600 path (unreadable by uid_agent), publishes only the PUBLIC jwks, and serves capability
requests over the socket. The peer-credential refusal (SO_PEERCRED) is what enforces identity —
not the socket file mode (which we widen only so a *different-uid* agent can connect; identity is
still checked by the kernel-provided peer uid).

Reuses `signet/broker/server.py` + `signet/rails/supabase/es256.py` verbatim — no transport edits.

Container entrypoint:  python3 -m examples.refund_triage.tier1_broker
Env: SIGNET_BROKER_SOCK, SIGNET_BROKER_KEY (private PEM path), SIGNET_BROKER_JWKS (public),
     SIGNET_HOME (broker-owned receipts dir), SIGNET_AGENT_UID (the agent uid to expect).
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Optional

from signet.broker.mandate import DbGrant, MandateProvider, StandingPolicy
from signet.broker.server import Broker, UnixSocketBrokerServer
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.supabase.es256 import Es256Key

from .agent import load_mandate


def build_broker(*, minter: Es256Key, clock=None, allow_same_uid: bool = False) -> Broker:
    """The refund broker: frozen mandate (credits {select,insert}) ∩ standing ceiling (public.*).
    Same mandate/standing as the Tier-0 door, so VERDICTS ARE IDENTICAL across tiers."""
    mandates = MandateProvider()
    mandates.register(load_mandate())
    standing = StandingPolicy(grants=(
        DbGrant("public", "*", ("select", "insert", "update", "delete")),))
    receipts = LocalReceiptLog("refund:broker")
    return Broker.create(mandates=mandates, standing=standing, receipts=receipts,
                         minter=minter, clock=clock, allow_same_uid=allow_same_uid)


def write_keypair(key_path: str, jwks_path: str) -> Es256Key:
    """Generate the ES256 key, write the PRIVATE PEM 0600 (owned by THIS process's uid) and the
    PUBLIC jwks 0644. The container runs this as uid_broker, so the private key is owned by
    uid_broker and unreadable by uid_agent — the structural key-custody property."""
    import json
    key = Es256Key.generate()
    kp = Path(key_path)
    kp.write_bytes(key.private_pem())
    os.chmod(kp, 0o600)                          # owner-only; agent uid cannot read it
    Path(jwks_path).write_text(json.dumps(key.jwks()))
    os.chmod(jwks_path, 0o644)                   # public verification material
    return key


def _open_socket_for_peer(socket_path: str) -> None:
    """Widen the SOCKET file mode so a different-uid agent can connect(). This does NOT weaken the
    only-door: identity is enforced by SO_PEERCRED (the kernel-supplied peer uid), never by file
    perms. Without this, default bind perms (others lack write) would block a cross-uid connect."""
    try:
        os.chmod(socket_path, 0o666)
    except OSError:
        pass


class ThreadBroker:
    """Run a broker over a real socket in a background thread (used by local tests). Accept loop
    until stop()."""

    def __init__(self, broker: Broker, socket_path: str, expected_agent_uid: Optional[int] = None):
        self._server = UnixSocketBrokerServer(broker, socket_path,
                                              expected_agent_uid=expected_agent_uid)
        self._path = socket_path
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def __enter__(self) -> "ThreadBroker":
        self._server.start()
        _open_socket_for_peer(self._path)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._server.serve_one(timeout=0.5)
            except (OSError, TimeoutError):           # accept timeout or socket closed on stop
                continue

    def __exit__(self, *exc) -> None:
        self.stop()

    def stop(self) -> None:
        self._stop.set()
        self._server.stop()
        if self._thread is not None:
            self._thread.join(timeout=2)


def serve_forever(broker: Broker, socket_path: str, *,
                  expected_agent_uid: Optional[int] = None) -> None:
    server = UnixSocketBrokerServer(broker, socket_path, expected_agent_uid=expected_agent_uid)
    server.start()
    _open_socket_for_peer(socket_path)
    print(f"[broker] serving on {socket_path} as uid={os.getuid()} "
          f"(expected agent uid={expected_agent_uid})", flush=True)
    try:
        while True:
            try:
                server.serve_one(timeout=None)
            except (OSError, TimeoutError) as e:
                print(f"[broker] connection error (continuing): {e}", flush=True)
    finally:
        server.stop()


def main() -> int:
    sock = os.environ["SIGNET_BROKER_SOCK"]
    key_path = os.environ["SIGNET_BROKER_KEY"]
    jwks_path = os.environ["SIGNET_BROKER_JWKS"]
    agent_uid = os.environ.get("SIGNET_AGENT_UID")
    minter = write_keypair(key_path, jwks_path)
    broker = build_broker(minter=minter)
    serve_forever(broker, sock,
                  expected_agent_uid=int(agent_uid) if agent_uid is not None else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
