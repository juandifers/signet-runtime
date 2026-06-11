"""The egress proxy — the broker's SECOND surface (inline admission on the data path).

The broker is now MULTI-SURFACE: the unix-socket RPC (issuer mode, the DB rail — server.py) and
this forward proxy (inline mode, the egress rail). Both reuse the same machinery: the kernel
verifier (consume-once + signed token), the unchanged `Authorizer.authorize` template, and the
signed receipt log. The proxy adds no new kernel and forks nothing — it is a transport that
drives EgressAuthorizer.

Adoption property (DESIGN.md egress note): egress needs ZERO agent code. The agent makes normal
outbound connections (configured via HTTP(S)_PROXY in v0, forced by a netns in productization);
the proxy intercepts, resolves the destination with its OWN trusted resolver, and admits or
drops. There is no Signet client call on the agent side.

HONEST SCOPE: the proxy binds WHERE the agent connects (host+port), never WHAT it sends. The
CONNECT tunnel splices bytes verbatim — no TLS termination, no payload parsing. EGRESS-SOLE-PATH
(the netns) is what makes this a boundary; in v0 it is simulated and a negative test records that
a direct connection bypasses the proxy entirely.
"""
from __future__ import annotations

import datetime as _dt
import select
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..cli.local_receipts import LocalReceiptLog
from ..rails.egress.authorizer import EgressAuthorizer
from ..rails.egress.chain_adapter import EgressBrokerCore
from ..rails.egress.effect import EgressEffect
from ..rails.egress.mandate import EgressStandingPolicy
from ..rails.egress.resolver import SystemResolver, TrustedResolver
from .mandate import MandateProvider


@dataclass
class AdmissionResult:
    admitted: bool
    cause: str
    receipt_id: Optional[str] = None
    forward_ip: Optional[str] = None
    forward_port: Optional[int] = None
    chain_hash: Optional[str] = None


@dataclass
class EgressBroker:
    """Inline egress admission: resolve (trusted) -> mint token (kernel) -> authorize template
    -> receipt. Mirrors server.Broker but consumes the capability inline (no bearer token)."""
    core: EgressBrokerCore
    mandates: MandateProvider
    standing: EgressStandingPolicy
    receipts: LocalReceiptLog
    resolver: TrustedResolver
    clock: Callable[[], _dt.datetime]
    task_id: str
    agent_id: str = "agent"
    ttl_seconds: int = 60

    @classmethod
    def create(cls, *, mandates: MandateProvider, standing: EgressStandingPolicy,
               receipts: LocalReceiptLog, task_id: str,
               resolver: Optional[TrustedResolver] = None,
               clock: Optional[Callable[[], _dt.datetime]] = None,
               agent_id: str = "agent", ttl_seconds: int = 60) -> "EgressBroker":
        clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
        core = EgressBrokerCore.create(clock=clock, token_ttl_seconds=ttl_seconds)
        return cls(core=core, mandates=mandates, standing=standing, receipts=receipts,
                   resolver=resolver or SystemResolver(), clock=clock, task_id=task_id,
                   agent_id=agent_id, ttl_seconds=ttl_seconds)

    def _receipt(self, *, verdict: str, cause: str, eff: Optional[EgressEffect], channel: str,
                 resolved: Optional[Tuple[str, int]] = None,
                 policy_hash: Optional[str] = None, chain_hash: Optional[str] = None) -> str:
        effect_dict = {"kind": "egress", "channel": channel}
        if eff is not None:
            effect_dict["dest"] = eff.bound_dict()
        if resolved is not None:
            effect_dict["resolved"] = f"{resolved[0]}:{resolved[1]}"
        if chain_hash:
            effect_dict["chain_hash"] = chain_hash
        rec = self.receipts.append(repo="egress", tool_name="broker.egress",
                                   effect=effect_dict, verdict=verdict, cause=cause,
                                   policy_hash=policy_hash)
        return rec["id"]

    def admit(self, host: str, port: int, protocol: str = "http_connect",
              request_nonce: str = "") -> AdmissionResult:
        """Decide a single outbound connection. Inline: no token is handed out; the proxy uses
        the returned forward target immediately. Never raises (fail-closed)."""
        try:
            # Trusted resolution — the agent cannot choose the destination IP (poisoned-resolver
            # and raw-IP defense). The proxy resolves; the agent's resolver is irrelevant.
            try:
                res = self.resolver.resolve(host)
            except OSError:
                return AdmissionResult(False, "resolution-failed",
                                       self._receipt(verdict="deny", cause="resolution-failed",
                                                     eff=None, channel="proxy"))
            forward_ip = res.ip
            forward_port = res.port if res.port is not None else port
            eff = EgressEffect(host, port, protocol, resolved_ip=forward_ip)

            decision, token, req, verifier = self.core.mint_token(
                eff, self.task_id, self.agent_id, request_nonce)
            if not decision.approved or token is None:
                cause = "replay" if "Replay" in decision.reason else decision.reason
                return AdmissionResult(False, cause,
                                       self._receipt(verdict="deny", cause=cause, eff=eff,
                                                     channel="proxy"))

            authorizer = EgressAuthorizer(
                verifier, self.core.enforcer_vk, mandate_provider=self.mandates,
                standing_policy=self.standing, resolver=self.resolver, clock=self.clock)
            result = authorizer.authorize(token, req)
            mandate_hash = authorizer.last_mandate_hash

            if not result.executed:
                return AdmissionResult(False, result.reason,
                                       self._receipt(verdict="deny", cause=result.reason, eff=eff,
                                                     channel="injection", policy_hash=mandate_hash,
                                                     chain_hash=token.chain_hash))
            rid = self._receipt(verdict="pass", cause=result.reason, eff=eff, channel="proxy",
                                resolved=(forward_ip, forward_port), policy_hash=mandate_hash,
                                chain_hash=token.chain_hash)
            return AdmissionResult(True, result.reason, rid, forward_ip, forward_port,
                                   token.chain_hash)
        except Exception as e:  # fail-closed
            return AdmissionResult(False, f"internal-error:{type(e).__name__}",
                                   self._receipt(verdict="deny",
                                                 cause=f"internal-error:{type(e).__name__}",
                                                 eff=None, channel="proxy"))


def _recv_headers(conn: socket.socket) -> bytes:
    """Read up to the end of the request header block (b'\\r\\n\\r\\n')."""
    buf = b""
    conn.settimeout(2.0)
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(1024)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf


def _parse_authority(authority: str, default_port: int) -> Tuple[str, int]:
    if ":" in authority:
        host, _, p = authority.rpartition(":")
        return host, int(p)
    return authority, default_port


class EgressProxy:
    """A forward proxy driving inline egress admission. CONNECT (primary) + plain-HTTP forward."""

    def __init__(self, broker: EgressBroker, host: str = "127.0.0.1", port: int = 0):
        self._broker = broker
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._bind = (host, port)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.host = host
        self.port = port

    def start(self) -> "EgressProxy":
        self._sock.bind(self._bind)
        self._sock.listen(16)
        self._sock.settimeout(0.3)
        self.host, self.port = self._sock.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            head = _recv_headers(conn)
            if not head:
                return
            request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = request_line.split(" ")
            if len(parts) < 2:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            method, target = parts[0], parts[1]
            if method.upper() == "CONNECT":
                self._handle_connect(conn, target)
            elif target.lower().startswith("http://"):
                self._handle_plain(conn, head)
            else:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle_connect(self, conn: socket.socket, target: str) -> None:
        host, port = _parse_authority(target, 443)
        adm = self._broker.admit(host, port, protocol="http_connect")
        if not adm.admitted:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        try:
            upstream = socket.create_connection((adm.forward_ip, adm.forward_port), timeout=2)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._splice(conn, upstream)

    def _handle_plain(self, conn: socket.socket, first_head: bytes) -> None:
        """Plain-HTTP forward: admit PER REQUEST (a keep-alive connection can target different
        hosts). The host is read from the request LINE (routing framing), never the body/path —
        reading the routing target is not payload inspection."""
        head = first_head
        while head:
            request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = request_line.split(" ")
            if len(parts) < 2 or not parts[1].lower().startswith("http://"):
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            method, abs_uri = parts[0], parts[1]
            rest = abs_uri[len("http://"):]
            authority, _, path = rest.partition("/")
            host, port = _parse_authority(authority, 80)
            adm = self._broker.admit(host, port, protocol="http")
            if not adm.admitted:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            else:
                try:
                    upstream = socket.create_connection((adm.forward_ip, adm.forward_port),
                                                        timeout=2)
                    # origin-form request to the upstream (host+port already authorized)
                    origin = f"{method} /{path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                    upstream.sendall(origin)
                    upstream.settimeout(1.0)
                    try:
                        while True:
                            data = upstream.recv(4096)
                            if not data:
                                break
                            conn.sendall(data)
                    except socket.timeout:
                        pass
                    upstream.close()
                except OSError:
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            # try to read a subsequent pipelined request on this keep-alive connection
            try:
                head = _recv_headers(conn)
            except OSError:
                head = b""

    def _splice(self, a: socket.socket, b: socket.socket) -> None:
        """Verbatim bidirectional relay — NO parsing, NO modification. Arbitrary bytes (TLS
        records, binary) pass through untouched. Returns when either side closes."""
        socks = [a, b]
        try:
            while not self._stop.is_set():
                r, _, _ = select.select(socks, [], [], 5)
                if not r:
                    break
                for s in r:
                    data = s.recv(4096)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=1)
