"""Offline destination sim — the egress analogue of resource_sim.py.

Real localhost TCP upstreams (so the proxy's byte-splicing is exercised for real, with no
network) plus a deterministic trusted resolver mapping test hostnames to those upstreams.

  * the ALLOWED upstream (api.allowed.test) echoes bytes VERBATIM — so the no-inspection /
    binary-splice test can assert arbitrary bytes pass through untouched.
  * the ATTACKER upstream (evil.test) prefixes "EVIL:" — an identity marker, so a test can prove
    WHICH upstream answered (poisoned-resolver, direct-bypass).

The StubResolver is injected into the proxy as its trusted resolver; the proxy NEVER consults
the system resolver in tests, which is exactly how it ignores a poisoned agent-side resolver.
"""
from __future__ import annotations

import socket
import threading
from typing import Callable, Dict, Optional

from .resolver import Resolution, TrustedResolver, is_ip_literal


class EchoServer:
    """A trivial localhost TCP upstream. `transform(bytes)->bytes` is applied to each recv."""

    def __init__(self, name: str, transform: Optional[Callable[[bytes], bytes]] = None,
                 host: str = "127.0.0.1"):
        # `host` defaults to loopback (the offline deterministic tests); the netns boundary test
        # binds an upstream to the host-side veth IP so it is genuinely reachable from the host but
        # must be UNreachable from the sandboxed agent netns.
        self.name = name
        self._transform = transform or (lambda b: b)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(8)
        self._sock.settimeout(0.3)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def host(self) -> str:
        return self._sock.getsockname()[0]

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    def start(self) -> "EchoServer":
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
        conn.settimeout(1.0)
        try:
            while not self._stop.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(self._transform(data))
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=1)


class StubResolver(TrustedResolver):
    """Deterministic offline resolution: hostname -> Resolution(ip, upstream_port)."""

    def __init__(self, mapping: Dict[str, Resolution]):
        self._map = dict(mapping)

    def resolve(self, host: str) -> Resolution:
        if is_ip_literal(host):
            return Resolution(ip=host, port=None)
        if host not in self._map:
            raise OSError(f"name resolution failed for {host!r}")
        return self._map[host]
