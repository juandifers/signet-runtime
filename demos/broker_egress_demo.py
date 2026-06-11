"""A reproducible transcript of the egress rail (broker-as-proxy, DESIGN.md P7/P8/P9).

Runs the REAL egress proxy against offline localhost upstreams and prints, in order:
  honest CONNECT -> admitted + tunnel established + bytes round-trip + receipt;
  out-of-mandate destination -> refused + ConsideredRejected receipt;
  raw-IP to the attacker -> refused;
  the P8 negative: a DIRECT connection bypasses the proxy entirely (advisory without netns).

Everything shown is produced by the shipped code at run time. No verdict is authored here.

Run:  python -m demos.broker_egress_demo
"""
from __future__ import annotations

import datetime as _dt
import os
import socket
import tempfile

from signet.broker.mandate import MandateProvider
from signet.broker.proxy import EgressBroker, EgressProxy
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.egress.dest_sim import EchoServer, StubResolver
from signet.rails.egress.mandate import (EgressGrant, EgressMandate,
                                         EgressStandingPolicy)
from signet.rails.egress.resolver import Resolution

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)


def _p(s=""):
    print(s)


def main() -> int:
    os.environ.setdefault("SIGNET_HOME", tempfile.mkdtemp(prefix="signet_egress_demo_"))
    clock = lambda: T0
    allowed = EchoServer("ALLOWED").start()
    evil = EchoServer("EVIL", transform=lambda b: b"EVIL:" + b).start()
    resolver = StubResolver({"api.allowed.test": Resolution("127.0.0.1", allowed.port),
                             "evil.test": Resolution("127.0.0.1", evil.port)})
    mandates = MandateProvider()
    mandates.register(EgressMandate("task-001", (EgressGrant("api.allowed.test", (443,)),)))
    standing = EgressStandingPolicy((EgressGrant("api.allowed.test", (80, 443, 22)),
                                     EgressGrant("evil.test", (443,))))
    receipts = LocalReceiptLog("broker:egress:demo")
    broker = EgressBroker.create(mandates=mandates, standing=standing, receipts=receipts,
                                 task_id="task-001", resolver=resolver, clock=clock)
    proxy = EgressProxy(broker).start()

    _p("=" * 78)
    _p("SIGNET BROKER — egress rail (broker-as-proxy, DESIGN.md P7/P8/P9)")
    _p(f"  proxy at 127.0.0.1:{proxy.port}   frozen mandate task-001: {{api.allowed.test:443}}")
    _p("  agent needs ZERO code — it makes normal CONNECTs; the proxy intercepts + resolves")
    _p("  OS only-door (netns) is SIMULATED in v0 and DECLARED (EGRESS-SOLE-PATH)")
    _p("=" * 78)

    def connect(host, port, label, payload=b"ping"):
        _p()
        _p(f"[{label}] CONNECT {host}:{port}")
        s = socket.create_connection((proxy.host, proxy.port), timeout=3)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        reply = s.recv(256)
        if b"200" in reply:
            s.sendall(payload)
            s.settimeout(2)
            echo = s.recv(256)
            _p(f"   proxy   : ADMITTED — tunnel established")
            _p(f"   upstream: round-trip {payload!r} -> {echo!r}")
        else:
            _p(f"   proxy   : REFUSED ({reply.strip().decode('latin-1')})")
        s.close()

    connect("api.allowed.test", 443, "HONEST")
    connect("evil.test", 443, "OUT-OF-MANDATE")
    # raw-IP to evil's real localhost port (dodging the hostname)
    connect("127.0.0.1", evil.port, "RAW-IP EVASION")

    _p()
    _p("[P8 NEGATIVE] agent ignores the proxy and connects DIRECTLY to evil.test")
    s = socket.create_connection(("127.0.0.1", evil.port), timeout=2)
    s.sendall(b"exfil")
    s.settimeout(2)
    out = s.recv(256)
    s.close()
    _p(f"   bypass  : SUCCEEDS — direct connection returned {out!r}, NO proxy involved")
    _p("   => the proxy is only ADVISORY without the netns only-door (honest scope, P8)")

    _p()
    # show the receipts (granted + refused), each signed + hash-chained
    for r in receipts.records():
        dest = r["effect"].get("dest", {})
        _p(f"   receipt {r['id']}  {r['verdict']:4}  {dest.get('host','?')}:{dest.get('port','?')}"
           f"  ({r['cause']})")
    ok, msg, _ = receipts.verify()
    _p(f"RECEIPTS: {msg} -> verify ok={ok}")
    _p("=" * 78)

    proxy.stop(); allowed.stop(); evil.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
