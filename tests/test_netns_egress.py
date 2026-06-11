"""EGRESS-SOLE-PATH, ENFORCED — the privilege-gated boundary verification (the keystone).

This is the OTHER HALF of ONLY-DOOR-OR-DECLARE. Its sibling, the deterministic egress battery
`test_broker_egress.py::test_08_NEGATIVE_direct_connection_bypasses_proxy`, records the ADVISORY
state: WITHOUT an OS only-door, a direct connection bypasses the proxy and SUCCEEDS. That test
stays exactly as it is — it is true, and it is half of the proof.

This test proves the boundary half: INSIDE a network namespace whose only route out is the broker
proxy, the very same direct-bypass move is now BLOCKED, while the honest CONNECT still tunnels.

  ┌─────────────────────────────────────────── two halves, both true ───────────────────────────┐
  │ advisory-WITHOUT (deterministic, always-run, no privilege) : direct bypass SUCCEEDS  (#8)    │
  │ boundary-WITH    (this file, opt-in, needs CAP_NET_ADMIN)  : direct bypass BLOCKED           │
  └──────────────────────────────────────────────────────────────────────────────────────────────┘

This is a MEASUREMENT in the two-tier sense, NOT a deterministic invariant: CI cannot obtain
CAP_NET_ADMIN, so it SKIPS cleanly here (mirroring the agentdojo / live-railbridge importorskip
discipline). It is enabled only with BOTH `SIGNET_NETNS_TEST=1` and the privilege/OS to back it.
The scorecard must therefore report EGRESS-SOLE-PATH as: "declared invariant; enforcement verified
by this opt-in netns integration test (requires CAP_NET_ADMIN) — NOT a CI invariant." CI proves the
rail logic and the advisory state; this proves the OS boundary.

Run it (Linux, root):  SIGNET_NETNS_TEST=1 sudo -E python -m pytest tests/test_netns_egress.py -v -s
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import socket

import pytest

from signet.broker.mandate import MandateProvider
from signet.broker.proxy import EgressBroker, EgressProxy
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.egress.dest_sim import EchoServer, StubResolver
from signet.rails.egress.mandate import EgressGrant, EgressMandate, EgressStandingPolicy
from signet.rails.egress.resolver import Resolution
from signet.sandbox import netns

# ---- the two-tier gate: opt-in AND privileged, else a CLEAN, visible skip --------------------
_PREFLIGHT = netns.preflight()
_OPT_IN = os.environ.get("SIGNET_NETNS_TEST") == "1"
if not _OPT_IN:
    _SKIP = ("set SIGNET_NETNS_TEST=1 to run the EGRESS-SOLE-PATH netns boundary verification "
             "(opt-in, privileged integration test — a MEASUREMENT, not a CI invariant)")
else:
    _SKIP = _PREFLIGHT  # None if runnable; otherwise the precise reason (platform / root / tools)

pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
_PROBE = "signet.sandbox._agent_probe"
_OFFSUBNET = ("192.0.2.1", 443)   # TEST-NET-1: guaranteed unrouted (raw-IP / no-route case)


def _agent_python() -> str:
    import sys
    return sys.executable


def test_netns_makes_egress_a_boundary(tmp_path, monkeypatch):
    """The keystone: in the netns the direct bypass is BLOCKED and the honest CONNECT still tunnels;
    DNS is closed; and the unprivileged agent cannot reconfigure the netns to escape."""
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "h"))
    cfg = netns.NetnsConfig()

    # Upstreams. ALLOWED on loopback (the proxy, in the HOST netns, reaches it and resolves the
    # honest hostname to it). EVIL on the host-side veth IP: genuinely reachable from the host, so
    # that the agent-side block we assert below is provably the netns's doing — not a dead port.
    allowed = EchoServer("ALLOWED").start()
    evil = EchoServer("EVIL", transform=lambda b: b"EVIL:" + b, host=cfg.host_ip).start()
    resolver = StubResolver({"api.allowed.test": Resolution("127.0.0.1", allowed.port)})

    mandates = MandateProvider()
    mandates.register(EgressMandate("task-001", (EgressGrant("api.allowed.test", (443,)),)))
    standing = EgressStandingPolicy((EgressGrant("api.allowed.test", (80, 443, 22)),))
    receipts = LocalReceiptLog("broker:egress:netns")

    controller = netns.NetnsController(cfg)
    proxy = None
    try:
        controller.setup()  # netns + veth + default route up; host_ip is now bind-able

        broker = EgressBroker.create(mandates=mandates, standing=standing, receipts=receipts,
                                     task_id="task-001", resolver=resolver, clock=lambda: T0)
        proxy = EgressProxy(broker, host=cfg.host_ip, port=0).start()
        controller.restrict_to_proxy(proxy.port)  # nft: agent may now reach ONLY host_ip:proxy.port

        # Sanity (host side): EVIL really is reachable from the host. So when the agent can't reach
        # it below, that is the netns, not a missing server. This is the teeth of the keystone.
        with socket.create_connection((cfg.host_ip, evil.port), timeout=3) as s:
            s.sendall(b"hi")
            assert s.recv(64) == b"EVIL:hi"

        # Run the agent UNPRIVILEGED inside the netns and collect its view.
        proc = controller.exec_agent([
            _agent_python(), "-m", _PROBE,
            cfg.host_ip, str(proxy.port),            # the proxy: the sole reachable endpoint
            "api.allowed.test", "443",               # honest destination (proxy resolves it)
            cfg.host_ip, str(evil.port),             # #8's direct-bypass target (host-reachable)
            _OFFSUBNET[0], str(_OFFSUBNET[1]),       # off-subnet / raw-IP, no route
        ], timeout=90)
        assert proc.returncode == 0, f"probe failed: {proc.stderr}\n{proc.stdout}"
        data = json.loads(proc.stdout.strip().splitlines()[-1])

        # HONEST PATH still works through the sandbox.
        assert data["honest"]["ok"] is True, data["honest"]
        assert data["honest"]["echo"] == "ping"

        # THE KEYSTONE — battery #8 INVERTED: the direct bypass now FAILS.
        assert data["direct_evil_blocked"] is True, "direct bypass to evil leaked through the netns"
        # raw-IP / off-subnet: no route, blocked.
        assert data["direct_offsubnet_blocked"] is True

        # NO-DNS: direct name resolution inside the netns fails (only the proxy resolves).
        assert data["dns_blocked"] is True

        # AGENT-UNPRIVILEGED-IN-NETNS: the agent cannot reconfigure the netns to escape.
        assert data["add_route_denied"] is True, "agent added a route — only-door is VOID"
        assert data["flush_nft_denied"] is True, "agent flushed nftables — only-door is VOID"
    finally:
        if proxy is not None:
            proxy.stop()
        allowed.stop()
        evil.stop()
        controller.teardown()

    # Teardown leaves nothing leaked: the netns and the host-side veth are gone (idempotent re-run).
    listed = controller._run(["ip", "netns", "list"], check=False, capture=True).stdout
    assert cfg.ns not in listed, f"netns {cfg.ns} leaked after teardown"
    gone = controller._run(["ip", "link", "show", cfg.veth_host], check=False, capture=True)
    assert gone.returncode != 0, f"host veth {cfg.veth_host} leaked after teardown"
    controller.teardown()  # second teardown is a clean no-op
