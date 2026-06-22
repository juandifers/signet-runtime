"""Tier-1 demo: a LangGraph-shaped agent that holds NO key reaches the DB only through the broker.

Run:  python -m demos.langgraph_db_broker_demo

What it shows (offline, deterministic — real ES256 crypto, real role->GRANT, no network/LLM):

  1. ALLOW          — an in-mandate write (staging.analytics_events) is admitted by the broker
                      over a Unix socket; the agent receives a scoped, ~60s ES256 JWT (role
                      `signet_staging_rw`), uses it for exactly that call, and the capability
                      clears after.
  2. BLOCK          — an off-mandate read (prod.users) is contained: the tool never runs; a
                      structured `signet:blocked / out-of-mandate` refusal comes back instead.
  3. KILL-BROKER    — with the broker stopped, every guarded call fails closed
                      (`broker-unreachable`): no key in the agent, no broker => no DB access.

Topology (the security is the topology, not the code). The agent process imports only a socket
path via `BrokerTransport`; the broker process holds the only signing key. Here both run in one
process over a real socket (`allow_same_uid=True`) so the granted path is exercised portably —
that single-process mode is ADVISORY (mirrors test_broker_supabase's two-tier split). The
STRUCTURAL boundary is reached by running the broker as a SEPARATE OS user (a distinct uid), at
which point `allow_same_uid=False` and the same-uid peer is refused. Same one line of agent code
either way: `SignetMiddleware(transport=BrokerTransport(sock), ...)`.
"""
from __future__ import annotations

import datetime as _dt
import os
import threading

from signet.broker.mandate import DbGrant, MandateProvider, StandingPolicy, TaskMandate
from signet.broker.server import Broker, UnixSocketBrokerServer
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.supabase.es256 import Es256Key, verify_jwt

from integrations.effect_gateway.transport import BrokerTransport
from integrations.langgraph.middleware import (GuardedToolSpec, SignetMiddleware,
                                               current_capability)

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
SOCK = f"/tmp/sgnt_demo_{os.getpid()}.sock"


class _Req:
    """A minimal LangChain tool-call request (the middleware reads only `.tool_call`)."""
    def __init__(self, name, args):
        self.tool_call = {"name": name, "args": args, "id": "call-1", "type": "tool_call"}


def _make_broker():
    mandates = MandateProvider()
    mandates.register(TaskMandate(
        task_id="task-001", database="app",
        grants=(DbGrant("staging", "analytics_events", ("select", "delete")),)))
    standing = StandingPolicy(grants=(
        DbGrant("staging", "*", ("select", "insert", "update", "delete")),
        DbGrant("prod", "*", ("select",)),
    ))
    return Broker.create(mandates=mandates, standing=standing,
                         receipts=LocalReceiptLog("demo:app"),
                         minter=Es256Key.generate(),
                         clock=lambda: T0, ttl_seconds=60, allow_same_uid=True)


def _db_effect(args):
    if not all(k in args for k in ("schema", "table", "op")):
        return None
    return {"database": "app", "schema": args["schema"], "table": args["table"], "op": args["op"]}


def _run_call(mw, name, args):
    """Drive one guarded tool call through the middleware. The 'tool' just reports the capability
    it was handed (proving the agent has nothing until the broker grants it)."""
    seen = {}

    def handler(request):
        cap = current_capability()
        seen["cap"] = cap.token if cap else None
        return "TOOL RAN"

    result = mw.wrap_tool_call(_Req(name, args), handler)
    return result, seen.get("cap", "TOOL-DID-NOT-RUN")


def main() -> None:
    broker = _make_broker()
    server = UnixSocketBrokerServer(broker, SOCK)
    server.start()

    # The broker answers connections on a background thread (a real, separate server loop).
    stop = threading.Event()

    def serve_loop():
        while not stop.is_set():
            try:
                server.serve_one(timeout=0.5)
            except Exception:
                continue

    t = threading.Thread(target=serve_loop, daemon=True)
    t.start()

    # THE AGENT-SIDE WIRING — one line. No key here, only a socket path.
    mw = SignetMiddleware(transport=BrokerTransport(SOCK), task_id="task-001",
                          guarded_tools={"db": GuardedToolSpec(effect_from_args=_db_effect)})

    print("=" * 78)
    print("Tier-1 broker DB rail — the agent holds NO key, only a socket path:", SOCK)
    print("=" * 78)

    try:
        # 1. ALLOW — in-mandate write.
        msg, cap = _run_call(mw, "db", {"schema": "staging", "table": "analytics_events",
                                        "op": "delete"})
        status = getattr(msg, "status", None)
        if status != "error":
            claims = verify_jwt(cap, broker.minter.jwks(), now=T0)
            print(f"\n1. ALLOW  staging.analytics_events delete")
            print(f"   tool ran with scoped cap: role={claims['role']} "
                  f"exp=+{int(claims['exp']) - int(claims['iat'])}s sub={claims['sub']}")
            print(f"   capability cleared after the call: {current_capability() is None}")
        else:
            print(f"\n1. unexpected BLOCK: {msg.content}")

        # 2. BLOCK — off-mandate read.
        msg, cap = _run_call(mw, "db", {"schema": "prod", "table": "users", "op": "select"})
        print(f"\n2. BLOCK  prod.users select")
        print(f"   tool ran? {'no' if cap == 'TOOL-DID-NOT-RUN' else 'YES (BUG)'}  "
              f"refusal: {msg.content}")

        # 3. KILL-BROKER — stop the server; every guarded call now fails closed.
        stop.set()
        t.join(timeout=2)
        server.stop()
        msg, cap = _run_call(mw, "db", {"schema": "staging", "table": "analytics_events",
                                        "op": "delete"})
        print(f"\n3. KILL-BROKER  staging.analytics_events delete (broker down)")
        print(f"   tool ran? {'no' if cap == 'TOOL-DID-NOT-RUN' else 'YES (BUG)'}  "
              f"refusal: {msg.content}")
        print("\nNo key in the agent + no broker => no DB access. Fail-closed.\n")
    finally:
        stop.set()
        try:
            server.stop()
        except Exception:
            pass


if __name__ == "__main__":
    main()
