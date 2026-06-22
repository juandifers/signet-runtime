"""Acceptance for `SignetMiddleware` + the broker-client wire (the Tier-1 DB rail).

Each test = one gate from the spec §3/§6. House style mirrors test_broker_supabase.py: a fully
wired broker + a fixed clock + a tmp SIGNET_HOME, offline and deterministic (real ES256 crypto,
real role->GRANT, no model, no network). The worked example is unchanged: a frozen task mandate
scopes the agent to `staging.analytics_events` (select|delete); an injection wants `prod.users`.

The invariant under test is INVARIANT-INTERFACE: the SAME middleware, behind `InProcessTransport`
(Tier 0, key co-located, advisory) vs `BrokerTransport` (Tier 1, out-of-process, structural),
produces identical ALLOW/BLOCK control flow — security is the transport + the process topology,
never the agent code.

langchain is required to construct the middleware; tests that need it `importorskip`. The pure
transport-level tests (kill-broker, same-uid, scoped-ttl) run without langchain.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
import threading
from pathlib import Path

import pytest

from signet.broker.mandate import DbGrant, MandateProvider, StandingPolicy, TaskMandate
from signet.broker.server import Broker, UnixSocketBrokerServer
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.supabase.es256 import Es256Key, verify_jwt

from integrations.effect_gateway.transport import (BrokerTransport, CapabilityOutcome,
                                                   InProcessTransport)

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[1]


class Clock:
    def __init__(self, now: _dt.datetime):
        self.now = now

    def __call__(self) -> _dt.datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now = self.now + _dt.timedelta(seconds=seconds)


def _make_broker(tmp_path, monkeypatch, *, allow_same_uid: bool, tag: str = "mw") -> Broker:
    """The worked-example broker: staging.analytics_events (select|delete) granted; prod read-only
    at the ceiling. `allow_same_uid` lets the single-process granted path through the OS check."""
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "signet_home"))
    clock = Clock(T0)
    mandates = MandateProvider()
    mandates.register(TaskMandate(
        task_id="task-001", database="app",
        grants=(DbGrant("staging", "analytics_events", ("select", "delete")),)))
    standing = StandingPolicy(grants=(
        DbGrant("staging", "*", ("select", "insert", "update", "delete")),
        DbGrant("prod", "*", ("select",)),
    ))
    broker = Broker.create(mandates=mandates, standing=standing,
                           receipts=LocalReceiptLog(f"broker:{tag}"),
                           minter=Es256Key.generate(), clock=clock, ttl_seconds=60,
                           allow_same_uid=allow_same_uid)
    return broker


# A guarded "db write" tool reading its effect from args. The model supplies schema/table/op; the
# database is fixed by the deployment (the agent does not get to pick the database).
def _db_effect_from_args(args: dict):
    if not all(k in args for k in ("schema", "table", "op")):
        return None
    return {"database": "app", "schema": args["schema"], "table": args["table"],
            "op": args["op"]}


# --------------------------------------------------------------------------------------------
# Lightweight stand-ins for the LangChain tool-call request/handler, so the middleware decision
# logic is exercised without spinning a full graph. `wrap_tool_call` only reads `request.tool_call`
# and calls `handler(request)`.
# --------------------------------------------------------------------------------------------
class _Req:
    def __init__(self, name, args, _id="call-1"):
        self.tool_call = {"name": name, "args": args, "id": _id, "type": "tool_call"}


class _Handler:
    """Records that it ran and what capability was visible WHILE it ran (proves ALLOW-RUNS-WITH-
    CAP and that the scope is live during the call)."""
    def __init__(self):
        self.ran = False
        self.cap_during = "UNSET"

    def __call__(self, request):
        from integrations.langgraph.middleware import current_capability
        self.ran = True
        cap = current_capability()
        self.cap_during = cap.token if cap else None
        from langchain_core.messages import ToolMessage
        return ToolMessage(content="ok", name=request.tool_call["name"],
                           tool_call_id=request.tool_call["id"])


def _middleware(transport, **kw):
    pytest.importorskip("langchain")
    from integrations.langgraph.middleware import GuardedToolSpec, SignetMiddleware
    spec = GuardedToolSpec(effect_from_args=_db_effect_from_args)
    return SignetMiddleware(transport=transport, task_id="task-001",
                            guarded_tools={"db_write": spec, "db_read": spec}, **kw)


# ===========================================================================================
# §6.1 — in-mandate write -> ALLOW; handler runs; the scoped JWT is live during the call and
#        cleared after (BLOCK-NEVER-RUNS / ALLOW-RUNS-WITH-CAP).
# ===========================================================================================
def test_allowed_db_write_runs_with_scoped_cap(tmp_path, monkeypatch):
    from integrations.langgraph.middleware import current_capability
    broker = _make_broker(tmp_path, monkeypatch, allow_same_uid=True)
    mw = _middleware(InProcessTransport(broker))
    h = _Handler()

    msg = mw.wrap_tool_call(_Req("db_write", {"schema": "staging",
                                              "table": "analytics_events", "op": "delete"}), h)
    assert h.ran is True
    assert h.cap_during and h.cap_during != "UNSET"        # a real JWT was in scope during the call
    claims = verify_jwt(h.cap_during, broker.minter.jwks(), now=T0)
    assert claims["role"] == "signet_staging_rw" and claims["sub"] == "task-001"
    assert current_capability() is None                    # scope cleared after the call
    assert getattr(msg, "status", None) != "error"         # a normal tool result, not a refusal


# ===========================================================================================
# §6.2 — off-mandate (prod / delete-off-table) -> BLOCK; handler NOT called; structured refusal.
# ===========================================================================================
def test_off_mandate_db_write_blocked(tmp_path, monkeypatch):
    broker = _make_broker(tmp_path, monkeypatch, allow_same_uid=True)
    mw = _middleware(InProcessTransport(broker))
    h = _Handler()

    msg = mw.wrap_tool_call(_Req("db_write", {"schema": "prod", "table": "users",
                                              "op": "select"}), h)
    assert h.ran is False                                   # the tool never ran
    assert getattr(msg, "status", None) == "error"
    import json
    body = json.loads(msg.content)
    assert body["signet"] == "blocked" and body["cause"] == "out-of-mandate"
    assert body["receipt_id"]                               # the deny receipt is referenced


# ===========================================================================================
# §6.3 — AGENT-HOLDS-NO-KEY: the agent-side modules name no signing key / minter / DB credential.
# ===========================================================================================
def test_agent_holds_no_key():
    forbidden = ["Es256Key", "minter", "service_role", "private_pem", "DATABASE_URL",
                 "SUPABASE_SECRET", "mint_jwt", "enforcer_sk", "principal_sk"]
    for rel in ["integrations/effect_gateway/transport.py",
                "integrations/langgraph/middleware.py"]:
        src = (REPO_ROOT / rel).read_text()
        hits = [tok for tok in forbidden if tok in src]
        assert not hits, f"{rel} references key material {hits} — AGENT-HOLDS-NO-KEY violated"
    # The Tier-1 transport holds ONLY a socket path.
    bt = BrokerTransport("/tmp/whatever.sock")
    assert {type(v).__name__ for v in vars(bt).values()} <= {"BrokerClient", "float"}


# ===========================================================================================
# §6.4 — KILL-BROKER-NO-WRITES: broker not listening -> BLOCK (broker-unreachable); tool never runs.
# ===========================================================================================
def test_kill_broker_no_writes(tmp_path, monkeypatch):
    dead_sock = str(tmp_path / "no_broker.sock")             # nothing is listening here
    transport = BrokerTransport(dead_sock, timeout=1.0)
    out = transport.request(effect_kind="db.query",
                            effect_params=_db_effect_from_args(
                                {"schema": "staging", "table": "analytics_events", "op": "delete"}),
                            task_id="task-001", agent_id="agent", request_nonce="n1")
    assert out.granted is False and out.cause == "broker-unreachable"

    # And through the middleware: handler is never called.
    mw = _middleware(transport)
    h = _Handler()
    msg = mw.wrap_tool_call(_Req("db_write", {"schema": "staging",
                                              "table": "analytics_events", "op": "delete"}), h)
    assert h.ran is False and getattr(msg, "status", None) == "error"


# ===========================================================================================
# §6.5 — SAME-UID-REFUSED: allow_same_uid=False + a same-uid peer (single process over a real
#        socket) -> BLOCK at the transport (only-door void).
# ===========================================================================================
def test_same_uid_refused(tmp_path, monkeypatch):
    broker = _make_broker(tmp_path, monkeypatch, allow_same_uid=False)
    sock_path = f"/tmp/sgntmw_{os.getpid()}.sock"            # AF_UNIX path is length-capped on macOS
    server = UnixSocketBrokerServer(broker, sock_path)
    server.start()
    err = {}

    def _serve():
        try:
            server.serve_one(timeout=5)
        except Exception as e:  # pragma: no cover
            err["e"] = repr(e)

    t = threading.Thread(target=_serve)
    t.start()
    try:
        out = BrokerTransport(sock_path).request(
            effect_kind="db.query",
            effect_params=_db_effect_from_args(
                {"schema": "staging", "table": "analytics_events", "op": "select"}),
            task_id="task-001", agent_id="agent", request_nonce="n1")
        assert out.granted is False
        assert "same-uid-as-broker" in out.cause             # the only-door is void same-uid
    finally:
        t.join(timeout=5)
        server.stop()


# ===========================================================================================
# §6.6 — SCOPED-SHORT-TTL: a granted cap is a least-privilege role + ~now+60s exp, NOT the root key.
# ===========================================================================================
def test_scoped_short_ttl(tmp_path, monkeypatch):
    broker = _make_broker(tmp_path, monkeypatch, allow_same_uid=True)
    out = InProcessTransport(broker).request(
        effect_kind="db.query",
        effect_params=_db_effect_from_args(
            {"schema": "staging", "table": "analytics_events", "op": "select"}),
        task_id="task-001", agent_id="agent", request_nonce="n1")
    assert out.granted and out.extra["role"] == "signet_staging_ro"
    assert out.expires_at == (T0 + _dt.timedelta(seconds=60)).isoformat()
    claims = verify_jwt(out.capability, broker.minter.jwks(), now=T0)
    assert claims["role"] == "signet_staging_ro"            # least-privilege, never service_role
    assert "service_role" not in out.capability
    # exp is exactly 60s out (verifier-authoritative clock), and a forged cap fails JWKS verify.
    assert int(claims["exp"]) - int(claims["iat"]) == 60


# ===========================================================================================
# §6.7 — INVARIANT-INTERFACE: same middleware, Tier 0 vs Tier 1, identical ALLOW/BLOCK control flow.
# ===========================================================================================
def test_tier0_tier1_invariant_interface(tmp_path, monkeypatch):
    # Tier 0 — in-process broker (advisory).
    broker0 = _make_broker(tmp_path / "t0", monkeypatch, allow_same_uid=True, tag="t0")
    # Tier 1 — out-of-process broker over a real Unix socket (structural; same-uid allowed so the
    # single-process granted path is exercised).
    broker1 = _make_broker(tmp_path / "t1", monkeypatch, allow_same_uid=True, tag="t1")

    def run(transport):
        mw = _middleware(transport)
        results = {}
        for label, args in (("allow", {"schema": "staging", "table": "analytics_events",
                                       "op": "delete"}),
                            ("block", {"schema": "prod", "table": "users", "op": "select"})):
            h = _Handler()
            msg = mw.wrap_tool_call(_Req("db_write", args), h)
            results[label] = (h.ran, getattr(msg, "status", None) == "error")
        return results

    tier0 = run(InProcessTransport(broker0))

    sock_path = f"/tmp/sgntmw_inv_{os.getpid()}.sock"
    server = UnixSocketBrokerServer(broker1, sock_path)
    server.start()

    def serve_n(n):
        for _ in range(n):
            try:
                server.serve_one(timeout=5)
            except Exception:  # pragma: no cover
                break

    t = threading.Thread(target=serve_n, args=(2,))   # allow + block = two connections
    t.start()
    try:
        tier1 = run(BrokerTransport(sock_path))
    finally:
        t.join(timeout=5)
        server.stop()

    # Identical control flow: ALLOW ran the tool / was not an error; BLOCK did not run / was error.
    assert tier0 == tier1
    assert tier0["allow"] == (True, False) and tier0["block"] == (False, True)


# ===========================================================================================
# §6.8 — FAIL-CLOSED: malformed args / unsupported kind / unreachable -> BLOCK, never a pass.
# ===========================================================================================
def test_fail_closed(tmp_path, monkeypatch):
    broker = _make_broker(tmp_path, monkeypatch, allow_same_uid=True)
    mw = _middleware(InProcessTransport(broker))

    # (a) malformed args (missing op) -> refuse before the broker is even asked.
    h = _Handler()
    msg = mw.wrap_tool_call(_Req("db_write", {"schema": "staging", "table": "x"}), h)
    assert h.ran is False
    import json
    assert json.loads(msg.content)["cause"] == "malformed-or-missing-db-effect"

    # (b) unsupported effect kind at the transport -> blocked.
    out = InProcessTransport(broker).request(
        effect_kind="fs.write", effect_params={"path": "/etc/passwd"},
        task_id="task-001", agent_id="agent", request_nonce="n1")
    assert out.granted is False and out.cause.startswith("unsupported-effect-kind")
    bt_out = BrokerTransport("/tmp/none.sock").request(
        effect_kind="fs.write", effect_params={}, task_id="t", agent_id="a", request_nonce="n")
    assert bt_out.granted is False and bt_out.cause.startswith("unsupported-effect-kind")


# ===========================================================================================
# §6.9 — NO-ESCALATE-V0: a db tool decision is binary; the middleware never emits Command(resume=).
# ===========================================================================================
def test_no_escalate_for_db(tmp_path, monkeypatch):
    from langgraph.types import Command
    broker = _make_broker(tmp_path, monkeypatch, allow_same_uid=True)
    mw = _middleware(InProcessTransport(broker))
    for args in ({"schema": "staging", "table": "analytics_events", "op": "delete"},
                 {"schema": "prod", "table": "users", "op": "select"}):
        msg = mw.wrap_tool_call(_Req("db_write", args), _Handler())
        assert not isinstance(msg, Command)


# ===========================================================================================
# §6.10 — NO-DOWNSTREAM-EDITS: seam + broker trio + authorizer + kernel are byte-identical.
# ===========================================================================================
_DOWNSTREAM_HASHES = {
    "integrations/effect_gateway/seam.py": "653afde94c8de70ec77fb0567e9d54991a18c35b96e5db9a441499526e60d49c",
    "signet/broker/server.py": "9aa075491469ba39fc258aa1bbc26b0d076da6bfdc7a8a79248e1cca480f4fa2",
    "signet/broker/client.py": "fb945e5c8a3e6705bc45cea8a812efb7abe61dcd293b0f87e32a8c44f81dce12",
    "signet/broker/protocol.py": "83690ada5fffab90cdc025a6accbc8a7c51058a0d855b4ee06dd140eb4bed0e9",
    "signet/rails/supabase/authorizer.py": "7f786a60d3c1b53aab36ecfb5304cc28d13a712d7e97737b907ffe894e81946f",
    "signet/verifier.py": "1f7e6ca9cc9091173ed0bfbc849dc42ec6c4b5a828c7a86a6193ecd0ec4f50fc",
    "signet/chain.py": "6177270f7a226d2540cc324ee3207e7e54d5c77ded62f030f23c485b1f826302",
    "signet/models.py": "c0557145c0e3a34d268a7f37b2a4e122488a5ff3bafbffa0712ff7d2fbdd791b",
    "signet/policy.py": "72ee8c8a6387ba018681137dd578512f3c117ef5f588daa52d34b1f2d94ea4f1",
    "signet/nonce.py": "0fc7c37dda2e4e78479b5c01e390e35c5fa5be41649730c376c8100ab1837f27",
    "signet/revocation.py": "1dd3d3ba3b8336bceba2843dbc8630a2b040cd972ae2f377685c2d94e013197f",
    "signet/receipts.py": "f33ca2683494bc08e26c85aa0890e74b150ebb2cfecc9a08d7da18e0cf2d3435",
    "signet/builder.py": "b2afa09e3e70d8821c711782749a85eefc00c686595e41d44f1435a14e245a2d",
    "signet/crypto.py": "cb0ed752e0e2217c652ed9112f7eeafbac74359ba4b9e4873f6debf7e36992fc",
    "signet/canonical.py": "314e39bc8ae1a0ec78f75ba96493b7698fa520ebc82dc626ed8a9366eac2d02e",
}


def test_downstream_hashes_unchanged():
    for rel, want in _DOWNSTREAM_HASHES.items():
        got = hashlib.sha256((REPO_ROOT / rel).read_bytes()).hexdigest()
        assert got == want, f"{rel} changed (NO-DOWNSTREAM-EDITS): {got} != {want}"


# ===========================================================================================
# §6.11 — the one-line drop-in: create_agent(middleware=[SignetMiddleware(...)]) wires + runs.
# ===========================================================================================
def test_drop_in_create_agent(tmp_path, monkeypatch):
    """The one-line wiring `create_agent(middleware=[SignetMiddleware(...)])` builds AND, driven by
    a fake model that emits an off-mandate db tool call, the middleware contains it end-to-end —
    the tool never runs, a structured `signet:blocked` ToolMessage lands in the graph state. No LLM
    provider package or API key needed (a FakeMessagesListChatModel stands in for the model)."""
    pytest.importorskip("langchain")
    try:
        from langchain.agents import create_agent
        from langchain_core.tools import tool
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage as LcToolMessage
        from langchain_core.language_models.chat_models import BaseChatModel
        from langchain_core.outputs import ChatGeneration, ChatResult
    except Exception as e:  # pragma: no cover - version drift
        pytest.skip(f"langchain test surface unavailable: {e}")
    from integrations.langgraph.middleware import GuardedToolSpec, SignetMiddleware

    # A scripted model that supports bind_tools (create_agent binds the tools to it) and replays a
    # fixed list of AIMessages — turn 1 a tool call, turn 2 the wrap-up.
    class _ScriptedToolModel(BaseChatModel):
        responses: list
        i: int = 0

        @property
        def _llm_type(self) -> str:
            return "scripted-tool-model"

        def bind_tools(self, tools, **kwargs):
            return self           # tools are irrelevant to a scripted model

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            msg = self.responses[min(self.i, len(self.responses) - 1)]
            object.__setattr__(self, "i", self.i + 1)
            return ChatResult(generations=[ChatGeneration(message=msg)])

    ran = {"db": False}

    @tool
    def db_write(schema: str, table: str, op: str) -> str:
        """write to the db"""
        ran["db"] = True            # MUST stay False: the middleware blocks before the tool runs
        return "ok"

    broker = _make_broker(tmp_path, monkeypatch, allow_same_uid=True)
    spec = GuardedToolSpec(effect_from_args=_db_effect_from_args)
    mw = SignetMiddleware(transport=InProcessTransport(broker), task_id="task-001",
                          guarded_tools={"db_write": spec})

    # Turn 1: the model asks for an OFF-MANDATE write (prod.users). Turn 2: it wraps up.
    call = {"name": "db_write",
            "args": {"schema": "prod", "table": "users", "op": "select"},
            "id": "tc-1", "type": "tool_call"}
    model = _ScriptedToolModel(responses=[
        AIMessage(content="", tool_calls=[call]),
        AIMessage(content="done"),
    ])

    agent = create_agent(model, tools=[db_write], middleware=[mw])
    out = agent.invoke({"messages": [HumanMessage(content="delete prod users")]})

    # The guarded tool NEVER ran, and a structured signet refusal is in the transcript.
    assert ran["db"] is False
    import json
    blocked = [m for m in out["messages"]
               if isinstance(m, LcToolMessage) and '"signet": "blocked"' in (m.content or "")]
    assert blocked, "no signet-blocked ToolMessage in the agent transcript"
    assert json.loads(blocked[0].content)["cause"] == "out-of-mandate"
