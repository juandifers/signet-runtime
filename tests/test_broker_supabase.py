"""The broker-bypass battery — the acceptance gate for the first keyholder vertical slice.

Muscle-layer analogue of the 21 kernel attack tests (DESIGN.md "broker-bypass battery"). Each
case is contained-or-fail-loud. The scenario mirrors the worked example: a frozen task mandate
scopes the agent to `staging.analytics_events` (select|delete); an injection wants `prod.users`.

Offline + deterministic: real ES256 crypto, real role->GRANT scope logic, a fixed clock, and a
tmp SIGNET_HOME for the signed receipts. Nothing here calls a model or the network.

The keystone is test #9 (P8 honest-under-test): it asserts the bypass SUCCEEDS when a standing
elevated credential is left in the agent's environment — proving the broker is only ADVISORY
without an OS only-door. If that test ever flips to "blocked" without the OS layer, something
else is silently gating and must be explained (do not just delete the test).
"""
from __future__ import annotations

import datetime as _dt
import os
import socket
import threading

import pytest

from signet.broker.client import BrokerClient
from signet.broker.mandate import (DbGrant, MandateProvider, StandingPolicy,
                                    TaskMandate)
from signet.broker.protocol import CapabilityRequest
from signet.broker.server import Broker, UnixSocketBrokerServer, authenticate_peer
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.supabase.es256 import Es256Error, Es256Key, verify_jwt
from signet.rails.supabase.resource_sim import (PostgresDirect, Store,
                                                SupabaseGateway,
                                                SupabaseResourceError)
from signet.rails.supabase.roles import default_grants

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
AGENT_UID = os.getuid() + 1   # the agent is a DIFFERENT OS user than the broker (the only-door)


class Clock:
    """A mutable, injectable clock so the dwell/expiry tests advance time deterministically."""
    def __init__(self, now: _dt.datetime):
        self.now = now

    def __call__(self) -> _dt.datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now = self.now + _dt.timedelta(seconds=seconds)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A fully wired broker + a faithful resource, scoped to the worked example."""
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "signet_home"))
    clock = Clock(T0)

    mandates = MandateProvider()
    mandates.register(TaskMandate(
        task_id="task-001", database="app",
        grants=(DbGrant("staging", "analytics_events", ("select", "delete")),)))

    # Standing ceiling: staging is fully writable, prod is read-only at most. A task grant can
    # only narrow this — it can never authorize a prod write (monotonic).
    standing = StandingPolicy(grants=(
        DbGrant("staging", "*", ("select", "insert", "update", "delete")),
        DbGrant("prod", "*", ("select",)),
    ))

    minter = Es256Key.generate()
    receipts = LocalReceiptLog("broker:app")
    broker = Broker.create(mandates=mandates, standing=standing, receipts=receipts,
                           minter=minter, clock=clock, ttl_seconds=60)

    # The resource: restricted roles GRANT only on staging.*; NO role touches prod.*.
    store = Store(tables={
        ("staging", "analytics_events"): [{"id": 1, "evt": "click"}, {"id": 2, "evt": "view"}],
        ("prod", "users"): [{"id": 1, "email": "ceo@corp.com", "ssn": "***"}],
    })
    grants = default_grants(schemas_rw=["staging"], schemas_ro=["staging"])
    gateway = SupabaseGateway(jwks=minter.jwks(), grants=grants, store=store, clock=clock)

    return dict(broker=broker, gateway=gateway, store=store, minter=minter,
                receipts=receipts, clock=clock)


def _req(schema, table, op, *, task="task-001", nonce=""):
    return CapabilityRequest("db.query",
                             {"database": "app", "schema": schema, "table": table, "op": op},
                             task_id=task, agent_id="agent", request_nonce=nonce)


PUBLISHABLE = "sb_publishable_demo"   # the agent legitimately holds this (RLS-neutered)


# ===========================================================================================
# 1. HONEST PATH — request within mandate -> grant -> resource accepts -> receipt
# ===========================================================================================
def test_01_honest_path_grants_scoped_jwt_and_resource_accepts(env):
    r = env["broker"].handle_request(_req("staging", "analytics_events", "delete"), AGENT_UID)
    assert r.granted, r.cause
    assert r.capability and r.extra["role"] == "signet_staging_rw"

    claims = verify_jwt(r.capability, env["minter"].jwks(), now=T0)
    assert claims["role"] == "signet_staging_rw"
    assert claims["iss"] == "signet-broker"
    assert claims["sub"] == "task-001"

    out = env["gateway"].request(apikey=PUBLISHABLE, bearer_jwt=r.capability,
                                 schema="staging", table="analytics_events", op="delete", now=T0)
    assert out["deleted"] == 2 and out["via"] == "gateway"

    rec = next(x for x in env["receipts"].records() if x["id"] == r.receipt_id)
    assert rec["verdict"] == "pass" and rec["policy_hash"].startswith("tm_")


# ===========================================================================================
# 2. OUT-OF-MANDATE — prod.users is outside the frozen grant -> refused, ConsideredRejected
# ===========================================================================================
def test_02_out_of_mandate_is_refused_with_rejection_receipt(env):
    r = env["broker"].handle_request(_req("prod", "users", "select"), AGENT_UID)
    assert not r.granted
    assert r.capability is None
    assert r.cause == "out-of-mandate"
    rec = next(x for x in env["receipts"].records() if x["id"] == r.receipt_id)
    assert rec["verdict"] == "deny" and rec["effect"]["channel"] == "injection"


# ===========================================================================================
# 3. FORGE — the agent has no signing key; a self-fabricated JWT fails JWKS verification
# ===========================================================================================
def test_03_forged_jwt_is_rejected_by_the_resource(env):
    rogue = Es256Key.generate()   # NOT the broker's key
    forged = rogue.mint_jwt({"role": "signet_staging_rw", "sub": "task-001",
                             "iss": "signet-broker"}, now=T0, ttl_seconds=60)
    with pytest.raises(SupabaseResourceError, match="jwt rejected"):
        env["gateway"].request(apikey=PUBLISHABLE, bearer_jwt=forged,
                               schema="staging", table="analytics_events", op="delete", now=T0)


# ===========================================================================================
# 4. REPLAY — duplicating a consumed request collides on chain_hash -> consume-once refuses
# ===========================================================================================
def test_04_replay_is_refused_by_consume_once(env):
    first = env["broker"].handle_request(_req("staging", "analytics_events", "delete"), AGENT_UID)
    assert first.granted
    again = env["broker"].handle_request(_req("staging", "analytics_events", "delete"), AGENT_UID)
    assert not again.granted and again.cause == "replay"


# ===========================================================================================
# 5. EXPIRY — a granted JWT used after its TTL is rejected by the resource
# ===========================================================================================
def test_05_expired_capability_is_rejected(env):
    r = env["broker"].handle_request(_req("staging", "analytics_events", "select"), AGENT_UID)
    assert r.granted
    later = T0 + _dt.timedelta(seconds=61)   # ttl is 60s
    with pytest.raises(SupabaseResourceError, match="expired"):
        env["gateway"].request(apikey=PUBLISHABLE, bearer_jwt=r.capability,
                               schema="staging", table="analytics_events", op="select", now=later)


# ===========================================================================================
# 6. REPHRASE / SEARCH_PATH — a VALID staging JWT cannot reach prod.users: the role has no
#    GRANT on prod, so the DB rejects it regardless of how the query is phrased
# ===========================================================================================
def test_06_valid_staging_jwt_cannot_reach_prod_users(env):
    r = env["broker"].handle_request(_req("staging", "analytics_events", "select"), AGENT_UID)
    assert r.granted and r.extra["role"] == "signet_staging_ro"
    # The capability is perfectly valid; the scope is enforced at the DB by the credential.
    with pytest.raises(SupabaseResourceError, match="no GRANT on prod.users"):
        env["gateway"].request(apikey=PUBLISHABLE, bearer_jwt=r.capability,
                               schema="prod", table="users", op="select", now=T0)


# ===========================================================================================
# 7. GO-AROUND — a direct Postgres connection needs a DSN the agent does not have
# ===========================================================================================
def test_07_direct_connection_impossible_without_standing_credential(env):
    agent_env = {}   # zero-standing-elevated-creds: no DSN, no secret key
    with pytest.raises(ConnectionRefusedError, match="nothing to go around"):
        PostgresDirect.from_env(agent_env, env["store"])


# ===========================================================================================
# 8. PERSISTENCE / DWELL — an injection planted on turn 1 fires on turn N; the per-task
#    mandate + consume-once + TTL all still hold
# ===========================================================================================
def test_08_delayed_injection_is_contained(env):
    broker, clock = env["broker"], env["clock"]
    # turn 1: a legitimate grant, and a captured out-of-mandate request to fire later.
    legit = broker.handle_request(_req("staging", "analytics_events", "delete"), AGENT_UID)
    assert legit.granted
    planted = _req("prod", "users", "select")          # captured, not yet sent

    # (a) within the capability's life, replaying turn-1's request is refused (consume-once).
    clock.advance(30)                                  # still < 60s ttl
    replay = broker.handle_request(_req("staging", "analytics_events", "delete"), AGENT_UID)
    assert not replay.granted and replay.cause == "replay"

    clock.advance(3600)                                # ... turn N, long past the ttl ...

    # (b) the delayed out-of-mandate request is STILL refused by the frozen mandate — the
    #     property session-scoped gating never had to defend (unbounded dwell).
    fired = broker.handle_request(planted, AGENT_UID)
    assert not fired.granted and fired.cause == "out-of-mandate"
    # (c) the credential captured on turn 1 is useless on turn N: expired at the resource.
    with pytest.raises(SupabaseResourceError, match="expired"):
        env["gateway"].request(apikey=PUBLISHABLE, bearer_jwt=legit.capability,
                               schema="staging", table="analytics_events", op="delete",
                               now=clock())


# ===========================================================================================
# 9. NEGATIVE / P8 HONEST-UNDER-TEST — with a standing elevated credential in the agent's
#    environment, the bypass SUCCEEDS. This documents (in executable form) that the broker is
#    only ADVISORY without an OS only-door. If this ever fails (bypass blocked) WITHOUT the OS
#    layer, something else is silently gating and must be explained — do not delete this test.
# ===========================================================================================
def test_09_NEGATIVE_bypass_succeeds_when_standing_credential_present(env):
    leaked_env = {"DATABASE_URL": "postgres://service_role:secret@db.project.supabase.co:5432/postgres"}
    direct = PostgresDirect.from_env(leaked_env, env["store"])   # constructs BECAUSE a DSN exists
    out = direct.query("prod", "users", "select")               # BYPASSRLS — no broker involved
    # The bypass MUST succeed: this is the honest P8 limit, asserted, not hidden.
    assert out["op"] == "select"
    assert any(row["email"] == "ceo@corp.com" for row in out["rows"]), \
        "P8: with a standing elevated credential the agent reaches prod.users directly"
    assert out["via"].startswith("postgres-direct")


# ===========================================================================================
# Supporting invariants beyond the 9-case battery
# ===========================================================================================
def test_secret_key_blocked_in_apikey_header(env):
    r = env["broker"].handle_request(_req("staging", "analytics_events", "select"), AGENT_UID)
    with pytest.raises(SupabaseResourceError, match="secret/service_role key blocked"):
        env["gateway"].request(apikey="sb_secret_elevated", bearer_jwt=r.capability,
                               schema="staging", table="analytics_events", op="select", now=T0)


def test_monotonic_ceiling_a_grant_cannot_exceed_standing_policy(tmp_path, monkeypatch):
    """A task grant that tries to authorize a prod WRITE is refused by the standing ceiling
    (out-of-standing-policy), proving the per-task mandate can only narrow, never widen."""
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "h"))
    clock = Clock(T0)
    mandates = MandateProvider()
    mandates.register(TaskMandate(task_id="hostile", database="app",
                                  grants=(DbGrant("prod", "users", ("delete",)),)))
    standing = StandingPolicy(grants=(DbGrant("prod", "*", ("select",)),))  # prod is read-only
    broker = Broker.create(mandates=mandates, standing=standing,
                           receipts=LocalReceiptLog("broker:app2"), clock=clock)
    r = broker.handle_request(_req("prod", "users", "delete", task="hostile"), AGENT_UID)
    assert not r.granted and r.cause == "out-of-standing-policy"


def test_capability_independently_verifiable_without_broker(env):
    """Acceptance #4: a granted JWT verifies against the JWKS with no broker in the loop."""
    r = env["broker"].handle_request(_req("staging", "analytics_events", "select"), AGENT_UID)
    jwks = env["minter"].jwks()           # the public half; the broker process is irrelevant now
    claims = verify_jwt(r.capability, jwks, now=T0)
    assert claims["role"] == "signet_staging_ro"


def test_broker_receipt_chain_verifies(env):
    """Every decision (grant + refusal) appends a signed, hash-chained receipt."""
    env["broker"].handle_request(_req("staging", "analytics_events", "delete"), AGENT_UID)
    env["broker"].handle_request(_req("prod", "users", "select"), AGENT_UID)
    ok, msg, idx = env["receipts"].verify()
    assert ok, msg
    assert idx == -1 and "2 records" in msg


def test_authenticate_peer_refuses_same_uid():
    ok, why = authenticate_peer(os.getuid(), os.getuid(), allow_same_uid=False)
    assert not ok and "same-uid-as-broker" in why
    ok2, _ = authenticate_peer(os.getuid() + 1, os.getuid())
    assert ok2


# ===========================================================================================
# Acceptance #3 — the real Unix socket refuses a same-uid peer (SO_PEERCRED / fallback)
# ===========================================================================================
def test_unix_socket_refuses_same_uid_peer(env):
    # AF_UNIX paths are capped (~104 bytes on macOS); keep it short, not under tmp_path.
    sock_path = f"/tmp/sgntbrk_{os.getpid()}.sock"
    server = UnixSocketBrokerServer(env["broker"], sock_path)
    server.start()
    result = {}

    def _serve():
        try:
            server.serve_one(timeout=5)
        except Exception as e:        # pragma: no cover - surfaced via the assert below
            result["error"] = repr(e)

    t = threading.Thread(target=_serve)
    t.start()
    try:
        client = BrokerClient(sock_path)
        # Same process => peer uid == broker uid => refused (only-door void).
        resp = client.request_db(database="app", schema="staging",
                                 table="analytics_events", op="select", task_id="task-001")
        assert not resp.granted
        assert "same-uid-as-broker" in resp.cause
    finally:
        t.join(timeout=5)
        server.stop()


def test_unix_socket_refuses_to_start_when_agent_is_broker_uid(env):
    with pytest.raises(RuntimeError, match="REFUSING TO START"):
        UnixSocketBrokerServer(env["broker"], f"/tmp/sgntbrk_start_{os.getpid()}.sock",
                               expected_agent_uid=os.getuid())
