"""Acceptance for the Supabase db-write `RailBinding` (SUPABASE_BINDING.md §6). Each test = one
property. The seam's SECOND admission rail — the DECIDING vote on `SEAM-SHAPE-OVERFIT`, and the rail
on which the effect-key/credential-broker door is genuinely load-bearing (mint separated from use).

House style mirrors tests/test_egress_binding.py (build the interceptor, run the decision path,
assert outcome + a cause substring + a signed receipt), for a CREDENTIAL-BROKER admission rail.
Offline + deterministic: real ES256 crypto, a fixed clock, an in-memory ReceiptLog. The binding adds
NO gate — every verdict here is the EXISTING Supabase composition's verdict, reached through the seam
(ADMISSION-PARITY).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from pathlib import Path

import pytest

from signet.receipts import ReceiptLog
from signet.broker.mandate import (DbGrant, MandateProvider, StandingPolicy, TaskMandate,
                                    effective_permits)
from signet.rails.supabase.chain_adapter import DbBrokerCore
from signet.rails.supabase.effect import DbEffect
from signet.rails.supabase.es256 import Es256Key, verify_jwt
from signet.rails.supabase.resource_sim import Store, SupabaseGateway, SupabaseResourceError
from signet.rails.supabase.roles import default_grants

from integrations.effect_gateway.rails_supabase import SupabaseBinding
from integrations.effect_gateway.seam import EffectInterceptor, Outcome, ProposedEffect

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[1]
SEAM_PATH = REPO_ROOT / "integrations" / "effect_gateway" / "seam.py"
# Pinned post-reshape — the seam is no longer byte-identical to 8761fe98 (SEAM-RESHAPE-INTENTIONAL:
# the first deliberate edit added shape ∈ {resolution, admission} + proposal_for). The seam invariant
# is now "pinned, changes only by a deliberate human-gated spec", not "frozen at 8761fe98".
SEAM_SHA256 = "653afde94c8de70ec77fb0567e9d54991a18c35b96e5db9a441499526e60d49c"

PUBLISHABLE = "sb_publishable_demo"   # the agent legitimately holds this (RLS-neutered)


class Clock:
    def __init__(self, now): self.now = now

    def __call__(self): return self.now


def _make(*, task_id="task-001",
          grants=(DbGrant("staging", "analytics_events", ("select", "insert")),),
          expires_at=None, register_mandate=True, standing=None):
    """Assemble a Supabase interceptor over a fresh per-test core (fresh consume-once) + a faithful
    resource (restricted roles GRANT only on staging.*; NO role touches prod.*)."""
    clock = Clock(T0)
    core = DbBrokerCore.create(clock=clock)
    receipts = ReceiptLog(core.enforcer_sk, core.enforcer_vk)
    minter = Es256Key.generate()
    standing = standing or StandingPolicy(grants=(
        DbGrant("staging", "*", ("select", "insert", "update", "delete")),
        DbGrant("prod", "*", ("select",)),
    ))
    mandate = TaskMandate(task_id=task_id, database="app", grants=tuple(grants),
                          expires_at=expires_at)
    mandates = MandateProvider()
    if register_mandate:
        mandates.register(mandate)
    binding = SupabaseBinding(broker_core=core, mandate_provider=mandates,
                              standing_policy=standing, minter=minter, ttl_seconds=60,
                              agent_id="agent")
    ic = EffectInterceptor(mandate, [binding], env=None, bridge=None, receipts=receipts, world=None)

    # The resource: restricted roles GRANT only on staging.*; NO role touches prod.*.
    store = Store(tables={
        ("staging", "analytics_events"): [{"id": 1, "evt": "click"}, {"id": 2, "evt": "view"}],
        ("prod", "users"): [{"id": 1, "email": "ceo@corp.com"}],
    })
    grants_map = default_grants(schemas_rw=["staging"], schemas_ro=["staging"])
    gateway = SupabaseGateway(jwks=minter.jwks(), grants=grants_map, store=store, clock=clock)

    return dict(ic=ic, receipts=receipts, core=core, minter=minter, mandates=mandates,
                standing=standing, mandate=mandate, clock=clock, gateway=gateway, store=store)


def _db(schema, table, op, *, tool="db_write", database="app", **extra):
    return ProposedEffect(tool, {"database": database, "schema": schema, "table": table,
                                 "op": op, **extra})


# ===========================================================================================
# 1. PERMITTED WRITE — in-mandate (schema.table, op) admits, a scoped JWT is issued
# ===========================================================================================
def test_db_permitted_write_admits():
    env = _make()
    d = env["ic"].intercept(_db("staging", "analytics_events", "insert"), proposer=None)
    assert d.outcome is Outcome.ALLOW
    assert d.escalation_source == "resolved"
    assert d.bound_target == "staging.analytics_events.insert"
    assert d.check_ref, "ALLOW must carry the issued JWT as the capability ref"
    # the capability is a real, independently verifiable ES256 JWT scoped to a restricted role.
    claims = verify_jwt(d.check_ref, env["minter"].jwks(), now=T0)
    assert claims["role"] == "signet_staging_rw" and claims["iss"] == "signet-broker"
    ok, _ = env["receipts"].verify(d.receipt)
    assert ok and d.receipt.decision == "approved" and d.receipt.payment_status == "capability_issued"


# ===========================================================================================
# 2. OFF-TABLE / OFF-OP — a table or op outside the frozen fence is contained
# ===========================================================================================
def test_db_off_table_blocked():
    env = _make()                                   # mandate = staging.analytics_events only
    d = env["ic"].intercept(_db("staging", "secrets", "insert"), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "admission_denied"
    assert "out-of-mandate" in d.cause
    ok, _ = env["receipts"].verify(d.receipt)
    assert ok and d.receipt.decision == "blocked"


def test_db_off_op_blocked():
    env = _make()                                   # mandate grants select|insert; delete is not granted
    d = env["ic"].intercept(_db("staging", "analytics_events", "delete"), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert "out-of-mandate" in d.cause


# ===========================================================================================
# 3. OFF-MANDATE (MONOTONIC) — an op in STANDING but absent from the FROZEN mandate is blocked
# ===========================================================================================
def test_db_off_mandate_blocked():
    # standing allows staging.* {select,insert,update,delete}; the frozen mandate grants only
    # select|insert on analytics_events. `update` is in standing but NOT the mandate -> contained.
    env = _make()
    d = env["ic"].intercept(_db("staging", "analytics_events", "update"), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "admission_denied"
    assert "out-of-mandate" in d.cause             # the mandate narrows the standing ceiling


def test_db_off_standing_blocked():
    # prod is read-only in the standing ceiling; a prod WRITE is refused at the ceiling (monotonic
    # violation reported as out-of-standing-policy, the cause order in effective_permits).
    env = _make()
    d = env["ic"].intercept(_db("prod", "users", "insert"), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert "out-of-standing-policy" in d.cause


# ===========================================================================================
# 4. FRESHNESS — MandateFreshness is reachable THROUGH the binding (expired / no-mandate)
# ===========================================================================================
def test_db_expired_mandate_blocked():
    env = _make(expires_at="2026-06-11T11:00:00+00:00")   # expired at T0 (12:00)
    d = env["ic"].intercept(_db("staging", "analytics_events", "insert"), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "admission_denied"
    assert "mandate-expired" in d.cause


def test_db_no_frozen_mandate_blocked():
    # the seam's frozen mandate names a task the provider does NOT carry -> recheck fails closed.
    env = _make(register_mandate=False)
    d = env["ic"].intercept(_db("staging", "analytics_events", "insert"), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert "no-frozen-mandate" in d.cause


# ===========================================================================================
# 5. BIND recheck steps 1/2 — unbound-token / effect-context-mismatch. The binding builds a
#    self-consistent chain (cart == context from the same eff.args), so these are injected directly
#    against the SAME SupabaseAuthorizer composition the binding drives (mirrors the egress TOCTOU
#    test) — proving the Bind gate is LIVE in that path even though it isn't expressible from args.
# ===========================================================================================
def _authorizer(env, verifier):
    from signet.rails.supabase.authorizer import SupabaseAuthorizer
    core = env["core"]
    return SupabaseAuthorizer(verifier, core.enforcer_vk, mandate_provider=env["mandates"],
                              standing_policy=env["standing"], minter=env["minter"],
                              ttl_seconds=60, clock=core.clock)


def test_db_unbound_token_blocked():
    env = _make()
    core = env["core"]
    eff_a = DbEffect("app", "staging", "analytics_events", "select")
    _, token_a, _, verifier_a = core.mint_token(eff_a, "task-001", "agent")
    assert token_a is not None
    # a DIFFERENT operation's request, authorized with effect-A's token -> chain_hash mismatch.
    req_b = core.build_request(DbEffect("app", "staging", "analytics_events", "insert"),
                               "task-001", "agent")
    auth = _authorizer(env, verifier_a).authorize(token_a, req_b)
    assert not auth.executed and auth.reason == "unbound-token"


def test_db_effect_context_mismatch_blocked():
    env = _make()
    core = env["core"]
    eff = DbEffect("app", "staging", "analytics_events", "insert")
    _, token, req, verifier = core.mint_token(eff, "task-001", "agent")
    assert token is not None
    # divergence: the runtime context points at a DIFFERENT effect than the signed Cart (chain_hash
    # still matches — it is computed over intent/cart/payment, not context).
    bad_ctx = req.context.model_copy(update={"destination_account": '{"tampered": true}',
                                             "recipient": "staging.secrets"})
    bad_req = req.model_copy(update={"context": bad_ctx})
    auth = _authorizer(env, verifier).authorize(token, bad_req)
    assert not auth.executed and auth.reason == "effect-context-mismatch"


# ===========================================================================================
# 6. NO-ESCALATE-V0 — supabase NEVER escalates; a forced resume fails closed
# ===========================================================================================
def test_db_never_escalates():
    env = _make()
    outcomes = [
        env["ic"].intercept(_db("staging", "analytics_events", "insert"), proposer=None).outcome,
        env["ic"].intercept(_db("staging", "analytics_events", "delete"), proposer=None).outcome,
        env["ic"].intercept(_db("prod", "users", "insert"), proposer=None).outcome,
        env["ic"].intercept(ProposedEffect("db_write", {}), proposer=None).outcome,   # malformed
    ]
    assert Outcome.ESCALATE not in outcomes

    # a forced resume (no resume() on the binding) fails closed to BLOCK in the seam.
    d = env["ic"].intercept(_db("staging", "analytics_events", "insert"), proposer=None)
    resumed = env["ic"].resume(_db("staging", "analytics_events", "insert"), d, {"approved": True},
                               frozen_world=None)
    assert resumed.outcome is Outcome.BLOCK


# ===========================================================================================
# 7. FAIL-CLOSED — a missing / malformed / out-of-band operation is contained, never default-allow
# ===========================================================================================
@pytest.mark.parametrize("args", [
    {},                                                         # no operation
    {"database": "app", "schema": "staging", "table": "x"},     # no op
    {"database": "app", "schema": "staging", "op": "insert"},   # no table
    {"schema": "staging", "table": "x", "op": "insert"},        # no database
    {"database": "app", "schema": "staging", "table": "x", "op": "drop_table"},   # oob op
    {"database": "app", "schema": "staging", "table": "x", "op": "INSERT"},       # wrong case -> oob
])
def test_db_fail_closed_on_malformed_args(args):
    env = _make()
    d = env["ic"].intercept(ProposedEffect("db_write", args), proposer=None)
    assert d.outcome is Outcome.BLOCK and d.outcome is not Outcome.ALLOW
    assert d.escalation_source == "gate_contained"


# ===========================================================================================
# 8. EFFECT-KEY-REACHABLE (the residue-2 closer, through the REAL door) — a JWT minted for one
#    operation is SCOPED at the resource by the effect-determined role; a substituted op/target it
#    does not cover is REJECTED at the resource PEP, with NO broker in the loop.
#
#    HONEST FRAMING (NO-FAKE): the resource binds at ROLE granularity (role -> GRANT), NOT at the
#    finer `signet_effect_hash`. So op-class escalation (ro select -> delete) and cross-schema
#    (staging -> prod) ARE rejected; but a SAME-role-class substitution (rw insert -> rw delete on
#    the same table) is NOT caught at the resource — the effect_hash is bound at MINT (Bind /
#    consume-once) but advisory at the resource PEP in v0. This is the third face, SUPABASE_BINDING.md
#    §4/§8 and SEAM-EFFECT-PHASE. Both halves are asserted here, neither hidden.
# ===========================================================================================
def test_db_effect_key_reachable():
    env = _make(grants=(DbGrant("staging", "analytics_events", ("select",)),))   # a READ task
    d = env["ic"].intercept(_db("staging", "analytics_events", "select"), proposer=None)
    assert d.outcome is Outcome.ALLOW
    jwt = d.check_ref
    claims = verify_jwt(jwt, env["minter"].jwks(), now=T0)
    assert claims["role"] == "signet_staging_ro"     # the effect (op=select) chose a read-only role

    gw = env["gateway"]
    # honest use within the credential's scope succeeds.
    out = gw.request(apikey=PUBLISHABLE, bearer_jwt=jwt, schema="staging",
                     table="analytics_events", op="select", now=T0)
    assert out["via"] == "gateway"
    # (a) op-class escalation: the read JWT cannot delete — REJECTED at the resource.
    with pytest.raises(SupabaseResourceError, match="no GRANT"):
        gw.request(apikey=PUBLISHABLE, bearer_jwt=jwt, schema="staging",
                   table="analytics_events", op="delete", now=T0)
    # (b) cross-schema: the staging JWT cannot reach prod — REJECTED at the resource.
    with pytest.raises(SupabaseResourceError, match="no GRANT on prod.users"):
        gw.request(apikey=PUBLISHABLE, bearer_jwt=jwt, schema="prod", table="users",
                   op="select", now=T0)


def test_db_effect_hash_advisory_at_resource_v0():
    """The honest gap (NO-FAKE): a JWT minted for (analytics_events, insert) carries a per-effect
    `signet_effect_hash`, but the resource enforces only ROLE scope. So the SAME rw role can drive a
    DIFFERENT rw op (delete) on the same table — the effect_hash is advisory at the resource PEP in
    v0 (SEAM-EFFECT-PHASE). Recorded as an executable finding, not patched to green."""
    env = _make(grants=(DbGrant("staging", "analytics_events", ("insert",)),))   # a WRITE task
    d = env["ic"].intercept(_db("staging", "analytics_events", "insert"), proposer=None)
    assert d.outcome is Outcome.ALLOW
    jwt = d.check_ref
    claims = verify_jwt(jwt, env["minter"].jwks(), now=T0)
    assert claims["role"] == "signet_staging_rw"
    # the effect_hash IS bound into the JWT...
    insert_eff = DbEffect("app", "staging", "analytics_events", "insert")
    assert claims["signet_effect_hash"] == insert_eff.effect_hash()
    # ...but the resource accepts a DIFFERENT op the rw role also covers: effect_hash NOT enforced here.
    out = env["gateway"].request(apikey=PUBLISHABLE, bearer_jwt=jwt, schema="staging",
                                 table="analytics_events", op="delete", now=T0)
    assert out["op"] == "delete" and out["via"] == "gateway", \
        "v0: the resource binds at role granularity; the finer effect_hash is advisory at the PEP"


# ===========================================================================================
# 9. through the LangGraph guarded tool — the adapter is rail-agnostic across a THIRD rail
# ===========================================================================================
def test_db_through_langgraph_guarded_tool():
    pytest.importorskip("langgraph")
    from integrations.langgraph.guarded_tool import signet_guarded_tool
    env = _make()
    tool = signet_guarded_tool(env["ic"], tool_name="db_write", id_arg="table",
                               world_getter=lambda: None)

    blocked = tool(database="app", schema="prod", table="users", op="insert")
    assert blocked.outcome == Outcome.BLOCK.value and blocked.status == "blocked"

    allowed = tool(database="app", schema="staging", table="analytics_events", op="insert")
    assert allowed.outcome == Outcome.ALLOW.value and allowed.status == "merged"


# ===========================================================================================
# 10. SEAM pinned (post-reshape) + K0 — the seam moves only by a deliberate human-gated spec
# ===========================================================================================
def test_db_seam_pinned():
    actual = hashlib.sha256(SEAM_PATH.read_bytes()).hexdigest()
    assert actual == SEAM_SHA256, "seam.py changed unexpectedly — pinned post-reshape sha violated"


def test_db_kernel_baseline_unchanged():
    from evals.scorecard.architecture import kernel_edit_check
    assert kernel_edit_check()["edits"] == 0


# ===========================================================================================
# 11. ADMISSION-PARITY — the binding's verdict EQUALS the existing pipeline's verdict (the oracle
#     is effective_permits, mandate ∩ standing) over an operation corpus. The binding adds no gate.
# ===========================================================================================
def test_db_binding_parity():
    env = _make()
    mandate, standing = env["mandate"], env["standing"]
    corpus = [
        ("staging", "analytics_events", "select"),   # in mandate ∩ standing
        ("staging", "analytics_events", "insert"),   # in mandate ∩ standing
        ("staging", "analytics_events", "delete"),   # in standing, off mandate (op)
        ("staging", "analytics_events", "update"),   # in standing, off mandate (op)
        ("staging", "secrets", "insert"),            # in standing (staging.*), off mandate (table)
        ("prod", "users", "select"),                 # in standing (prod ro), off mandate
        ("prod", "users", "insert"),                 # off standing entirely (prod is ro)
    ]
    for schema, table, op in corpus:
        d = env["ic"].intercept(_db(schema, table, op), proposer=None)
        expected_ok, _ = effective_permits(DbEffect("app", schema, table, op), mandate, standing)
        got_ok = d.outcome is Outcome.ALLOW
        assert got_ok == expected_ok, (
            f"parity mismatch for {schema}.{table}.{op}: "
            f"binding={got_ok} effective_permits={expected_ok}")


# ===========================================================================================
# 12. A1-CONTAINMENT — an attacker-named table/op in the proposal is admitted ONLY if it passes
# ===========================================================================================
def test_db_a1_attacker_operation_contained():
    env = _make()
    # an injection names a prod write; it is off the standing ceiling -> contained. The raw proposer
    # (an attacker-chosen id) never decides — the proposal is data.
    d = env["ic"].intercept(_db("prod", "users", "insert"), proposer="prod.users")
    assert d.outcome is Outcome.BLOCK
    # and the legit operation still passes.
    legit = env["ic"].intercept(_db("staging", "analytics_events", "insert"), proposer="prod.users")
    assert legit.outcome is Outcome.ALLOW


# ===========================================================================================
# Structural — the binding satisfies the seam Protocol as-is, ships no resume (NO-ESCALATE-V0)
# ===========================================================================================
def test_db_binding_satisfies_protocol():
    from integrations.effect_gateway.seam import RailBinding
    env = _make()
    binding = env["ic"].bindings[0]
    assert isinstance(binding, RailBinding)
    assert not hasattr(binding, "resume")            # NO resume path in v0
