"""Egress-into-LangGraph acceptance: one agent, two rails, one session (spec §7).

The combined refund-triage run proposes BOTH a DB write (capability-issuing door -> ALLOW) and a
network egress (effect-performing PROXY door -> BLOCK) under one frozen task, across the one
unchanged EffectInterceptor. These tests pin:

  * the combined session carries the DB ALLOW and the egress BLOCK as two effects on two rails,
  * the egress proxy admits an allowlisted host and refuses an off-allowlist host,
  * the egress binding fails closed when the proxy is down,
  * the egress effect is labeled `advisory`, never `structural`,
  * the two door archetypes are NOT collapsed — egress mints NO bearer capability,
  * DB verdicts are unchanged.

Offline + deterministic: real localhost upstreams + a trusted stub resolver + the real proxy, a
tmp SIGNET_HOME for the proxy's signed receipts. No real network.
"""
from __future__ import annotations

import datetime as _dt

import pytest

pytest.importorskip("langgraph")  # the demo graph; the broader suite runs without the demo extra

from examples.refund_triage import egress as eg
from examples.refund_triage.session import build_combined_session
from integrations.effect_gateway.seam import Outcome

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)


@pytest.fixture(autouse=True)
def _tmp_home(tmp_path, monkeypatch):
    # Keep the proxy's signed LocalReceiptLog out of the real ~/.signet home.
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "h"))


@pytest.fixture
def door():
    d = eg.build_combined_door(clock=lambda: T0)
    try:
        yield d
    finally:
        d.stop()


# ===========================================================================================
# 1. The headline: one run, one mandate -> DB ALLOW + egress BLOCK, two rails, one session
# ===========================================================================================
def test_combined_session_db_allow_and_egress_block():
    s = build_combined_session(clock=lambda: T0)
    assert s["session_id"] == "refund-triage-combined"
    assert len(s["effects"]) == 2

    db, egress = s["effects"]
    assert db["rail"] == "supabase" and db["decision"] == "ALLOW"
    assert db["performed"] == {"rows": 1, "executed": True}      # DB verdict unchanged
    assert db["token_minted"] is True                            # capability-issuing archetype

    assert egress["rail"] == "egress" and egress["decision"] == "BLOCK"
    assert egress["performed"]["egress"] == "blocked"
    assert egress["proposed"]["target"] == f"{eg.ATTACKER_HOST}:{eg.EGRESS_PORT}"
    # the mandate spans both rails
    rails = {g["rail"] for g in s["mandate"]["granted_scope"]}
    assert rails == {"supabase", "egress"}


# ===========================================================================================
# 2. The egress proxy admits an allowlisted host, refuses an off-allowlist host
# ===========================================================================================
def test_egress_allowlisted_host_allows(door):
    res = door.egress_tool()(host=eg.ALLOWED_HOST, port=eg.EGRESS_PORT)
    assert res.outcome == Outcome.ALLOW.value, res.cause
    assert res.bound_target == f"{eg.ALLOWED_HOST}:{eg.EGRESS_PORT}"


def test_egress_offallowlist_host_blocks(door):
    res = door.egress_tool()(host=eg.ATTACKER_HOST, port=eg.EGRESS_PORT)
    assert res.outcome == Outcome.BLOCK.value
    assert "403" in res.cause or "refused" in res.cause


# ===========================================================================================
# 3. Fail closed when the proxy is down (the RemoteSupabaseBinding posture for a dead broker)
# ===========================================================================================
def test_egress_binding_fails_closed_when_proxy_down(door):
    door.egress_env.proxy.stop()                       # the proxy is gone
    res = door.egress_tool()(host=eg.ALLOWED_HOST, port=eg.EGRESS_PORT)
    assert res.outcome == Outcome.BLOCK.value          # never a silent egress
    assert "proxy-unreachable" in res.cause
    assert res.check_ref is None                        # nothing was minted/performed


# ===========================================================================================
# 4. Honest label: the egress effect is advisory, never structural (spec §5)
# ===========================================================================================
def test_egress_effect_labeled_advisory():
    s = build_combined_session(clock=lambda: T0)
    egress = s["effects"][1]
    assert s["tier"] == "0 (advisory)" and s["tier_structural"] is False
    assert egress["note"].startswith("advisory")
    assert "structural" not in egress["note"].lower().split("(", 1)[0]   # not claimed as structural
    assert "test_broker_egress.py #8" in egress["note"]                  # bypass honestly cited


# ===========================================================================================
# 5. ARCHETYPE NOT COLLAPSED: egress mints NO bearer capability (the agent holds nothing)
# ===========================================================================================
def test_egress_mints_no_bearer_token(door):
    allow = door.egress_tool()(host=eg.ALLOWED_HOST, port=eg.EGRESS_PORT)
    assert allow.outcome == Outcome.ALLOW.value
    assert allow.check_ref is None                      # no JWT / capability handed to the agent

    s = build_combined_session(clock=lambda: T0)
    assert s["effects"][1]["token_minted"] is False     # egress never mints; DB does


# ===========================================================================================
# 6. Receipts: both effects carry a verifiable signed receipt
# ===========================================================================================
def test_combined_effects_have_verifiable_receipts():
    s = build_combined_session(clock=lambda: T0)
    for e in s["effects"]:
        assert e["receipt_id"]
        assert e["receipt_verified"] is True


# ===========================================================================================
# 7. The seam routes by rail: the SAME interceptor handles both tools
# ===========================================================================================
def test_one_interceptor_two_bindings(door):
    names = [b.name for b in door.interceptor.bindings]
    assert "supabase" in names and "egress" in names
    # malformed egress destination fails closed (no host/url)
    res = door.egress_tool()(host=None)
    assert res.outcome == Outcome.BLOCK.value
    assert "malformed or missing" in res.cause
