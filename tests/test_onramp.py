"""On-ramp acceptance (spec §8): `guard(tool, mandate)` + `Mandate` + `SignetConfig`.

The on-ramp is a FACADE over the existing seam — it adds no enforcement and changes no behavior. The
keystone is faithfulness: the refund demo re-expressed through `guard()` produces a session IDENTICAL
to the hand-wired one (same verdicts, receipts, rows, advisory labels). The rest pins the DX
contract: the builder emits a valid granted_scope and round-trips JSON, `guard()` returns a drop-in
tool, the default is advisory and config makes it structural, the three teaching errors name their
fix, and an unreachable door fails closed.

Layering: builder/error/round-trip tests need only the signet core and run in the suite. Tests that
wire a door need the supabase rail crypto (`jwt`); the faithfulness tests run the demo graph
(`langgraph`). Each guards its own dependency with importorskip, so the file degrades cleanly.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

import pytest

from signet import Mandate, SignetConfig, guard
from examples.onramp import (MalformedTargetError, MissingRailExtraError, SignetOnRampError,
                             UnknownRailError, build_onramp_door, guarded_door)
from examples.onramp.errors import require

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
CLEAN = Path("examples/refund_triage/scenarios/mandate.clean.json")


@pytest.fixture(autouse=True)
def _tmp_home(tmp_path, monkeypatch):
    # Keep the egress proxy's signed LocalReceiptLog out of the real ~/.signet home.
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "h"))


def _normalize(session: dict) -> dict:
    """Drop the two fields the kernel stamps non-deterministically — `generated_at` (wall-clock) and
    each receipt's `receipt_id` (the kernel ReceiptLog stamps datetime.now() + a uuid into every
    receipt, signet/receipts.py:31,40, so the hash is never reproducible run-to-run). Everything else
    — verdicts, rows, scope, token_minted, performed, notes, labels — IS deterministic and must match.
    Each receipt's PRESENCE and verifiability is asserted here, so 'same receipts' still holds."""
    s = dict(session)
    s.pop("generated_at", None)
    effects = []
    for e in s["effects"]:
        e = dict(e)
        assert e.pop("receipt_id"), "every effect must carry a receipt"
        assert e["receipt_verified"] is True, "every effect's receipt must verify"
        effects.append(e)
    s["effects"] = effects
    return s


# ===========================================================================================
# 1. THE KEYSTONE: the refund demo re-expressed via guard() is byte-identical to hand-wired
# ===========================================================================================
def test_onramp_reproduces_handwired_refund_session():
    pytest.importorskip("langgraph")
    from examples.refund_triage import agent
    from examples.refund_triage.egress import ALLOWED_HOST
    from examples.refund_triage.session import build_combined_session

    # --- combined two-rail session: hand-wired vs on-ramp-assembled door -------------------
    hand = build_combined_session(clock=lambda: T0)

    mandate = Mandate.from_json(CLEAN).allow_egress(ALLOWED_HOST).build()
    door = build_onramp_door(mandate, SignetConfig(), clock=lambda: T0)   # guard()'s door, explicitly
    try:
        onramp = build_combined_session(clock=lambda: T0, door=door)
    finally:
        door.stop()
    assert _normalize(onramp) == _normalize(hand)          # IDENTICAL (modulo non-deterministic stamps)

    # --- single-rail clean/a1/a2/a3: per-case verdict + receipt parity ---------------------
    cases = [("clean", None, "deterministic"), ("injected", "a1", "adversarial"),
             ("injected", "a2", "adversarial"), ("injected", "a3", "adversarial")]
    for scenario, attack, resolver in cases:
        hw = agent.run_scenario(scenario=scenario, attack=attack, resolver=resolver,
                                clock=lambda: T0)
        od = build_onramp_door(Mandate.from_json(CLEAN), SignetConfig(), clock=lambda: T0)
        ov = agent.run_scenario(scenario=scenario, attack=attack, resolver=resolver,
                                clock=lambda: T0, door=od)
        # verdict / token / rows are deterministic and must match; receipt_id is kernel-stamped
        # non-deterministically (datetime.now()+uuid), so assert it is present, not equal.
        assert (ov.outcome, ov.token_minted, ov.rows_written) == \
               (hw.outcome, hw.token_minted, hw.rows_written), \
               f"{scenario}/{attack} diverged: on-ramp {ov.outcome} vs hand-wired {hw.outcome}"
        assert ov.receipt_id and hw.receipt_id


def test_onramp_db_door_matches_handwired_build_door():
    """The on-ramp's DB door is the demo's build_door verbatim (same binding, same frozen mandate)."""
    pytest.importorskip("jwt")
    from examples.refund_triage import agent
    hw = agent.build_door(agent.load_mandate(), clock=lambda: T0)
    od = build_onramp_door(Mandate.from_json(CLEAN), SignetConfig(), clock=lambda: T0)
    assert [type(b).__name__ for b in od.interceptor.bindings] == \
           [type(b).__name__ for b in hw.interceptor.bindings] == ["SupabaseBinding"]
    assert od.mandate.signing_payload() == hw.mandate.signing_payload()


# ===========================================================================================
# 2. The Mandate builder: valid granted_scope across rails + JSON round-trip
# ===========================================================================================
def test_mandate_builder_emits_valid_granted_scope_db_and_egress():
    m = (Mandate("support-bot", task_id="refund-001")
         .allow_db("public.credits", ops=("select", "insert"))
         .allow_egress("payments.internal")
         .build())
    assert m.rails() == {"supabase", "egress"}
    assert m.granted_scope() == [
        {"rail": "supabase", "action": "select", "target": "public.credits"},
        {"rail": "supabase", "action": "insert", "target": "public.credits"},
        {"rail": "egress", "action": "connect", "target": "payments.internal:443"},
    ]
    # the DB projection is exactly a TaskMandate the broker can verify
    tm = m.to_taskmandate()
    assert tm.task_id == "refund-001" and tm.database == "app"


def test_mandate_roundtrips_json():
    original = json.loads(CLEAN.read_text())
    m = Mandate.from_json(CLEAN)
    assert m.to_json() == original                       # byte-equal fields against the scenario file

    # and a round-trip through a dict reconstructs the same artifact
    m2 = Mandate.from_json(m.to_json())
    assert m2.to_json() == original


def test_mandate_builder_has_no_row_value_helper():
    """Spec §0.3: the API must not over-promise. The DB door binds (schema, table, op) — there is no
    amount/predicate value-binding helper, because no door backs it."""
    m = Mandate("support-bot").allow_db("public.credits")
    assert not hasattr(m, "max_amount")
    assert not any("amount" in n or "value" in n for n in dir(m) if not n.startswith("_"))


# ===========================================================================================
# 3. guard() returns a drop-in LangGraph tool
# ===========================================================================================
def test_guard_returns_dropin_langgraph_tool():
    pytest.importorskip("jwt")
    m = Mandate.from_json(CLEAN)
    g = guard(lambda **k: None, m, clock=lambda: T0)         # single rail -> rail inferred
    assert callable(g) and hasattr(g, "tool_name")
    # same kwargs interface as the underlying tool; returns a structured GuardedResult
    res = g(database="app", schema="public", table="credits", op="insert",
            order_id="ORD-1042", amount=50.0, currency="EUR")
    assert res.outcome == "allow" and bool(res.check_ref) is True    # capability-issuing DB rail
    # (DB-only Door is in-process — nothing to tear down)


def test_guard_shares_one_session_across_two_tools():
    pytest.importorskip("jwt")
    m = Mandate.from_json(CLEAN).allow_egress("payments.internal").build()
    guard(lambda **k: None, m, rail="supabase", clock=lambda: T0)
    guard(lambda **k: None, m, rail="egress", clock=lambda: T0)
    door = guarded_door(m, clock=lambda: T0)               # the SAME cached door both calls used
    try:
        assert [b.name for b in door.interceptor.bindings] == ["supabase", "egress"]
    finally:
        door.stop()


# ===========================================================================================
# 4. Default advisory / config structural — both labeled (spec §0.4)
# ===========================================================================================
def test_guard_default_is_advisory():
    assert SignetConfig().structural is False
    assert SignetConfig().label() == "0 (advisory)"
    pytest.importorskip("langgraph")
    from examples.refund_triage.egress import ALLOWED_HOST
    from examples.refund_triage.session import build_combined_session
    m = Mandate.from_json(CLEAN).allow_egress(ALLOWED_HOST).build()
    door = build_onramp_door(m, SignetConfig(), clock=lambda: T0)
    try:
        s = build_combined_session(clock=lambda: T0, door=door)
    finally:
        door.stop()
    assert s["tier"] == "0 (advisory)" and s["tier_structural"] is False


def test_guard_config_marks_structural():
    cfg = SignetConfig(tier=1, broker_socket="/tmp/x.sock", jwks_path="/tmp/x.jwks")
    assert cfg.structural is True
    assert cfg.label().startswith("1 (structural")


# ===========================================================================================
# 5. Teaching errors — each names the fix (spec §0.5 / §8)
# ===========================================================================================
def test_error_missing_rail_extra():
    with pytest.raises(MissingRailExtraError) as ei:
        require("a_module_that_is_not_installed_xyz", rail="supabase", extra="supabase")
    msg = str(ei.value)
    assert "pip install" in msg and "[supabase]" in msg     # names the fix, not a traceback


def test_error_malformed_target():
    with pytest.raises(MalformedTargetError) as db_err:
        Mandate("support-bot").allow_db("credits")          # no schema.table
    assert "schema.table" in str(db_err.value)

    with pytest.raises(MalformedTargetError) as eg_err:
        Mandate("support-bot").allow_egress("https://payments.internal/x")   # carries a scheme
    assert "bare hostname" in str(eg_err.value)


def test_error_unknown_rail():
    m = Mandate.from_json(CLEAN)
    with pytest.raises(UnknownRailError) as ei:
        guard(lambda **k: None, m, rail="ipfs")
    msg = str(ei.value)
    assert "ipfs" in msg and "supabase" in msg              # lists the rails it does wire


def test_error_guarding_rail_not_in_mandate():
    m = Mandate.from_json(CLEAN)                             # DB only, no egress
    with pytest.raises(SignetOnRampError) as ei:
        guard(lambda **k: None, m, rail="egress")
    assert "allow_egress" in str(ei.value)                  # tells you how to add it


# ===========================================================================================
# 6. Fail-closed: an unreachable door BLOCKs, never a silent pass (spec §0.6)
# ===========================================================================================
def test_guard_fails_closed_when_doors_unreachable():
    pytest.importorskip("jwt")
    m = Mandate.from_json(CLEAN).allow_egress("payments.internal").build()
    cfg = SignetConfig(proxy="127.0.0.1:1")                 # a caller-run proxy that is not there
    g = guard(lambda **k: None, m, rail="egress", signet=cfg, clock=lambda: T0)
    res = g(host="payments.internal", port=443)
    assert res.outcome == "block"                           # never a silent egress
    assert "proxy-unreachable" in res.cause
    assert res.check_ref is None                            # nothing minted/performed
    guarded_door(m, cfg, clock=lambda: T0).stop()           # external-proxy door: no auto env to tear down
