"""Acceptance for the egress `RailBinding` (EGRESS_BINDING.md §6). Each test = one property.

The seam's FIRST admission rail. House style mirrors tests/test_langgraph_adapter.py (build the
interceptor, run the decision path, assert outcome + a cause substring + a signed receipt), but
for ADMISSION rather than resolution. Offline + deterministic: a stub resolver, a fixed clock, an
in-memory ReceiptLog. The binding adds NO gate — every verdict here is the EXISTING egress
composition's verdict, reached through the seam (ADMISSION-PARITY).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from pathlib import Path

import pytest

from signet.receipts import ReceiptLog
from signet.broker.mandate import MandateProvider
from signet.rails.egress.chain_adapter import EgressBrokerCore
from signet.rails.egress.dest_sim import StubResolver
from signet.rails.egress.effect import EgressEffect
from signet.rails.egress.mandate import (EgressGrant, EgressMandate, EgressStandingPolicy,
                                         effective_admits)
from signet.rails.egress.resolver import Resolution

from integrations.effect_gateway.rails_egress import EgressBinding
from integrations.effect_gateway.seam import EffectInterceptor, Outcome, ProposedEffect

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[1]
SEAM_PATH = REPO_ROOT / "integrations" / "effect_gateway" / "seam.py"
# Pinned post-reshape — the seam is no longer byte-identical to 8761fe98 (SEAM-RESHAPE-INTENTIONAL:
# the first deliberate edit added shape ∈ {resolution, admission} + proposal_for). The seam invariant
# is now "pinned, changes only by a deliberate human-gated spec", not "frozen at 8761fe98".
SEAM_SHA256 = "653afde94c8de70ec77fb0567e9d54991a18c35b96e5db9a441499526e60d49c"


class Clock:
    def __init__(self, now): self.now = now

    def __call__(self): return self.now


def _resolver(allowed_port=8443, evil_port=9443):
    return StubResolver({
        "api.allowed.test": Resolution("127.0.0.1", allowed_port),
        "evil.test": Resolution("127.0.0.1", evil_port),
    }), allowed_port, evil_port


def _make(*, task_id="task-001", grants=(EgressGrant("api.allowed.test", (443,)),),
          expires_at=None, register_mandate=True, standing=None):
    """Assemble an egress interceptor over a fresh per-test core (fresh consume-once)."""
    clock = Clock(T0)
    core = EgressBrokerCore.create(clock=clock)
    receipts = ReceiptLog(core.enforcer_sk, core.enforcer_vk)
    resolver, allowed_port, evil_port = _resolver()
    standing = standing or EgressStandingPolicy((
        EgressGrant("api.allowed.test", (80, 443, 22)),
        EgressGrant("*.allowed.test", (443,)),
        EgressGrant("evil.test", (443,)),
    ))
    mandate = EgressMandate(task_id, tuple(grants), expires_at=expires_at)
    mandates = MandateProvider()
    if register_mandate:
        mandates.register(mandate)
    binding = EgressBinding(broker_core=core, mandate_provider=mandates,
                            standing_policy=standing, resolver=resolver, agent_id="agent")
    ic = EffectInterceptor(mandate, [binding], env=None, bridge=None, receipts=receipts, world=None)
    return dict(ic=ic, receipts=receipts, core=core, resolver=resolver, mandates=mandates,
                standing=standing, mandate=mandate, clock=clock,
                allowed_port=allowed_port, evil_port=evil_port)


def _fetch(host, port, **extra):
    return ProposedEffect("fetch_url", {"host": host, "port": port, **extra})


# ===========================================================================================
# 1. ALLOWED — in-mandate, in-standing destination is admitted
# ===========================================================================================
def test_egress_allowed_destination_admits():
    env = _make()
    d = env["ic"].intercept(_fetch("api.allowed.test", 443), proposer=None)
    assert d.outcome is Outcome.ALLOW
    assert d.escalation_source == "resolved"
    assert d.bound_target == "api.allowed.test:443"
    ok, _ = env["receipts"].verify(d.receipt)
    assert ok and d.receipt.decision == "approved" and d.receipt.payment_status == "admitted"


# ===========================================================================================
# 2. OFF-ALLOWLIST — a host outside the standing ceiling is contained
# ===========================================================================================
def test_egress_off_allowlist_blocked():
    # standing ceiling allows api.allowed.test:{80,443,22}; port 22 is in standing but NOT mandate,
    # so to hit out-of-STANDING we use a host absent from standing entirely.
    standing = EgressStandingPolicy((EgressGrant("api.allowed.test", (443,)),))
    env = _make(standing=standing,
                grants=(EgressGrant("api.allowed.test", (443,)),))
    d = env["ic"].intercept(_fetch("evil.test", 443), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "admission_denied"
    assert "out-of-standing-policy" in d.cause
    ok, _ = env["receipts"].verify(d.receipt)
    assert ok and d.receipt.decision == "blocked"


# ===========================================================================================
# 3. OFF-MANDATE — a host in STANDING but not in the FROZEN mandate is blocked (MONOTONIC)
# ===========================================================================================
def test_egress_off_mandate_blocked():
    env = _make()                                   # mandate = api.allowed.test:443 only
    d = env["ic"].intercept(_fetch("evil.test", 443), proposer=None)   # evil.test IS in standing
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "admission_denied"
    assert "out-of-mandate-destination" in d.cause   # the mandate narrows the standing ceiling


def test_egress_forbidden_port_on_allowed_host_blocked():
    env = _make()                                   # mandate grants 443 only; 22 is in standing
    d = env["ic"].intercept(_fetch("api.allowed.test", 22), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert "out-of-mandate-destination" in d.cause


# ===========================================================================================
# 4. FRESHNESS — MandateFreshness is reachable THROUGH the binding (expired / no-mandate)
# ===========================================================================================
def test_egress_expired_mandate_blocked():
    env = _make(expires_at="2026-06-11T11:00:00+00:00")   # expired at T0 (12:00)
    d = env["ic"].intercept(_fetch("api.allowed.test", 443), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "admission_denied"
    assert "mandate-expired" in d.cause


def test_egress_no_frozen_mandate_blocked():
    # The seam's frozen mandate names a task the provider does NOT carry -> MandateFreshness fails.
    env = _make(register_mandate=False)
    d = env["ic"].intercept(_fetch("api.allowed.test", 443), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert "no-frozen-mandate" in d.cause


# ===========================================================================================
# 5. RAW-IP EVASION — a raw IP that is not the trusted resolution of an allowlisted host
# ===========================================================================================
def test_egress_raw_ip_evasion_blocked():
    env = _make()
    # the agent dials evil's actual ip:port as a raw literal, dodging the hostname allowlist.
    d = env["ic"].intercept(_fetch("127.0.0.1", env["evil_port"]), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "admission_denied"
    assert "out-of-mandate-destination" in d.cause


# ===========================================================================================
# 6. TOCTOU — the runtime destination diverging from the signed Cart hits Bind.recheck
#    (the binding builds a self-consistent chain, so the divergence is injected against the
#    SAME composition the binding drives — proving the Bind gate is live in that path)
# ===========================================================================================
def test_egress_toctou_chain_mismatch_blocked():
    from signet.rails.egress.authorizer import EgressAuthorizer
    env = _make()
    core = env["core"]
    effect = EgressEffect("api.allowed.test", 443, "http_connect")
    decision, token, req, verifier = core.mint_token(effect, "task-001", "agent")
    assert token is not None

    # divergence: the runtime context points at a DIFFERENT destination than the signed Cart.
    bad_ctx = req.context.model_copy(update={"destination_account": '{"host": "evil.test", '
                                             '"port": 443, "protocol": "http_connect"}',
                                             "recipient": "evil.test:443"})
    bad_req = req.model_copy(update={"context": bad_ctx})

    authorizer = EgressAuthorizer(verifier, core.enforcer_vk, mandate_provider=env["mandates"],
                                  standing_policy=env["standing"], resolver=env["resolver"],
                                  clock=core.clock)
    auth = authorizer.authorize(token, bad_req)
    assert not auth.executed
    assert auth.reason in ("effect-context-mismatch", "unbound-token")


# ===========================================================================================
# 7. NO-ESCALATE-V0 — egress NEVER escalates; a forced resume fails closed
# ===========================================================================================
def test_egress_never_escalates():
    env = _make()
    outcomes = [
        env["ic"].intercept(_fetch("api.allowed.test", 443), proposer=None).outcome,   # allow
        env["ic"].intercept(_fetch("evil.test", 443), proposer=None).outcome,          # block
        env["ic"].intercept(_fetch("127.0.0.1", env["evil_port"]), proposer=None).outcome,
        env["ic"].intercept(ProposedEffect("fetch_url", {}), proposer=None).outcome,   # malformed
    ]
    assert Outcome.ESCALATE not in outcomes

    # a forced resume (no resume() on the binding) fails closed to BLOCK in the seam.
    d = env["ic"].intercept(_fetch("api.allowed.test", 443), proposer=None)
    resumed = env["ic"].resume(_fetch("api.allowed.test", 443), d, {"approved": True},
                               frozen_world=None)
    assert resumed.outcome is Outcome.BLOCK


# ===========================================================================================
# 8. FAIL-CLOSED — a missing / malformed destination is contained, never a default-allow
# ===========================================================================================
@pytest.mark.parametrize("args", [
    {},                                             # no destination
    {"host": "api.allowed.test"},                   # no port
    {"host": "api.allowed.test", "port": "not-a-port"},
    {"url": "::::"},                                # unparseable url
    {"protocol": "bogus", "host": "api.allowed.test", "port": 443},   # bad protocol
])
def test_egress_malformed_destination_blocked(args):
    env = _make()
    d = env["ic"].intercept(ProposedEffect("fetch_url", args), proposer=None)
    assert d.outcome is Outcome.BLOCK and d.outcome is not Outcome.ALLOW
    assert d.escalation_source == "gate_contained"


def test_egress_url_form_admits():
    env = _make()
    d = env["ic"].intercept(ProposedEffect("fetch_url", {"url": "https://api.allowed.test/x"}),
                            proposer=None)
    assert d.outcome is Outcome.ALLOW                # https -> 443, in mandate
    assert d.bound_target == "api.allowed.test:443"


def test_egress_unhandled_tool_blocked():
    env = _make()
    d = env["ic"].intercept(ProposedEffect("merge_pr", {"pr": 7}), proposer=None)
    assert d.outcome is Outcome.BLOCK
    assert d.escalation_source == "no_binding"       # the seam, not the binding


# ===========================================================================================
# 9. SEAM pinned (post-reshape) + K0 — the seam moves only by a deliberate human-gated spec
# ===========================================================================================
def test_egress_seam_pinned():
    actual = hashlib.sha256(SEAM_PATH.read_bytes()).hexdigest()
    assert actual == SEAM_SHA256, "seam.py changed unexpectedly — pinned post-reshape sha violated"


def test_kernel_baseline_unchanged():
    from evals.scorecard.architecture import kernel_edit_check
    assert kernel_edit_check()["edits"] == 0


# ===========================================================================================
# 10. ADMISSION-PARITY — the binding's verdict EQUALS the existing composition's verdict
# ===========================================================================================
def test_egress_binding_parity():
    """Over a destination corpus, the binding admits a destination IFF `effective_admits`
    (the existing mandate ∩ standing decision) admits it. The binding adds no gate."""
    env = _make()
    mandate, standing = env["mandate"], env["standing"]
    corpus = [
        ("api.allowed.test", 443),     # in mandate ∩ standing
        ("evil.test", 443),            # in standing, off mandate
        ("api.allowed.test", 22),      # in standing, off mandate (port)
        ("notlisted.test", 443),       # off standing entirely
        ("sub.allowed.test", 443),     # wildcard standing, off mandate
    ]
    for host, port in corpus:
        d = env["ic"].intercept(_fetch(host, port), proposer=None)
        expected_ok, _ = effective_admits(EgressEffect(host, port, "http_connect"),
                                          mandate, standing)
        got_ok = d.outcome is Outcome.ALLOW
        assert got_ok == expected_ok, (
            f"parity mismatch for {host}:{port}: binding={got_ok} effective_admits={expected_ok}")


# ===========================================================================================
# 11. A1-CONTAINMENT — an attacker-named host in the proposal is admitted ONLY if it passes
# ===========================================================================================
def test_egress_a1_attacker_host_contained():
    env = _make()
    # an injection names an exfil host; it is in standing but off the frozen mandate -> contained.
    d = env["ic"].intercept(_fetch("evil.test", 443), proposer="evil.test")   # raw proposer ignored
    assert d.outcome is Outcome.BLOCK
    # and the legit destination still passes — the proposal is data, not a verdict.
    legit = env["ic"].intercept(_fetch("api.allowed.test", 443), proposer="evil.test")
    assert legit.outcome is Outcome.ALLOW


# ===========================================================================================
# 12. through the LangGraph guarded tool — the adapter is rail-agnostic (ALLOW/BLOCK flow)
# ===========================================================================================
def test_egress_through_langgraph_guarded_tool():
    pytest.importorskip("langgraph")
    from integrations.langgraph.guarded_tool import signet_guarded_tool
    env = _make()
    tool = signet_guarded_tool(env["ic"], tool_name="fetch_url", id_arg="host",
                               world_getter=lambda: None)

    blocked = tool(host="evil.test", port=443)
    assert blocked.outcome == Outcome.BLOCK.value and blocked.status == "blocked"

    allowed = tool(host="api.allowed.test", port=443)
    assert allowed.outcome == Outcome.ALLOW.value and allowed.status == "merged"


# ===========================================================================================
# Structural — the binding satisfies the seam Protocol as-is, ships no resume (NO-ESCALATE-V0)
# ===========================================================================================
def test_egress_binding_satisfies_protocol():
    from integrations.effect_gateway.seam import RailBinding
    env = _make()
    binding = env["ic"].bindings[0]
    assert isinstance(binding, RailBinding)
    assert not hasattr(binding, "resume")            # NO resume path in v0
