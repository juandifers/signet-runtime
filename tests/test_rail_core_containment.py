"""The containment boundary is now STRUCTURAL, not convention — these tests are rail-INDEPENDENT
(no GitHub, no deploy) and prove the inherited guarantees:

  PART 1 (the gate): order + fail-closed live in `_rail_core.role_b`. A candidate failing the
  allow-list never reaches the fence; each stage's failure yields the right ESC_GATE cause; a
  predicate that RAISES escalates instead of crashing through.

  PART 2 (the authorizer template): `base.Authorizer.authorize` runs verify_token THEN
  recheck_against_context BEFORE produce_capability. A deliberately-broken Authorizer whose
  produce_capability would mint UNCONDITIONALLY still cannot execute on an invalid token or a
  failed re-check — the template blocks it. A rail that "forgets" the hooks cannot even be
  instantiated (closes inventory GAP #6).
"""
import pytest

from signet.authorizers.base import AuthorizationResult, Authorizer
from evals._rail_core.role_b import (ESC_GATE, ESC_RESOLVED, run_gate, run_role_b_stages)
from evals._rail_core.resolver import FixedChoiceResolver


class _C:
    """A minimal rail-neutral candidate exposing `.id` (the shared resolver keys on it)."""
    def __init__(self, i):
        self.id = i


# ============================================================================
# PART 1 — the gate: order + fail-closed (rail-independent)
# ============================================================================
def test_gate_checks_owned_first():
    cause = run_gate(99, {1, 2}, lambda c: True, lambda c: True)
    assert cause is not None and "not-owned" in cause


def test_gate_allowlist_before_fence_and_short_circuits():
    calls = []

    def wa(c):
        calls.append(("allow", c))
        return False                                   # fail the allow-list ceiling

    def wf(c):
        calls.append(("fence", c))                     # MUST NOT be reached
        return True

    cause = run_gate(5, {5}, wa, wf)
    assert "off-allowlist" in cause
    assert calls == [("allow", 5)]                     # fence never evaluated (order + short-circuit)


def test_gate_fence_runs_after_allowlist_passes():
    cause = run_gate(5, {5}, lambda c: True, lambda c: False)
    assert "off-fence" in cause


def test_gate_passes_when_all_three_hold():
    assert run_gate(5, {5}, lambda c: True, lambda c: True) is None


def test_gate_fail_closed_when_fence_predicate_raises():
    def boom(c):
        raise RuntimeError("predicate exploded")
    cause = run_gate(5, {5}, lambda c: True, boom)
    assert "off-fence" in cause and "raised" in cause  # treated as failure, NOT a crash-through


def test_gate_fail_closed_when_allowlist_predicate_raises():
    def boom(c):
        raise RuntimeError("predicate exploded")
    cause = run_gate(5, {5}, boom, lambda c: True)
    assert "off-allowlist" in cause and "raised" in cause


# ---- the gate is wired as Stage 3 of the orchestrator: no "resolve" without it passing ----
def test_orchestrator_resolve_requires_the_gate_to_pass():
    stages = run_role_b_stages("crit", [_C(1)], {1}, resolver=FixedChoiceResolver(1),
                               within_allowlist=lambda c: True, within_fence=lambda c: True)
    assert stages.status == "resolve" and stages.chosen_id == 1
    assert stages.escalation_source == ESC_RESOLVED


def test_orchestrator_gate_rejection_is_gate_contained():
    stages = run_role_b_stages("crit", [_C(1)], {1}, resolver=FixedChoiceResolver(1),
                               within_allowlist=lambda c: True, within_fence=lambda c: False)
    assert stages.status == "escalate"
    assert stages.escalation_source == ESC_GATE        # telemetry unchanged
    assert stages.surviving_ids == (1,) and "off-fence" in stages.cause


def test_orchestrator_gate_predicate_raise_escalates_not_crash():
    def boom(c):
        raise RuntimeError("boom")
    stages = run_role_b_stages("crit", [_C(1)], {1}, resolver=FixedChoiceResolver(1),
                               within_allowlist=lambda c: True, within_fence=boom)
    assert stages.status == "escalate" and stages.escalation_source == ESC_GATE


# ============================================================================
# PART 2 — the authorizer template: a broken rail CANNOT bypass
# ============================================================================
class _Verifier:
    def __init__(self, ok):
        self._ok = ok

    def verify_token(self, token, vk):
        return self._ok


class _BrokenAuthorizer(Authorizer):
    """A future rail written carelessly: produce_capability mints UNCONDITIONALLY. The template
    must still block it whenever a guard fails."""
    rail = "broken"

    def __init__(self, verifier, recheck_ok):
        super().__init__(verifier, "enforcer-vk")
        self._recheck_ok = recheck_ok
        self.minted = False
        self.rejected = False

    def recheck_against_context(self, token, req):
        return (self._recheck_ok, "ok" if self._recheck_ok else "context mismatch")

    def produce_capability(self, token, req):
        self.minted = True                              # would ALWAYS mint if reached
        return AuthorizationResult(True, "MINTED UNCONDITIONALLY", rail=self.rail)

    def on_rejected(self, token, req, reason):
        self.rejected = True


def test_invalid_token_blocks_before_capability():
    a = _BrokenAuthorizer(_Verifier(False), recheck_ok=True)
    res = a.authorize(token=object(), req=object())
    assert not res.executed
    assert not a.minted                                 # produce_capability NEVER reached
    assert "token" in res.reason.lower()


def test_context_mismatch_blocks_before_capability_and_records():
    a = _BrokenAuthorizer(_Verifier(True), recheck_ok=False)
    res = a.authorize(token=object(), req=object())
    assert not res.executed
    assert not a.minted                                 # blocked despite the unconditional minter
    assert a.rejected                                   # on_rejected DID run (rail-native record)
    assert "mismatch" in res.reason.lower()


def test_both_guards_pass_reaches_capability():
    a = _BrokenAuthorizer(_Verifier(True), recheck_ok=True)
    res = a.authorize(token=object(), req=object())
    assert res.executed and a.minted                    # the template DOES reach produce when valid


def test_a_rail_that_forgets_the_hooks_cannot_be_instantiated():
    # Closes GAP #6 at the type level: the hooks are abstract; a rail missing them is abstract too.
    class _Forgetful(Authorizer):
        rail = "forgetful"
    with pytest.raises(TypeError):
        _Forgetful(_Verifier(True), "vk")
