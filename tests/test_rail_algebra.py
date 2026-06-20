"""Acceptance tests for the rail-algebra refactor (SPEC §6). The tests are the spec.

  1. merge composition reproduces the §0.3 golden corpus verdict-for-verdict.
  2. egress composition reproduces the golden, including the raw-IP cases.
  3. PROVENANCE-MONOTONICITY holds for the shipped policies; the audit FLAGS an allow-on-untrusted.
  4. the payment composition stub instantiates.
  5. the register_rail conformance battery still passes for the refactored rails.
  6. the implementation report exists.

`tests/` is not a package; pytest prepends it to sys.path, so `_golden` imports resolve.
"""
from __future__ import annotations

import json
from pathlib import Path

from _golden.corpus import egress_verdicts, merge_verdicts

_REPO = Path(__file__).resolve().parents[1]
_GOLDEN = json.loads((_REPO / "tests" / "_golden" / "rail_verdicts.json").read_text())


# ============================================================================
# 1 + 2 — BEHAVIOR-PRESERVED: the refactored rails reproduce the golden corpus
# ============================================================================
def test_merge_composition_matches_golden():
    assert merge_verdicts() == _GOLDEN["merge"]


def test_egress_composition_matches_golden():
    now = egress_verdicts()
    assert now == _GOLDEN["egress"]
    # make the raw-IP coverage explicit: the trusted-resolution match admits, the evasion is refused.
    by_label = {c["label"]: c for c in now}
    assert by_label["raw_ip_matching_allowed"]["admitted"] is True
    assert by_label["raw_ip_evasion"]["admitted"] is False
    assert by_label["raw_ip_evasion"]["cause"] == "out-of-mandate-destination"


# ============================================================================
# 3 — PROVENANCE-MONOTONICITY
# ============================================================================
def _merge_policy():
    from evals.conformance.rails import github_plugin
    from evals.github_railbridge.domain import github_membership_policy
    plugin = github_plugin()
    return github_membership_policy(plugin._effective(plugin.build_world()))


def _egress_policy():
    from signet.broker.mandate import MandateProvider
    from signet.rails.egress.authorizer import EgressAuthorizer
    from signet.rails.egress.dest_sim import StubResolver
    from signet.rails.egress.mandate import EgressStandingPolicy
    # provenance_audit only drives the policy's allow_witness/decide/neutralize — no verifier needed.
    auth = EgressAuthorizer(None, "vk", mandate_provider=MandateProvider(),
                            standing_policy=EgressStandingPolicy(()), resolver=StubResolver({}))
    return auth.composition.policy


def test_provenance_monotonicity_holds():
    from signet.rail_algebra import provenance_audit
    assert provenance_audit(_merge_policy()) == [], "merge DeclarativeMembership leaks untrusted->allow"
    assert provenance_audit(_egress_policy()) == [], "egress PatternAllowlist leaks untrusted->allow"


def test_provenance_monotonicity_catches_violation():
    from signet.rail_algebra import AllowOnUntrustedContent, provenance_audit
    violations = provenance_audit(AllowOnUntrustedContent())
    assert violations, "the audit must FLAG a policy that allows on an untrusted match"
    assert "UNTRUSTED" in violations[0] and "ALLOW" in violations[0]


# ============================================================================
# 4 — payment composition stub
# ============================================================================
def test_payment_stub_instantiates():
    from signet.rail_algebra import payment_composition
    comp = payment_composition()
    d = comp.describe()
    assert d["policy"] == "payment_cap"
    assert d["bind"] == "MeteredLedger" and d["bind_lifecycle"] == "metered"
    assert d["door"] == "KeyholderBroker" and d["door_soundness"] == "custody"


# ============================================================================
# 5 — CONFORMANCE-GREEN for the refactored rails
# ============================================================================
def test_conformance_still_passes():
    # merge: the real register_rail conformance battery over the refactored github plugin.
    from evals.conformance.rails import github_plugin
    from evals.conformance.register import register_rail
    certified = register_rail(github_plugin())
    assert certified.report.all_pass, certified.report.failures

    # egress: it is NOT a Role-B register_rail plugin (its PDP is inline admission, not set-valued
    # resolution — reported as residue in IMPLEMENTATION.md §4.2). Its conformance is the unchanged
    # authorizer-template contract: EgressAuthorizer fills ONLY the two hooks, never overriding the
    # order-owning template, and its Policy is provenance-monotone.
    from signet.authorizers.base import Authorizer
    from signet.rails.egress.authorizer import EgressAuthorizer
    assert issubclass(EgressAuthorizer, Authorizer)
    assert EgressAuthorizer.authorize is Authorizer.authorize           # order + fail-closed unchanged
    assert "recheck_against_context" in EgressAuthorizer.__dict__
    assert "produce_capability" in EgressAuthorizer.__dict__


# ============================================================================
# 6 — the implementation report is present
# ============================================================================
def test_implementation_report_exists():
    assert (_REPO / "signet" / "rail_algebra" / "IMPLEMENTATION.md").is_file()
