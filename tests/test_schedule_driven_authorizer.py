"""Acceptance tests for the schedule-driven authorizer promotion (PROMOTION.md / SPEC v2 §6).

The promotion makes `base.Authorizer` drive a COMPOSED rail's terminal phase (merge: AUTHORIZE;
egress: ADMIT) via its declared Schedule (run_phase) instead of two hardcoded hooks, while every
LEGACY rail stays on the unchanged hooks. The tests are the spec:

  1. test_merge_authorize_driven_by_schedule   — merge AUTHORIZE invokes Bind -> Door in schedule order.
  2. test_egress_admit_driven_by_schedule      — egress ADMIT invokes Bind -> MandateFreshness ->
                                                  Policy -> Door in schedule order.
  3. test_merge_policy_not_rerun_at_authorize  — PHASE-ISOLATION: merge Policy fires at RESOLVE, never
                                                  at AUTHORIZE.
  4. test_legacy_rail_unchanged                — a non-composed rail takes the legacy hook path.
  5. test_run_phase_fails_closed               — mismatch / unknown phase / raising component / missing
                                                  Door / gate-deny all BLOCK (never an implicit allow).
  6. test_promotion_report_exists              — signet/rail_algebra/PROMOTION.md present with §4.7.
  7. test_egress_mandate_freshness_not_dropped — COMPONENT-COMPLETENESS: under the DRIVEN egress path
                                                  the two lifecycle guards still BLOCK and the
                                                  last_mandate_hash side effect survives.

The faithfulness instrumentation (observe/mark/phase_scope) is a no-op outside an observe() block, so
the same end-to-end paths are byte-identical in production.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from signet.authorizers.base import (AuthorizationResult, Authorizer, ComponentOutcome,
                                     ScheduledComponent)
from signet.rail_algebra import (EGRESS_SCHEDULE, MERGE_SCHEDULE, Phase, Schedule, Step, observe,
                                 observed_schedule)
from signet.rail_algebra.schedule import BIND, DOOR, POLICY
from signet.rails.egress.authorizer import EgressAuthorizer
from signet.rails.egress.effect import EgressEffect

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "tests"))                    # _golden is not a package


# ============================================================================
# fixtures — full, PASSING end-to-end runs that exercise the DRIVEN path
# ============================================================================
def _run_merge_observed():
    """A full Role-B merge job that RESOLVES + AUTHORIZES an in-scope owned PR (the Role-B path that
    routes through the rail-algebra composition). Returns (job, observed marks)."""
    from evals.github_railbridge.merge_chain import make_github_env
    from evals.github_railbridge.policy import InMemoryPolicySource
    from evals.github_railbridge.domain import CONFIGURED_REPO, GitHubWorld, PullRequest
    from evals.github_railbridge.mandate import OpenMandate, run_open_mandate
    from evals.github_railbridge.resolver import FixedChoiceResolver
    from signet.authorizers.github_railbridge import GitHubRailBridge, MockGitHubRail
    from signet.receipts import ReceiptLog

    env = make_github_env()
    bridge = GitHubRailBridge(env.verifier, env.enforcer_vk, github_rail=MockGitHubRail())
    receipts = ReceiptLog(env.enforcer_sk, env.enforcer_vk)
    pr = PullRequest(CONFIGURED_REPO, 2, "main", "sha02aaaaaa", ("src/app/payments.py",),
                     title="Fix double-charge in checkout", branch="fix/issue-7", closes_issue=7)
    world = GitHubWorld(open_prs={2: pr})
    om = OpenMandate(criterion="merge the PR that fixes issue #7", scope_allow=("src/**",), cap=1)
    with observe() as rec:
        job = run_open_mandate(env, InMemoryPolicySource(), bridge, receipts, world,
                               repo_id=CONFIGURED_REPO, open_mandate=om,
                               resolver=FixedChoiceResolver(2))
    return job, rec


def _drive_egress(broker, host="api.allowed.test", port=443):
    """Replicate EgressBroker.admit's mint -> authorize so the test holds the EgressAuthorizer
    instance (to read its last_mandate_hash side effect) while still going through the DRIVEN
    authorize() -> run_phase path. Returns (AuthorizationResult, authorizer)."""
    res = broker.resolver.resolve(host)
    eff = EgressEffect(host, port, "http_connect", resolved_ip=res.ip)
    decision, token, req, verifier = broker.core.mint_token(eff, broker.task_id, broker.agent_id, "")
    assert decision.approved and token is not None, "kernel mint must succeed (independent of mandate)"
    authz = EgressAuthorizer(verifier, broker.core.enforcer_vk, mandate_provider=broker.mandates,
                             standing_policy=broker.standing, resolver=broker.resolver,
                             clock=broker.clock)
    return authz.authorize(token, req), authz


class _OkVerifier:
    def verify_token(self, token, vk):
        return True


# ============================================================================
# 1 — merge AUTHORIZE is driven Bind -> Door via the schedule
# ============================================================================
def test_merge_authorize_driven_by_schedule():
    job, rec = _run_merge_observed()
    assert job.outcome is not None and job.outcome.approved, "fixture must reach Bind+Door (AUTHORIZE)"
    authorize_steps = [s.component for s in rec if s.phase is Phase.AUTHORIZE]
    assert authorize_steps == [BIND, DOOR], authorize_steps
    # the driven steps are exactly MERGE_SCHEDULE's AUTHORIZE steps, in order.
    assert [s.component for s in MERGE_SCHEDULE.steps_for(Phase.AUTHORIZE)] == [BIND, DOOR]


# ============================================================================
# 2 — egress ADMIT is driven Bind -> MandateFreshness -> Policy -> Door via the schedule
# ============================================================================
def test_egress_admit_driven_by_schedule():
    from _golden.corpus import _egress_broker
    with observe() as rec:
        adm = _egress_broker().admit("api.allowed.test", 443)
    assert adm.admitted, adm.cause
    assert [s.component for s in rec] == [BIND, BIND, POLICY, DOOR], [s.component for s in rec]
    assert all(s.phase is Phase.ADMIT for s in rec)
    assert EGRESS_SCHEDULE.matches(observed_schedule(rec)), EGRESS_SCHEDULE.steps
    # the second BIND step is MandateFreshness — a first-class marked component now in the schedule.
    assert [s.component for s in EGRESS_SCHEDULE.steps_for(Phase.ADMIT)] == [BIND, BIND, POLICY, DOOR]


# ============================================================================
# 3 — PHASE-ISOLATION: merge Policy fires at RESOLVE, never at AUTHORIZE
# ============================================================================
def test_merge_policy_not_rerun_at_authorize():
    _, rec = _run_merge_observed()
    policy_at_authorize = [s for s in rec
                           if s.component.startswith("policy") and s.phase is Phase.AUTHORIZE]
    assert policy_at_authorize == [], policy_at_authorize
    # sanity: the Policy DID fire — at RESOLVE (so we are not trivially asserting "never ran").
    policy_at_resolve = [s for s in rec
                         if s.component.startswith("policy") and s.phase is Phase.RESOLVE]
    assert policy_at_resolve, "merge Policy must fire at RESOLVE"


# ============================================================================
# 4 — NON-COMPOSED-UNCHANGED: a legacy rail takes the legacy hook path
# ============================================================================
def test_legacy_rail_unchanged():
    class _Recorder(Authorizer):
        rail = "legacy-fake"

        def __init__(self):
            super().__init__(verifier=_OkVerifier(), enforcer_vk="vk")
            self.calls = []

        def recheck_against_context(self, token, req):
            self.calls.append("recheck")
            return True, "ok"

        def produce_capability(self, token, req):
            self.calls.append("produce")
            return AuthorizationResult(True, "minted", rail=self.rail)

    a = _Recorder()
    assert a.composition is None                              # not composed -> legacy branch
    res = a.authorize(object(), object())
    assert res.executed and a.calls == ["recheck", "produce"], a.calls

    # spot-check REAL legacy rails carry no composition (so they never reach run_phase).
    from signet.authorizers.deploy_railbridge import DeployRailBridge
    from signet.authorizers.infra_railbridge import InfraRailBridge
    assert getattr(DeployRailBridge, "composition", None) is None
    assert getattr(InfraRailBridge, "composition", None) is None


# ============================================================================
# 5 — FAIL-CLOSED: run_phase never produces an implicit allow
# ============================================================================
def _fake_composed(components, schedule):
    class _FC(Authorizer):
        rail = "fc"

        def __init__(self):
            super().__init__(verifier=_OkVerifier(), enforcer_vk="vk")
            self.composition = SimpleNamespace(schedule=schedule)
            self._comps = components

        def _components_for(self, phase, token, req):
            return self._comps

        def recheck_against_context(self, token, req):
            return True, ""

        def produce_capability(self, token, req):
            return AuthorizationResult(True, "", rail=self.rail)

    return _FC()


def _door_ok():
    return AuthorizationResult(True, "door-ok", rail="fc")


def _boom():
    raise RuntimeError("boom")


def test_run_phase_fails_closed():
    admit2 = Schedule((Step(BIND, Phase.ADMIT), Step(DOOR, Phase.ADMIT)))

    # (a) unknown / empty-but-required phase: no steps scheduled there -> BLOCK.
    a = _fake_composed([ScheduledComponent(BIND, lambda: ComponentOutcome(True)),
                        ScheduledComponent(DOOR, _door_ok, is_door=True)], admit2)
    r = a.run_phase(Phase.RESOLVE, a.composition, object(), object())
    assert not r.executed and "mismatch" in r.reason

    # (b) a raising gate component -> BLOCK (never crash-through).
    a = _fake_composed([ScheduledComponent(BIND, _boom),
                        ScheduledComponent(DOOR, _door_ok, is_door=True)], admit2)
    r = a.run_phase(Phase.ADMIT, a.composition, object(), object())
    assert not r.executed and "raised" in r.reason

    # (c) a gate that DENIES -> BLOCK with its cause, Door never reached.
    a = _fake_composed([ScheduledComponent(BIND, lambda: ComponentOutcome(False, "nope")),
                        ScheduledComponent(DOOR, _door_ok, is_door=True)], admit2)
    r = a.run_phase(Phase.ADMIT, a.composition, object(), object())
    assert not r.executed and r.reason == "nope"

    # (d) schedule with no terminal Door -> BLOCK.
    bind_only = Schedule((Step(BIND, Phase.ADMIT),))
    a = _fake_composed([ScheduledComponent(BIND, lambda: ComponentOutcome(True))], bind_only)
    r = a.run_phase(Phase.ADMIT, a.composition, object(), object())
    assert not r.executed and "Door" in r.reason

    # (e) component/schedule label mismatch -> BLOCK.
    a = _fake_composed([ScheduledComponent(DOOR, _door_ok, is_door=True)], admit2)
    r = a.run_phase(Phase.ADMIT, a.composition, object(), object())
    assert not r.executed and "mismatch" in r.reason

    # the happy path through the same machinery still ALLOWs (so the failures above are meaningful).
    a = _fake_composed([ScheduledComponent(BIND, lambda: ComponentOutcome(True)),
                        ScheduledComponent(DOOR, _door_ok, is_door=True)], admit2)
    r = a.run_phase(Phase.ADMIT, a.composition, object(), object())
    assert r.executed and r.reason == "door-ok"


# ============================================================================
# 6 — the promotion report is present, with a §4.7 readiness verdict
# ============================================================================
def test_promotion_report_exists():
    report = _REPO / "signet" / "rail_algebra" / "PROMOTION.md"
    assert report.is_file()
    text = report.read_text()
    assert "4.7" in text and "RESOLVE" in text


# ============================================================================
# 7 — COMPONENT-COMPLETENESS: the egress lifecycle guards are NOT dropped on the driven path
# ============================================================================
def test_egress_mandate_freshness_not_dropped():
    from _golden.corpus import _egress_broker, _egress_broker_expired, _egress_broker_no_mandate

    # expired frozen mandate (TOCTOU + destination policy-clean) -> BLOCK mandate-expired.
    r, _ = _drive_egress(_egress_broker_expired())
    assert not r.executed and r.reason == "mandate-expired", r.reason

    # missing frozen mandate -> BLOCK no-frozen-mandate.
    r, _ = _drive_egress(_egress_broker_no_mandate())
    assert not r.executed and r.reason == "no-frozen-mandate", r.reason

    # fresh mandate -> ALLOW, and the last_mandate_hash SIDE EFFECT survives the promotion.
    r, authz = _drive_egress(_egress_broker())
    assert r.executed, r.reason
    assert authz.last_mandate_hash is not None and authz.last_mandate_hash.startswith("em_")
