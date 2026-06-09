"""The declarative typed-policy contract — the "fence is DATA, not code" machine tests.

  * the ONE shared evaluator is correct over every op (scalar + set-valued)            [EVALUATOR_SOUND]
  * a fence/allow-list Condition may reference ONLY a DECLARED, OWN attribute            [PART 4]
  * a NUMERIC attr with no bounding condition is a VISIBLE WARNING, not a silent pass     [PART 3/6]
  * every built-in rail ships a non-empty schema whose conditions are all OWN + declared  [PART 5]
  * the rails inherit the SHARED within_* (no per-rail fence/allow-list code)             [PART 2]
  * the scorecard diffs the PolicySpec run-over-run; a loosened cap / removed fence is an
    ALARM, a tightened cap is not                                                          [PART 6]
"""
import pytest

from evals._rail_core.policy_spec import (AttrDecl, BOOL, CATEGORICAL, NUMERIC, Condition, EQ, GE,
                                          IN_SET, LE, NOT_IN_SET, OWN, UNTRUSTED, PolicySpec,
                                          evaluate_allowlist, evaluate_fence,
                                          evaluator_soundness_failures, schema_violations,
                                          unbounded_numeric_warnings)
from evals.conformance import ConformanceError, DeclarativeRailPlugin, register_rail, run_conformance
from evals.conformance.protocol import DeclarativeRailPlugin as _Base
from evals.conformance.rails import (DeployPlugin, GitHubPlugin, InfraRailPlugin, deploy_plugin,
                                     github_plugin, infra_plugin)

ALL_PLUGINS = [github_plugin, deploy_plugin, infra_plugin]


# ============================================================================
# PART 1 — the shared evaluator
# ============================================================================
def test_evaluator_is_sound():
    assert evaluator_soundness_failures() == []


def test_set_valued_ops_are_subset_and_disjoint():
    # IN_SET over a set-valued attr == subset; NOT_IN_SET == disjoint (the protected/universe folds)
    spec = PolicySpec(fence=(Condition("types", NOT_IN_SET, frozenset({"iam"})),
                             Condition("types", IN_SET, frozenset({"s3", "ecs", "iam"}))))
    ok, _ = evaluate_fence({"types": frozenset({"s3"})}, spec)
    assert ok
    ok, disp = evaluate_fence({"types": frozenset({"s3", "iam"})}, spec)
    assert not ok and disp == "types"             # touches a protected type -> first fence violation


def test_missing_attr_fails_closed():
    spec = PolicySpec(fence=(Condition("ghost", EQ, True),))
    ok, disp = evaluate_fence({}, spec)            # attr not projected -> fail CLOSED
    assert not ok and disp == "ghost"
    assert not evaluate_allowlist({}, PolicySpec(allowlist=(Condition("ghost", EQ, True),)))


# ============================================================================
# PART 4 — the structural contract (register_rail refuses by construction)
# ============================================================================
def test_schema_violations_flag_untrusted_and_undeclared():
    schema = (AttrDecl("ok_attr", BOOL(), OWN), AttrDecl("tainted", BOOL(), UNTRUSTED))
    spec = PolicySpec(fence=(Condition("tainted", EQ, False),   # untrusted -> violation
                             Condition("ghost", EQ, False)))    # undeclared -> violation
    v = schema_violations(schema, spec)
    assert any("UNTRUSTED" in x for x in v) and any("UNDECLARED" in x for x in v)
    # an OWN, declared condition is clean
    assert schema_violations(schema, PolicySpec(fence=(Condition("ok_attr", EQ, True),))) == []


def test_register_refuses_empty_schema():
    class _NoSchema(InfraRailPlugin):
        name = "no_schema"
        def candidate_schema(self):
            return ()
    with pytest.raises(ConformanceError) as ei:
        register_rail(_NoSchema())
    assert "EMPTY" in str(ei.value)


def test_register_refuses_fence_over_untrusted_attr():
    class _Untrusted(InfraRailPlugin):
        name = "untrusted_fence"
        def candidate_schema(self):
            return super().candidate_schema() + (AttrDecl("injected", BOOL(), UNTRUSTED),)
        def policy_spec(self, world):
            base = super().policy_spec(world)
            return PolicySpec(allowlist=base.allowlist,
                              fence=base.fence + (Condition("injected", EQ, False),))
    with pytest.raises(ConformanceError) as ei:
        register_rail(_Untrusted())
    assert "UNTRUSTED" in str(ei.value)


# ============================================================================
# PART 3/6 — the unbounded-numeric WARNING
# ============================================================================
def test_unbounded_numeric_is_a_warning():
    schema = (AttrDecl("blast", NUMERIC(0, 20), OWN), AttrDecl("flag", BOOL(), OWN))
    bounded = PolicySpec(fence=(Condition("blast", LE, 10), Condition("flag", EQ, False)))
    assert unbounded_numeric_warnings(schema, bounded) == []
    unbounded = PolicySpec(fence=(Condition("flag", EQ, False),))     # no bound on blast
    w = unbounded_numeric_warnings(schema, unbounded)
    assert len(w) == 1 and "blast" in w[0]


# ============================================================================
# PART 2 / PART 5 — every rail is data-driven and inherits the shared evaluator
# ============================================================================
@pytest.mark.parametrize("make", ALL_PLUGINS)
def test_rail_schema_is_nonempty_and_all_conditions_own(make):
    p = make()
    schema = p.candidate_schema()
    assert schema, "rail must declare a non-empty candidate schema"
    spec = p.policy_spec(p.build_world())
    assert schema_violations(schema, spec) == []      # every condition OWN + declared
    # the rail must have a fence (it discriminates) and the fence references only declared attrs
    names = {d.name for d in schema}
    assert spec.fence and all(c.attr in names for c in spec.fence)


@pytest.mark.parametrize("cls", [GitHubPlugin, DeployPlugin, InfraRailPlugin])
def test_rail_does_not_override_the_shared_fence(cls):
    # the allow-list / fence DECISION lives in the shared base ONLY — a rail cannot ship its own.
    assert cls.within_allowlist is _Base.within_allowlist
    assert cls.within_fence is _Base.within_fence
    assert issubclass(cls, DeclarativeRailPlugin)


@pytest.mark.parametrize("make", ALL_PLUGINS)
def test_within_wrappers_equal_the_evaluator(make):
    # the shared wrapper IS evaluate_*(project, policy_spec) — prove they agree on the default world.
    p = make()
    world = p.build_world()
    spec = p.policy_spec(world)
    for cid in p.owned_ids(world):
        attrs = p.project(world, cid)
        assert p.within_allowlist(world, cid) == evaluate_allowlist(attrs, spec)
        assert p.within_fence(world, cid) == evaluate_fence(attrs, spec)[0]


# ============================================================================
# PART 6 — the scorecard diffs the PolicySpec (loosen/remove = ALARM; tighten = not)
# ============================================================================
def _doc(blast_cond):
    return {"measurements": {"conformance": {"infra": {"policy_spec": {
        "allowlist": ["account in_set ['a']"],
        "fence": ["protected_type eq False", blast_cond, "destroy_count le 0"]}}}}}


def test_policy_diff_alarms_on_loosen_and_remove_but_not_tighten():
    from evals.scorecard.grade import _policy_spec_diff
    prior = _doc("blast_radius le 10")
    _, loosen = _policy_spec_diff(prior, _doc("blast_radius le 20"))
    assert any(a["kind"] == "POLICY LOOSENED" for a in loosen)
    _, tighten = _policy_spec_diff(prior, _doc("blast_radius le 5"))
    assert tighten == []
    removed = {"measurements": {"conformance": {"infra": {"policy_spec": {
        "allowlist": ["account in_set ['a']"],
        "fence": ["protected_type eq False", "destroy_count le 0"]}}}}}
    _, weak = _policy_spec_diff(prior, removed)
    assert any(a["kind"] == "FENCE WEAKENED" for a in weak)
    _, same = _policy_spec_diff(prior, _doc("blast_radius le 10"))
    assert same == []
