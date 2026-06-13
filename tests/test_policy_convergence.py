"""Policy-convergence loop — the hard/soft generalizer as INVARIANTS, not measurements.

House style mirrors tests/test_declarative_policy.py: build the typed axes + standing, run the
pure generalizer / three-way decider, assert the invariant, and verify the signed receipt.

The two load-bearing invariants (asserted, named in `INVARIANTS`):
  * GENERALIZER_CORRECT — hard axes pinned, soft-with-class opened to exactly the class, soft
    without a class pinned, never a wildcard.
  * INSIDE_STANDING — a confirmed learned rule permits no effect the standing ceiling denies.

The behavioral proof (`test_friction_moves_not_fence_loosens`) is the point of the whole feature:
after learning a rule from an approved effect, a sibling differing only on SOFT axes runs silently,
while a sibling differing on a HARD axis still escalates — friction MOVED, the fence did NOT loosen.
"""
import pytest

from signet import crypto
from evals.effect_core import BLOCK, ENDORSE, REVIEW
from evals._rail_core.policy_spec import (BOOL, CATEGORICAL, NUMERIC, AttrDecl, Condition, HARD,
                                          IN_SET, SOFT, OWN, PolicySpec, axis_variability,
                                          normalize_variability)
from evals._rail_core.policy_convergence import (INVARIANTS, ActiveLayer, CandidateRule,
                                                 PolicyAuthoringLog, Rejected, SCOPE_REPO,
                                                 SCOPE_SESSION, Standing, confirm, decide,
                                                 generalize, inside_standing, promote,
                                                 render_candidate)


# ============================================================================
# A shared, illustrative world adapted to the REAL typed model (categorical/bool/numeric axes).
# The spec's "path within roots" is modeled as a categorical `path_root` membership.
# ============================================================================
def _schema():
    return (
        # HARD axes — widening these needs the operator.
        AttrDecl("egress_destination",
                 CATEGORICAL({"none", "api.supabase.internal", "api.partner.example"}),
                 OWN, variability=HARD),
        AttrDecl("irreversibility", CATEGORICAL({"low", "medium", "high"}), OWN, variability=HARD),
        AttrDecl("scope", CATEGORICAL({"repo", "org"}), OWN, variability=HARD),
        # SOFT axes — safe to generalize within an operator-declared class.
        AttrDecl("command_class",
                 CATEGORICAL({"test_runner", "build_tool", "deploy_tool"}), OWN, variability=SOFT),
        AttrDecl("path_root", CATEGORICAL({"src", "tests", "docs", "infra"}), OWN, variability=SOFT),
    )


def _standing():
    # Ceiling = the standing universe (outside => BLOCK). It encodes the deny on `high` irreversibility
    # and on the partner egress destination, and bounds path_root to {src,tests,docs} (infra denied).
    ceiling = (
        Condition("irreversibility", IN_SET, frozenset({"low", "medium"})),
        Condition("egress_destination", IN_SET, frozenset({"none", "api.supabase.internal"})),
        Condition("scope", IN_SET, frozenset({"repo", "org"})),
        Condition("command_class", IN_SET, frozenset({"test_runner", "build_tool", "deploy_tool"})),
        Condition("path_root", IN_SET, frozenset({"src", "tests", "docs"})),
    )
    # Seed: nothing pre-allowed -> almost every in-ceiling effect ESCALATES (the starting friction).
    return Standing(ceiling=ceiling, allow_rules=())


def _approved_effect():
    # An effect the operator approves after it escalated: a test runner touching src/, no egress,
    # low irreversibility, repo scope.
    return {"egress_destination": "none", "irreversibility": "low", "scope": "repo",
            "command_class": "test_runner", "path_root": "src"}


# `command_class` is opened within the {test_runner, build_tool} class; `path_root` within {src, tests}.
def _declared_classes():
    return {"command_class": frozenset({"test_runner", "build_tool"}),
            "path_root": frozenset({"src", "tests"})}


def _cond_map(clause):
    return {c.attr: c for c in clause}


# ============================================================================
# axis variability — the new field, fail-safe
# ============================================================================
def test_axis_variability_reads_field_and_fails_safe_to_hard():
    schema = _schema()
    av = axis_variability(schema)
    assert av["egress_destination"] == HARD and av["command_class"] == SOFT
    # unknown / missing variability collapses to HARD
    assert normalize_variability("squishy") == HARD
    assert normalize_variability(None) == HARD
    weird = AttrDecl("x", BOOL(), OWN, variability="banana")
    assert weird.variability == HARD


# ============================================================================
# GENERALIZER_CORRECT (invariant)
# ============================================================================
def test_generalizer_pins_every_hard_axis_to_the_approved_value():
    cand = generalize(_approved_effect(), _schema(), _standing(),
                      declared_classes=_declared_classes(), from_effect="eff_1")
    assert isinstance(cand, CandidateRule)
    cm = _cond_map(cand.allow)
    for axis in ("egress_destination", "irreversibility", "scope"):
        assert cm[axis].op == IN_SET
        assert cm[axis].value == frozenset({_approved_effect()[axis]})   # pinned, singleton, never widened


def test_generalizer_opens_soft_with_class_and_pins_soft_without_class():
    # command_class soft WITH a class -> opened to the class; path_root soft but NO class -> pinned.
    classes = {"command_class": frozenset({"test_runner", "build_tool"})}
    cand = generalize(_approved_effect(), _schema(), _standing(),
                      declared_classes=classes, from_effect="eff_2")
    assert isinstance(cand, CandidateRule)
    cm = _cond_map(cand.allow)
    assert cm["command_class"].value == frozenset({"test_runner", "build_tool"})   # OPENED to the class
    assert cm["path_root"].value == frozenset({"src"})                              # soft, no class -> PINNED
    assert ("command_class", ("build_tool", "test_runner")) in cand.opened
    assert ("path_root", "src") in cand.pinned


def test_generalizer_never_emits_a_wildcard():
    cand = generalize(_approved_effect(), _schema(), _standing(),
                      declared_classes=_declared_classes(), from_effect="eff_3")
    assert isinstance(cand, CandidateRule)
    # every condition is IN_SET of a CONCRETE, bounded frozenset; no literal '*'; never the full universe.
    universes = {"command_class": 3, "path_root": 4, "egress_destination": 3,
                 "irreversibility": 3, "scope": 2}
    for c in cand.allow:
        assert c.op == IN_SET and isinstance(c.value, frozenset) and len(c.value) >= 1
        assert "*" not in c.value
        assert len(c.value) < universes[c.attr]            # strictly inside the axis universe (not a wildcard)


def test_generalizer_refuses_a_class_equal_to_the_full_universe_as_a_wildcard():
    # declaring the ENTIRE command_class universe "safe" is a de-facto wildcard -> refused.
    classes = {"command_class": frozenset({"test_runner", "build_tool", "deploy_tool"})}
    out = generalize(_approved_effect(), _schema(), _standing(),
                     declared_classes=classes, from_effect="eff_4")
    assert isinstance(out, Rejected) and "wildcard" in out.reason.lower()


# ============================================================================
# INSIDE_STANDING (invariant) — the monotonicity guard
# ============================================================================
def test_inside_standing_rejects_a_soft_class_that_reaches_outside_the_ceiling():
    # path_root soft class includes 'infra', which the ceiling DENIES -> the candidate would permit a
    # standing-denied effect -> generalize must return Rejected.
    classes = {"path_root": frozenset({"src", "infra"})}
    out = generalize(_approved_effect(), _schema(), _standing(),
                     declared_classes=classes, from_effect="eff_5")
    assert isinstance(out, Rejected)
    assert "standing-denied" in out.reason or "not in its declared class" in out.reason


def test_inside_standing_guard_directly_on_a_handcrafted_overbroad_clause():
    # A clause is inside standing only if it constrains EVERY ceiling axis within the ceiling. A
    # full clause that opens irreversibility to include 'high' (ceiling-denied) is NOT inside.
    schema, standing = _schema(), _standing()
    good = (Condition("irreversibility", IN_SET, frozenset({"low", "medium"})),
            Condition("egress_destination", IN_SET, frozenset({"none", "api.supabase.internal"})),
            Condition("scope", IN_SET, frozenset({"repo", "org"})),
            Condition("command_class", IN_SET, frozenset({"test_runner", "build_tool"})),
            Condition("path_root", IN_SET, frozenset({"src", "tests"})))
    ok_good, reason_good = inside_standing(good, schema, standing)
    assert ok_good, reason_good
    # widen ONE axis past the ceiling -> no longer inside
    bad = tuple(Condition(c.attr, c.op, (frozenset({"low", "medium", "high"})
                                         if c.attr == "irreversibility" else c.value))
                for c in good)
    ok_bad, reason_bad = inside_standing(bad, schema, standing)
    assert not ok_bad and "standing-denied" in reason_bad

    # And a clause that LEAVES a ceiling axis unconstrained also fails — it permits the denied value
    # on that axis (egress=api.partner.example), proving the guard is total over ceiling axes.
    partial = (Condition("irreversibility", IN_SET, frozenset({"low", "medium"})),)
    ok_partial, _ = inside_standing(partial, schema, standing)
    assert not ok_partial


@pytest.mark.parametrize("approved", [
    {"egress_destination": "none", "irreversibility": "low", "scope": "repo",
     "command_class": "test_runner", "path_root": "src"},
    {"egress_destination": "api.supabase.internal", "irreversibility": "medium", "scope": "org",
     "command_class": "build_tool", "path_root": "tests"},
])
def test_property_every_confirmable_candidate_is_inside_standing(approved):
    # Property: for any in-ceiling approved effect, a generalized (non-Rejected) candidate permits
    # NO effect the standing ceiling denies — verified by exhaustively re-checking the guard.
    cand = generalize(approved, _schema(), _standing(),
                      declared_classes=_declared_classes(), from_effect="eff_prop")
    if isinstance(cand, Rejected):
        return
    ok, reason = inside_standing(cand.allow, _schema(), _standing())
    assert ok, reason


# ============================================================================
# THE BEHAVIORAL PROOF — friction MOVED, the fence did NOT loosen
# ============================================================================
def test_friction_moves_not_fence_loosens():
    schema, standing = _schema(), _standing()
    approved = _approved_effect()

    # 1. Before learning: the approved effect (and its siblings) ESCALATE — Signet feels like a prompt.
    layer = ActiveLayer(scope=SCOPE_SESSION)
    assert decide(approved, standing, (layer,)).kind == REVIEW

    # 2. Human approves it; generalize + confirm the learned rule (soft command_class opened to a class).
    cand = generalize(approved, schema, standing,
                      declared_classes=_declared_classes(), from_effect="eff_E")
    assert isinstance(cand, CandidateRule)
    rule, _ = confirm(cand, layer, rule_id="lr_E", confirmed_by="operator", created_at="2026-06-13T00:00:00Z")
    assert rule in layer.rules

    # 3. A sibling differing ONLY on a SOFT axis (command_class within the opened class) -> SILENT.
    soft_sibling = dict(approved, command_class="build_tool")     # build_tool is in the declared class
    assert decide(soft_sibling, standing, (layer,)).kind == ENDORSE   # friction MOVED: no re-escalation

    # 4. A sibling differing on a HARD axis (scope repo->org, still IN-CEILING) -> STILL ESCALATES.
    hard_sibling = dict(approved, scope="org")
    assert decide(hard_sibling, standing, (layer,)).kind == REVIEW    # fence did NOT loosen on hard axes

    # 5. A sibling outside the standing CEILING (irreversibility=high) -> BLOCKED, learned rule notwithstanding.
    denied = dict(approved, irreversibility="high")
    assert decide(denied, standing, (layer,)).kind == BLOCK           # learned rules cannot exceed standing

    # 6. And a soft sibling OUTSIDE the opened class (deploy_tool) keeps escalating — soft != wildcard.
    soft_outside_class = dict(approved, command_class="deploy_tool")
    assert decide(soft_outside_class, standing, (layer,)).kind == REVIEW


def test_structural_monotonicity_even_with_an_overbroad_rule_in_the_layer():
    # Defense in depth: even if an over-broad clause were somehow placed in a layer, `decide` checks
    # the ceiling FIRST, so an effect the ceiling denies is BLOCKED regardless of the learned rule.
    schema, standing = _schema(), _standing()
    rogue = ActiveLayer(scope=SCOPE_SESSION, rules=[
        # an (illegitimate) rule that "allows" a high-irreversibility effect
        __import__("evals._rail_core.policy_convergence", fromlist=["LearnedRule"]).LearnedRule(
            id="lr_rogue", allow=(Condition("irreversibility", IN_SET, frozenset({"high"})),),
            from_effect="eff_x", confirmed_by="?", created_at="", scope=SCOPE_SESSION)])
    denied = dict(_approved_effect(), irreversibility="high")
    assert decide(denied, standing, (rogue,)).kind == BLOCK


# ============================================================================
# RECEIPTS — new entry types verify under the EXISTING transparency verifier
# ============================================================================
def test_learned_rule_created_receipt_verifies_under_existing_verification():
    schema, standing = _schema(), _standing()
    sk, vk = crypto.generate_keypair()
    log = PolicyAuthoringLog(sk, vk, clock=lambda: __import__("datetime").datetime(2026, 6, 13,
                                                              tzinfo=__import__("datetime").timezone.utc))
    layer = ActiveLayer(scope=SCOPE_SESSION)
    cand = generalize(_approved_effect(), schema, standing,
                      declared_classes=_declared_classes(), from_effect="eff_R")
    rule, rec = confirm(cand, layer, rule_id="lr_R", confirmed_by="operator",
                        created_at="2026-06-13T00:00:00Z", log=log)
    assert rec is not None and rec.event == "learned_rule_created"
    ok, msg = log.verify("lr_R", event="learned_rule_created")
    assert ok, msg


def test_learned_rule_promoted_receipt_verifies_and_requires_explicit_always():
    schema, standing = _schema(), _standing()
    sk, vk = crypto.generate_keypair()
    log = PolicyAuthoringLog(sk, vk)
    session, repo = ActiveLayer(scope=SCOPE_SESSION), ActiveLayer(scope=SCOPE_REPO)
    cand = generalize(_approved_effect(), schema, standing,
                      declared_classes=_declared_classes(), from_effect="eff_P")
    rule, _ = confirm(cand, session, rule_id="lr_P", created_at="2026-06-13T00:00:00Z", log=log)

    # no auto-promotion: an implicit promote is refused
    with pytest.raises(PermissionError):
        promote(rule, session, repo, always=False, log=log)

    promoted, prec = promote(rule, session, repo, always=True, created_at="2026-06-13T00:01:00Z", log=log)
    assert promoted.scope == SCOPE_REPO and promoted in repo.rules and rule not in session.rules
    assert prec.event == "learned_rule_promoted"
    ok, msg = log.verify("lr_P", event="learned_rule_promoted")
    assert ok, msg


def test_render_candidate_shows_opened_and_pinned_axes():
    cand = generalize(_approved_effect(), _schema(), _standing(),
                      declared_classes=_declared_classes(), from_effect="eff_render")
    text = render_candidate(cand)
    assert "OPEN  command_class" in text and "PIN   irreversibility" in text


# ============================================================================
# INVARIANTS are declared (distinct from measurements)
# ============================================================================
def test_invariants_are_named_not_measured():
    assert len(INVARIANTS) == 2
    assert any("GENERALIZER_CORRECT" in i for i in INVARIANTS)
    assert any("INSIDE_STANDING" in i for i in INVARIANTS)
