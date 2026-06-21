"""Acceptance for the seam reshape (SPEC §6) — generalize `RailBinding` from resolution-only to
{resolution, admission} WITHOUT changing a verdict.

This is the FIRST deliberate edit to `integrations/effect_gateway/seam.py` (the old
SEAM-BYTE-IDENTICAL @ 8761fe98 invariant is intentionally retired; the new sha is pinned here).
The gate is BEHAVIOR-PRESERVED: all THREE known-good rails reproduce their verdicts through the
reshaped seam — merge (resolution), egress + supabase (admission). The committed verdict goldens
(`tests/_golden/rail_verdicts.json`) are NOT regenerated and NOT extended (they are computed through
rail-core entry points, orthogonal to the seam); preservation is asserted at the SEAM here.

The fixtures are imported verbatim from the existing binding test modules, so the verdicts compared
are the SAME ones those suites already pin — what this file adds is that they survive the reshape's
new shape-routing, shape-gated resume, and honest (binding-determined) verifier contract.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

# default (prepend) import mode already puts tests/ on sys.path; be explicit so this file is
# robust to the invocation path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evals.github_railbridge.resolver import FixedChoiceResolver, FixedSetResolver  # noqa: E402

from integrations.effect_gateway.rails_egress import EgressBinding  # noqa: E402
from integrations.effect_gateway.rails_github import GitHubMergeBinding  # noqa: E402
from integrations.effect_gateway.rails_supabase import SupabaseBinding  # noqa: E402
from integrations.effect_gateway.seam import (Decision, EffectInterceptor, Outcome,  # noqa: E402
                                              ProposedEffect)

import test_egress_binding as egress_mod  # noqa: E402
import test_langgraph_adapter as merge_mod  # noqa: E402
import test_supabase_binding as db_mod  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SEAM_PATH = REPO_ROOT / "integrations" / "effect_gateway" / "seam.py"
SEAM_DIR = REPO_ROOT / "integrations" / "effect_gateway"
# Pinned POST-reshape. The old byte-identical-to-8761fe98 invariant is retired (SEAM-RESHAPE-INTENTIONAL).
SEAM_SHA256_NEW = "653afde94c8de70ec77fb0567e9d54991a18c35b96e5db9a441499526e60d49c"
SEAM_SHA256_OLD = "8761fe982239774350387cc5b58b0fcdeef6452b02fa8068ae28268ad05b879b"


# ===========================================================================================
# §6.1-3  BEHAVIOR-PRESERVED — three rails reproduce their verdicts through the reshaped seam
# ===========================================================================================
def test_merge_resolution_preserved():
    """merge (shape='resolution') — RESOLVED->ALLOW, contained->BLOCK, cardinality>=2->ESCALATE,
    and resume after an escalation still authorizes. Routing through the reshaped seam (resolution
    branch + shape-gated resume) is verdict-for-verdict identical."""
    # a fresh interceptor per verdict (consume-once / the mock rail mutate state, exactly as the
    # existing adapter suite does — one _make() per scenario).
    allow_ic = merge_mod._make()[0]
    assert allow_ic.intercept(merge_mod._MERGE,
                              proposer=FixedChoiceResolver(7)).outcome is Outcome.ALLOW

    block_ic = merge_mod._make()[0]
    assert block_ic.intercept(merge_mod._MERGE,
                              proposer=FixedChoiceResolver(99)).outcome is Outcome.BLOCK

    # genuine ambiguity needs two in-fence owned PRs (#7, #8) and a non-issue criterion so Layer A
    # does not pre-resolve to the issue-closing PR (mirrors the adapter's escalate fixture).
    esc_ic = merge_mod._make(criterion="merge the ready feature PR",
                             world=merge_mod._world(extra=(merge_mod._legit_eight(),)))[0]
    amb = esc_ic.intercept(merge_mod._MERGE, proposer=FixedSetResolver([7, 8]))
    assert amb.outcome is Outcome.ESCALATE and set(amb.candidates) == {7, 8}
    # resume is valid on a resolution rail (RESUME-SHAPE-GATED admits it) -> authorizes the choice.
    resumed = esc_ic.resume(merge_mod._MERGE, amb, {"choice": 7},
                            frozen_world=esc_ic.world, current_world=esc_ic.world)
    assert resumed.outcome is Outcome.ALLOW


def test_egress_admission_preserved():
    """egress (shape='admission') — corpus verdicts through the admission branch are unchanged."""
    env = egress_mod._make()
    ic = env["ic"]
    cases = [
        (egress_mod._fetch("api.allowed.test", 443), Outcome.ALLOW),   # in mandate
        (egress_mod._fetch("evil.test", 443), Outcome.BLOCK),          # off-mandate (in standing)
        (egress_mod._fetch("api.allowed.test", 22), Outcome.BLOCK),    # off-mandate port
        (egress_mod._fetch("127.0.0.1", env["evil_port"]), Outcome.BLOCK),  # raw-IP evasion
        (ProposedEffect("fetch_url", {}), Outcome.BLOCK),              # malformed -> fail closed
    ]
    for eff, expected in cases:
        assert ic.intercept(eff, proposer=None).outcome is expected, eff


def test_supabase_admission_preserved():
    """supabase (shape='admission') — corpus verdicts through the admission branch are unchanged."""
    env = db_mod._make()
    ic = env["ic"]
    cases = [
        (db_mod._db("staging", "analytics_events", "insert"), Outcome.ALLOW),   # in mandate
        (db_mod._db("staging", "analytics_events", "delete"), Outcome.BLOCK),   # off-mandate op
        (db_mod._db("prod", "users", "insert"), Outcome.BLOCK),                 # off-standing
        (ProposedEffect("db_write", {}), Outcome.BLOCK),                        # malformed
    ]
    for eff, expected in cases:
        assert ic.intercept(eff, proposer=None).outcome is expected, eff


# ===========================================================================================
# §6.4  SHAPE-COMPLETENESS — every binding declares a known shape
# ===========================================================================================
def test_all_bindings_declare_shape():
    merge_b = merge_mod._make()[0].bindings[0]
    egress_b = egress_mod._make()["ic"].bindings[0]
    db_b = db_mod._make()["ic"].bindings[0]
    assert merge_b.shape == "resolution"
    assert egress_b.shape == "admission"
    assert db_b.shape == "admission"
    for b in (merge_b, egress_b, db_b):
        assert b.shape in {"resolution", "admission"}
    # the classes carry it too (so a fresh instance is never shapeless)
    assert GitHubMergeBinding.shape == "resolution"
    assert EgressBinding.shape == "admission"
    assert SupabaseBinding.shape == "admission"


# ===========================================================================================
# §6.5  RESUME-SHAPE-GATED — the seam refuses a resume on an admission binding (not by hasattr)
# ===========================================================================================
def test_resume_refused_on_admission_binding():
    env = egress_mod._make()
    ic = env["ic"]
    eff = egress_mod._fetch("api.allowed.test", 443)        # handled by the egress (admission) binding
    fake = Decision(Outcome.ESCALATE, "pretend escalation", candidates=(1,))
    out = ic.resume(eff, fake, {"choice": 1}, frozen_world=None)
    assert out.outcome is Outcome.BLOCK
    assert out.escalation_source == "no_binding"
    assert "only resolution rails escalate" in out.cause   # seam-level refusal, no binding reached


# ===========================================================================================
# §6.6  FAIL-CLOSED — an unknown / absent shape blocks before submit
# ===========================================================================================
class _FrobBinding:
    name = "frob"
    shape = "frobnicate"                                   # not in {resolution, admission}

    def handles(self, eff): return eff.tool == "frob_tool"
    def proposal_for(self, proposal): return proposal
    def submit(self, eff, **kw): return Decision(Outcome.ALLOW, "should never be reached")


class _ShapelessBinding:
    name = "shapeless"                                     # NO shape attribute at all

    def handles(self, eff): return eff.tool == "shapeless_tool"
    def proposal_for(self, proposal): return proposal
    def submit(self, eff, **kw): return Decision(Outcome.ALLOW, "should never be reached")


def test_unknown_shape_fails_closed():
    ic = EffectInterceptor(None, [_FrobBinding()], env=None, bridge=None, receipts=None)
    out = ic.intercept(ProposedEffect("frob_tool", {}), proposer=None)
    assert out.outcome is Outcome.BLOCK
    assert out.escalation_source == "no_binding"
    assert "no known shape" in out.cause


def test_absent_shape_fails_closed():
    ic = EffectInterceptor(None, [_ShapelessBinding()], env=None, bridge=None, receipts=None)
    out = ic.intercept(ProposedEffect("shapeless_tool", {}), proposer=None)
    assert out.outcome is Outcome.BLOCK and out.escalation_source == "no_binding"


# ===========================================================================================
# §6.7  NO-VESTIGIAL — zero `resolver_for` remains; every binding has `proposal_for`
# ===========================================================================================
def test_no_resolver_for_remains():
    # introspection: the renamed hook is gone from every binding class, the new one is present.
    for cls in (GitHubMergeBinding, EgressBinding, SupabaseBinding):
        assert not hasattr(cls, "resolver_for"), f"{cls.__name__} still has resolver_for"
        assert hasattr(cls, "proposal_for"), f"{cls.__name__} missing proposal_for"
    # the seam Protocol itself no longer names resolver_for in its routing.
    seam_src = SEAM_PATH.read_text()
    assert "resolver_for" not in seam_src
    assert "def proposal_for" in seam_src
    # no source file under the gateway defines/calls resolver_for any more (docs excluded).
    for py in SEAM_DIR.glob("*.py"):
        assert "resolver_for" not in py.read_text(), f"{py.name} still references resolver_for"


# ===========================================================================================
# §6.8  FACE-2-HONEST — admission rails do NOT read env.verifier; merge does
# ===========================================================================================
class _AllPoison:
    """Any attribute access raises — an admission rail that touched `env` at all would trip it."""
    def __getattr__(self, name):
        raise AssertionError(f"admission rail read env.{name} — it must use its per-effect verifier")


class _VerifierPoison:
    """Delegates every attribute to the real env EXCEPT `.verifier`, which raises — so merge runs
    up to the point it reads the verifier and then fails closed, proving the dependency."""
    def __init__(self, real): object.__setattr__(self, "_real", real)

    def __getattr__(self, name):
        if name == "verifier":
            raise AssertionError("env.verifier read")
        return getattr(object.__getattribute__(self, "_real"), name)


def test_admission_independent_of_env_verifier():
    # egress + supabase: poison the WHOLE env; they still produce correct verdicts (own verifier).
    eg = egress_mod._make()
    eg["ic"].env = _AllPoison()
    assert eg["ic"].intercept(egress_mod._fetch("api.allowed.test", 443),
                              proposer=None).outcome is Outcome.ALLOW
    assert eg["ic"].intercept(egress_mod._fetch("evil.test", 443),
                              proposer=None).outcome is Outcome.BLOCK

    db = db_mod._make()
    db["ic"].env = _AllPoison()
    assert db["ic"].intercept(db_mod._db("staging", "analytics_events", "insert"),
                              proposer=None).outcome is Outcome.ALLOW
    assert db["ic"].intercept(db_mod._db("prod", "users", "insert"),
                              proposer=None).outcome is Outcome.BLOCK


def test_merge_depends_on_env_verifier():
    # the contrapositive: merge with a poisoned verifier does NOT reach its ALLOW — the dependency
    # is rail-SHAPED (resolution reads env.verifier), exactly what the reshape makes honest.
    clean, _r, _x = merge_mod._make()
    assert clean.intercept(merge_mod._MERGE, proposer=FixedChoiceResolver(7)).outcome is Outcome.ALLOW

    poisoned, _r2, _x2 = merge_mod._make()
    poisoned.env = _VerifierPoison(poisoned.env)
    out = poisoned.intercept(merge_mod._MERGE, proposer=FixedChoiceResolver(7))
    assert out.outcome is not Outcome.ALLOW           # fails closed when its verifier is unreachable
    assert out.outcome is Outcome.BLOCK


# ===========================================================================================
# §6.9  SEAM-RESHAPE-INTENTIONAL — the new sha is pinned; the old 8761fe98 is gone
# ===========================================================================================
def test_seam_sha_pinned_post_reshape():
    actual = hashlib.sha256(SEAM_PATH.read_bytes()).hexdigest()
    assert actual == SEAM_SHA256_NEW, "seam.py changed unexpectedly — pinned post-reshape sha violated"
    assert actual != SEAM_SHA256_OLD, "seam.py is still at the retired byte-identical sha"


# ===========================================================================================
# K0 — the reshape touches the trusted base + bindings, never the kernel
# ===========================================================================================
def test_kernel_baseline_unchanged():
    from evals.scorecard.architecture import kernel_edit_check
    assert kernel_edit_check()["edits"] == 0
