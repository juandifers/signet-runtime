"""Acceptance tests for the lifecycle dimension (SPEC §7). The tests are the spec.

  1. test_merge_schedule_is_faithful  — the observed (component, phase) sequence of a full Role-B
     merge job equals merge's DECLARED schedule (Policy's two layers @ RESOLVE, Bind+Door @ AUTHORIZE).
  2. test_egress_schedule_is_faithful — same for egress: all three axes @ ADMIT, in invocation order.
  3. test_phases_are_ordered          — both declared schedules are monotonic in Phase (no axis fires
     before its inputs).
  4. test_golden_unchanged            — the committed golden corpus is reproduced verdict-for-verdict
     (BEHAVIOR-PRESERVED: the schedule is metadata + opt-in instrumentation, not control flow).
  5. test_schedule_report_exists      — signet/rail_algebra/SCHEDULE.md is present with a §5.2
     phase-set verdict.

`tests/` is not a package; pytest prepends it to sys.path, so `_golden` imports resolve. The
faithfulness instrumentation (observe/mark/phase_scope) is a no-op outside an observe() block, so
the same end-to-end paths used here are byte-identical in production.
"""
from __future__ import annotations

import json
from pathlib import Path

from signet.rail_algebra import (EGRESS_SCHEDULE, MERGE_SCHEDULE, Phase, observe, observed_schedule)

_REPO = Path(__file__).resolve().parents[1]
_GOLDEN = json.loads((_REPO / "tests" / "_golden" / "rail_verdicts.json").read_text())


# ============================================================================
# fixtures — a full, PASSING end-to-end run of each rail (so every phase fires)
# ============================================================================
def _run_merge_under_observation():
    """A full Role-B merge job that RESOLVES + AUTHORIZES an in-scope owned PR — so the Policy's two
    gate layers fire at RESOLVE and the Bind+Door fire at AUTHORIZE. (The Role-B path, not the
    deterministic one, is what routes the gate through the rail-algebra DeclarativeMembership.)"""
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
    return job, observed_schedule(rec, name="merge")


def _admit_egress_under_observation():
    """A full egress admission of an allowed host — Bind.recheck + Policy.decide + Door.enforce all
    fire at the single ADMIT phase."""
    import sys
    sys.path.insert(0, str(_REPO / "tests"))            # _golden is not a package
    from _golden.corpus import _egress_broker
    broker = _egress_broker()
    with observe() as rec:
        adm = broker.admit("api.allowed.test", 443)
    return adm, observed_schedule(rec, name="egress")


# ============================================================================
# 1 + 2 — SCHEDULE-FAITHFUL: declared == observed for both rails
# ============================================================================
def test_merge_schedule_is_faithful():
    job, observed = _run_merge_under_observation()
    assert job.outcome is not None and job.outcome.approved, "fixture must reach Bind+Door (AUTHORIZE)"
    assert MERGE_SCHEDULE.matches(observed), (
        f"declared {MERGE_SCHEDULE.steps} != observed {observed.steps}")
    # the merge POLICY is two layers, both at RESOLVE, BEFORE the Bind+Door at AUTHORIZE.
    phases = {s.component: s.phase for s in observed}
    assert phases["policy:allowlist"] is Phase.RESOLVE
    assert phases["policy:fence"] is Phase.RESOLVE
    assert phases["bind"] is Phase.AUTHORIZE and phases["door"] is Phase.AUTHORIZE


def test_egress_schedule_is_faithful():
    adm, observed = _admit_egress_under_observation()
    assert adm.admitted, "fixture must be a full admission (all three axes fire)"
    assert EGRESS_SCHEDULE.matches(observed), (
        f"declared {EGRESS_SCHEDULE.steps} != observed {observed.steps}")
    # the admission rail collapses the lifecycle: every axis fires at ADMIT.
    assert all(s.phase is Phase.ADMIT for s in observed)


# ============================================================================
# 3 — PHASES-ARE-ORDERED: schedules are monotonic in Phase
# ============================================================================
def test_phases_are_ordered():
    assert MERGE_SCHEDULE.is_monotonic(), MERGE_SCHEDULE.steps
    assert EGRESS_SCHEDULE.is_monotonic(), EGRESS_SCHEDULE.steps
    # merge genuinely spans two phases (RESOLVE -> AUTHORIZE); egress is single-phase (ADMIT).
    assert MERGE_SCHEDULE.phases() == (Phase.RESOLVE, Phase.RESOLVE, Phase.AUTHORIZE, Phase.AUTHORIZE)
    assert set(EGRESS_SCHEDULE.phases()) == {Phase.ADMIT}


# ============================================================================
# 4 — BEHAVIOR-PRESERVED: the committed golden corpus is unchanged
# ============================================================================
def test_golden_unchanged():
    import sys
    sys.path.insert(0, str(_REPO / "tests"))
    from _golden.corpus import build_corpus
    assert build_corpus() == _GOLDEN


# ============================================================================
# 5 — the schedule report is present, with a §5.2 phase-set verdict
# ============================================================================
def test_schedule_report_exists():
    report = _REPO / "signet" / "rail_algebra" / "SCHEDULE.md"
    assert report.is_file()
    text = report.read_text()
    assert "5.2" in text and "RESOLVE" in text and "ADMIT" in text and "AUTHORIZE" in text
