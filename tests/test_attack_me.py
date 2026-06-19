"""Stage 2 — `signet attack-me` is a demo that can FAIL.

These tests are the guarantee that a future regression in the gate surfaces as a RED
demo test, not a quietly-wrong demo:
  * every act's real verdict equals its recorded expectation (the demo tells the truth),
  * the receipts chain verifies (the proof is real),
  * flipping the policy (drop auth/**) makes ACT 1 FAIL its expectation — proving the
    expectation check is real, not decorative.

Offline, deterministic: the sandbox tree + the init default policy are fixed; only the
tmp path varies. Nothing here calls a model or the network.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from signet.cli.attack_me import ACTS, build_sandbox, drive_act, run_acts
from signet.cli.local_receipts import LocalReceiptLog
from signet.fence import POLICY_RELPATH, PolicyFile, render_policy_yaml


def _act(n: str):
    return next(a for a in ACTS if a.n == n)


def test_every_act_matches_its_recorded_expectation(tmp_path):
    repo = build_sandbox(str(tmp_path))
    results = run_acts(repo)
    # Five acts, each must hit its recorded expectation through the REAL gate.
    assert [r.act.n for r in results] == ["1", "2a", "2b", "3a", "3b"]
    for r in results:
        assert r.verdict == r.act.expected, (
            f"act {r.act.n}: expected {r.act.expected}, gate returned {r.verdict} "
            f"(cause {r.cause!r}) — a real gap, not a demo bug")
        assert r.passed
    # The four hostile acts are DENY; the bare-push honest gap is PASS.
    verdicts = {r.act.n: r.verdict for r in results}
    assert verdicts == {"1": "deny", "2a": "deny", "2b": "deny", "3a": "deny", "3b": "pass"}


def test_each_denied_act_carries_a_real_receipt_and_cause(tmp_path):
    repo = build_sandbox(str(tmp_path))
    results = run_acts(repo)
    by_n = {r.act.n: r for r in results}
    assert by_n["1"].cause == "auth/**"
    assert by_n["2a"].cause == "self-protect:.claude/settings.local.json"
    assert by_n["2b"].cause == "self-protect:.signet/policy.yaml"
    assert by_n["3a"].cause == "*git push*origin*main*"
    for r in results:
        assert r.receipt_id and r.receipt_id.startswith("ldr_")
        assert r.policy_hash  # every decision is bound to the policy that made it


def test_receipt_chain_verifies(tmp_path):
    repo = build_sandbox(str(tmp_path))
    run_acts(repo)
    import os
    log = LocalReceiptLog(os.path.realpath(str(repo)))
    ok, msg, idx = log.verify()
    assert ok, msg
    assert idx == -1
    assert "5 records" in msg


def test_act3b_bare_push_is_the_honest_gap(tmp_path):
    """The known gap is REPRESENTED, not hidden: bare `git push` really passes the local
    gate, and the act ships the honest explanation that points at Stage 3."""
    repo = build_sandbox(str(tmp_path))
    r = next(x for x in run_acts(repo) if x.act.n == "3b")
    assert r.verdict == "pass"
    assert r.act.honest_note and "Stage 3" in r.act.honest_note


def test_flipped_policy_makes_act1_FAIL_its_expectation(tmp_path):
    """Proof the assertion is real: remove auth/** and ACT 1 (edit auth/login.py) flips
    from DENY to PASS — so its recorded expectation FAILS. A demo that cannot fail cannot
    be trusted."""
    repo = build_sandbox(str(tmp_path))
    pol = PolicyFile.load(repo / POLICY_RELPATH)
    assert "auth/**" in pol.protect, "fixture precondition: auth/** must start protected"

    new_protect = [g for g in pol.protect if g != "auth/**"]
    (repo / POLICY_RELPATH).write_text(render_policy_yaml(
        repo=pol.repo, protect=new_protect,
        protected_branches=pol.protected_branches, bash_deny=pol.bash_deny))

    r = drive_act(repo, _act("1"))
    assert r.verdict == "pass", "with auth/** gone, editing auth/login.py is now in-fence"
    assert r.passed is False, "the act's recorded expectation (DENY) must now FAIL LOUDLY"


def test_cli_json_entrypoint_is_green_and_self_consistent():
    """End-to-end through the real console entrypoint: exit 0 and a coherent trace."""
    out = subprocess.run(
        [sys.executable, "-m", "signet.cli.main", "attack-me", "--json"],
        capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    trace = json.loads(out.stdout)
    assert trace["all_passed"] is True
    assert len(trace["acts"]) == 5
    assert all(a["passed"] for a in trace["acts"])
    assert "server-side rail" in trace["boundary"]


def test_cli_quiet_mode_keeps_verdicts():
    out = subprocess.run(
        [sys.executable, "-m", "signet.cli.main", "attack-me", "--quiet"],
        capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert "act 1: deny" in out.stdout
    assert "act 3b: pass" in out.stdout
