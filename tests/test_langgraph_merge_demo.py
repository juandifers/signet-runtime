"""Smoke + clean-room verification for demos/langgraph_merge_demo.py (hermetic mode).

Runs the real StateGraph end to end with a scripted injected model + MockGitHubRail (no LLM, no
network), asserts the printed verdict (containment), and re-verifies the decision's receipt and
its RFC-6962 inclusion proof clean-room (only public key + proof, no runtime access). Skips
cleanly when langgraph is absent (A8).
"""
import pytest

pytest.importorskip("langgraph")

from demos.langgraph_merge_demo import HEADLINE, run   # noqa: E402


def test_hermetic_demo_contains_attacker_and_proves_clean_room():
    res = run("hermetic", verbose=False)
    result = res["result"]

    # The injected model proposed the attacker (#99); the gate contained it below the orchestrator.
    assert res["proposal"] == 99
    assert result["outcome"] == "block"
    assert result["escalation_source"] == "gate_contained"
    assert not res["attacker_merged"] and not res["merged"]

    # The required Check Run was concluded FAILURE; nothing was merged to success.
    rail = res["rail"]
    assert rail.conclusions[-1][2] == "failure"
    assert not any(c[2] == "success" for c in rail.conclusions)

    # The decision's receipt is signed/contained and its inclusion proof verifies clean-room.
    assert res["receipt"].decision == "blocked"
    assert res["inclusion_ok"] is True
    assert res["headline"] == HEADLINE


def test_demo_main_exits_zero_hermetic():
    from demos.langgraph_merge_demo import main
    assert main([]) == 0
