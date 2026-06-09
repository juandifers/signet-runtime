"""GitHub rail-bridge end-to-end: PR -> evaluate -> GitHubRailBridge.authorize ->
MockGitHubRail conclusion -> receipt, plus the tampered-head failure path.

Proves the muscle (signet/authorizers/github_railbridge.py) drives the real kernel
verdict into a rail capability the agent cannot hold, and that the authorizer's
independent re-check catches a runtime-context tamper even when the token is valid.
"""
from signet.authorizers.github_railbridge import GitHubRailBridge, MockGitHubRail
from signet.receipts import ReceiptLog

from evals.github_railbridge.domain import CONFIGURED_REPO, effect_key, target_id
from evals.github_railbridge.merge_chain import build_merge_chain, make_github_env


def test_e2e_merge_authorizes_records_success_and_receipt():
    env = make_github_env()
    rail = MockGitHubRail()
    bridge = GitHubRailBridge(env.verifier, env.enforcer_vk, github_rail=rail)
    receipts = ReceiptLog(env.enforcer_sk, env.enforcer_vk)

    req = build_merge_chain(env)
    decision, token = env.verifier.evaluate(req)
    assert decision.approved

    result = bridge.authorize(token, req)
    assert result.executed
    assert result.rail == "github"
    assert result.payment_ref.startswith("check_")
    assert rail.conclusions[-1][2] == "success"

    receipt = receipts.append(
        execution_id=token.execution_id, mandate_id=token.mandate_id,
        chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
        decision="approved", payment_status="executed",
        payment_ref=result.payment_ref, rail=result.rail)
    ok, _ = receipts.verify(receipt)
    assert ok


def test_e2e_authorizer_refuses_forged_token():
    # The agent presents an unsigned/forged token -> verify_token fails FIRST.
    env = make_github_env()
    bridge = GitHubRailBridge(env.verifier, env.enforcer_vk, github_rail=MockGitHubRail())
    req = build_merge_chain(env)
    _, token = env.verifier.evaluate(req)
    token.signature = None
    result = bridge.authorize(token, req)
    assert not result.executed and "token" in result.reason.lower()


def test_e2e_tampered_head_sha_concludes_failure():
    # The enforcer approves the clean PR and mints a valid token. The agent then
    # presents that SAME valid token with a runtime context whose head_sha moved
    # (a force-push after authorization). verify_token PASSES, but the authorizer's
    # independent effect-vs-context re-check refuses -> conclusion=failure.
    env = make_github_env()
    rail = MockGitHubRail()
    bridge = GitHubRailBridge(env.verifier, env.enforcer_vk, github_rail=rail)

    req = build_merge_chain(env)
    decision, token = env.verifier.evaluate(req)
    assert decision.approved

    evil_recipient = effect_key("merge_pr", target_id(CONFIGURED_REPO, 42, "main", "shaEVIL000000"))
    tampered = req.model_copy(update={
        "context": req.context.model_copy(update={"recipient": evil_recipient})
    })
    result = bridge.authorize(token, tampered)
    assert not result.executed
    assert "mismatch" in result.reason.lower()
    assert rail.conclusions[-1][2] == "failure"
