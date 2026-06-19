"""Attack demos. Each test tells a piece of the enforcement story.

Run: pytest -v
"""
from datetime import datetime, timedelta, timezone

import pytest

# xrpl-py rides in the `dev` extra; skip cleanly (don't crash collection) if someone
# installed bare core. `pip install -e ".[dev]"` runs the full 21-attack spec.
Wallet = pytest.importorskip(
    "xrpl.wallet",
    reason="xrpl-py not installed — run: pip install -e '.[dev]'",
).Wallet

from signet.builder import make_env, build_chain
from signet.authorizers.mock_broker import MockCredentialBroker
from signet.authorizers.xrpl_cosigner import XRPLCosigner
from signet.receipts import ReceiptLog


# ---------- Core verifier: deterministic enforcement ----------

def test_valid_execution_succeeds():
    env = make_env()
    req = build_chain(env)
    decision, token = env.verifier.evaluate(req)
    assert decision.approved
    assert token is not None and token.signature
    assert env.verifier.verify_token(token, env.enforcer_vk)


def test_over_limit_blocked():
    env = make_env()
    req = build_chain(env, amount=7500)   # cap is 5000
    decision, token = env.verifier.evaluate(req)
    assert not decision.approved and token is None
    assert "exceeds" in decision.reason.lower()


def test_recipient_substitution_blocked():
    # Cart approved vendor_abc; runtime tries to redirect the destination.
    env = make_env()
    req = build_chain(env, ctx_destination="attacker_account")
    decision, _ = env.verifier.evaluate(req)
    assert not decision.approved
    assert "context" in decision.reason.lower()


def test_recipient_not_on_allowlist_blocked():
    env = make_env()
    req = build_chain(env, recipient="attacker_vendor",
                      destination_account="attacker_account")
    decision, _ = env.verifier.evaluate(req)
    assert not decision.approved


def test_currency_substitution_blocked():
    env = make_env()
    req = build_chain(env, currency="USD")   # policy allows only EUR
    decision, _ = env.verifier.evaluate(req)
    assert not decision.approved


def test_replay_blocked():
    env = make_env()
    req = build_chain(env)
    first, token = env.verifier.evaluate(req)
    assert first.approved
    # Resubmit the IDENTICAL transaction (e.g. retry storm or malicious replay).
    second, _ = env.verifier.evaluate(req)
    assert not second.approved
    assert "replay" in second.reason.lower()


def test_expired_mandate_blocked():
    env = make_env()
    past = env.clock() - timedelta(days=1)
    req = build_chain(env, valid_until=past)
    decision, _ = env.verifier.evaluate(req)
    assert not decision.approved and "expired" in decision.reason.lower()


def test_revoked_mandate_blocked():
    env = make_env()
    req = build_chain(env)
    env.revocation.revoke(req.intent.mandate_id)
    decision, _ = env.verifier.evaluate(req)
    assert not decision.approved and "revoked" in decision.reason.lower()


def test_cart_tamper_caught_by_signature():
    # Change a signed Cart's amount without re-signing.
    env = make_env()
    req = build_chain(env, tamper_cart_amount=50)
    decision, _ = env.verifier.evaluate(req)
    assert not decision.approved and "signature" in decision.reason.lower()


def test_chain_linkage_mismatch_blocked():
    # All signatures valid, but Payment commits to a different Cart.
    env = make_env()
    req = build_chain(env, break_linkage=True)
    decision, _ = env.verifier.evaluate(req)
    assert not decision.approved
    assert "cart" in decision.reason.lower()


def test_split_velocity_blocked():
    # Daily cap 10000. Four 4800 payments = 19200; the third should breach.
    env = make_env()
    approved = 0
    for i in range(4):
        req = build_chain(env, nonce=f"n{i}")
        d, _ = env.verifier.evaluate(req)
        if d.approved:
            approved += 1
        else:
            assert "daily" in d.reason.lower() or "velocity" in d.reason.lower() \
                   or "structuring" in d.reason.lower()
    assert approved == 2   # 4800 + 4800 = 9600 <= 10000; third would exceed


# ---------- Role 2: credential custody (rail-agnostic) ----------

def test_role2_executes_only_via_broker():
    env = make_env()
    broker = MockCredentialBroker(env.verifier, env.enforcer_vk)
    req = build_chain(env)
    decision, token = env.verifier.evaluate(req)
    assert decision.approved
    result = broker.authorize(token, req)
    assert result.executed and result.payment_ref.startswith("mockpay_tx_")


def test_role2_adapter_refuses_without_credential():
    # The agent has no capability to call the adapter directly.
    env = make_env()
    broker = MockCredentialBroker(env.verifier, env.enforcer_vk)
    with pytest.raises(PermissionError):
        broker.adapter.execute("cred_forged", "sha256:anything")


def test_role2_credential_is_consume_once():
    env = make_env()
    broker = MockCredentialBroker(env.verifier, env.enforcer_vk)
    req = build_chain(env)
    _, token = env.verifier.evaluate(req)
    # mint a real credential, use it, then try to reuse the same credential id
    cred = broker._mint(token.chain_hash)
    cid = cred.split(":")[0]
    ref = broker.adapter.execute(cid, token.chain_hash)
    assert ref
    with pytest.raises(PermissionError):
        broker.adapter.execute(cid, token.chain_hash)


# ---------- Role 1: XRPL multisign hard gate ----------

def _xrpl_setup(env):
    agent_w = Wallet.create()
    enforcer_w = Wallet.create()
    funding = Wallet.create().classic_address
    weights = {agent_w.classic_address: 1, enforcer_w.classic_address: 1}
    cosigner = XRPLCosigner(env.verifier, env.enforcer_vk, funding, enforcer_w,
                            signer_weights=weights, quorum=2)
    return agent_w, enforcer_w, funding, cosigner


def test_role1_requires_enforcer_cosignature():
    env = make_env()
    agent_w, enforcer_w, funding, cosigner = _xrpl_setup(env)
    dest = Wallet.create().classic_address
    # Build the AP2 chain for an XRPL leg (amount in drops, destination = XRPL addr).
    req = build_chain(env, rail="xrpl", currency="XRP", policy_id="xrpl_treasury_v1",
                      max_amount=2_000_000, recipient="vendor_abc",
                      destination_account=dest, amount=1_000_000)
    decision, token = env.verifier.evaluate(req)
    assert decision.approved

    tx = cosigner.build_payment(destination=dest, amount_drops=1_000_000,
                                sequence=10, last_ledger_sequence=20)
    agent_signed = cosigner.agent_presign(tx, agent_w)

    # Agent-only: quorum NOT met -> ledger would reject.
    from xrpl.transaction import multisign
    agent_only = multisign(tx, [agent_signed])
    total, met = cosigner.quorum_met(agent_only)
    assert total == 1 and met is False

    # Enforcer co-signs (only because the token is valid) -> quorum met.
    combined, reason = cosigner.cosign(tx, agent_signed, token, req)
    assert combined is not None
    total2, met2 = cosigner.quorum_met(combined)
    assert total2 == 2 and met2 is True


def test_role1_enforcer_refuses_on_redirect():
    env = make_env()
    agent_w, enforcer_w, funding, cosigner = _xrpl_setup(env)
    dest = Wallet.create().classic_address
    attacker = Wallet.create().classic_address
    req = build_chain(env, rail="xrpl", currency="XRP", policy_id="xrpl_treasury_v1",
                      max_amount=2_000_000, destination_account=dest, amount=1_000_000)
    _, token = env.verifier.evaluate(req)
    # Agent tries to co-sign a payment to a DIFFERENT destination than approved.
    tx = cosigner.build_payment(destination=attacker, amount_drops=1_000_000,
                                sequence=10, last_ledger_sequence=20)
    agent_signed = cosigner.agent_presign(tx, agent_w)
    combined, reason = cosigner.cosign(tx, agent_signed, token, req)
    assert combined is None and "destination" in reason.lower()


# ---------- Role 1b: MPC / threshold-signature hard gate (rail-agnostic) ----------

from signet.authorizers.mpc_cosigner import (
    MPCThresholdCosigner, ThresholdTx, setup_2of2,
    agent_commit, agent_partial, challenge, combine_scalars, group_verify,
)


def _mpc_setup(env):
    """A 2-of-2 threshold group (agent share + enforcer share). The enforcer's
    share lives only inside the cosigner; the agent never holds it."""
    group = setup_2of2()
    cosigner = MPCThresholdCosigner(env.verifier, env.enforcer_vk,
                                    enforcer_share=group.enforcer_share,
                                    group_pubkey=group.pubkey)
    return group, cosigner


def _approved_tx(env, **kw):
    req = build_chain(env, **kw)
    decision, token = env.verifier.evaluate(req)
    assert decision.approved
    tx = ThresholdTx(chain_hash=token.chain_hash,
                     destination=req.context.destination_account,
                     amount=req.context.amount, currency=req.context.currency)
    return req, token, tx


def test_role1b_threshold_requires_enforcer_share():
    # THE ATTACK: the agent holds one key share and tries to produce a settling
    # signature ALONE. The funding key is a 2-of-2 aggregate, so a signature is
    # only valid if the enforcer's share is mixed in. Without it the agent cannot
    # forge a verifying signature -- the enforcer's share is a hard requirement,
    # the rail-agnostic generalization of the XRPL co-signature.
    env = make_env()
    group, cosigner = _mpc_setup(env)
    req, token, tx = _approved_tx(env)
    msg = tx.message()

    # Agent-alone forgery: commit + partial-sign with ONLY its own share.
    r_a, R_a = agent_commit()
    c_solo = challenge(R_a, group.pubkey, msg)
    s_solo = agent_partial(r_a, group.agent_share, c_solo)
    assert not group_verify(group.pubkey, msg, R_a, s_solo)  # invalid: share missing

    # Enforcer contributes its share ONLY after token + context checks pass.
    contribution, reason = cosigner.cosign(tx, R_a, token, req)
    assert contribution is not None
    s_a = agent_partial(r_a, group.agent_share, contribution.c)
    s = combine_scalars([s_a, contribution.s_e])
    # 2-of-2 signature now verifies against the aggregate funding key.
    assert group_verify(group.pubkey, msg, contribution.R, s)


def test_role1b_enforcer_refuses_on_redirect():
    # Agent tries to get the enforcer's share for a payment to a DIFFERENT
    # destination than the approved Cart -> enforcer refuses to contribute.
    env = make_env()
    group, cosigner = _mpc_setup(env)
    req, token, _ = _approved_tx(env)
    redirected = ThresholdTx(chain_hash=token.chain_hash,
                             destination="attacker_account",
                             amount=req.context.amount,
                             currency=req.context.currency)
    _, R_a = agent_commit()
    contribution, reason = cosigner.cosign(redirected, R_a, token, req)
    assert contribution is None and "destination" in reason.lower()


def test_role1b_enforcer_refuses_amount_tamper():
    env = make_env()
    group, cosigner = _mpc_setup(env)
    req, token, _ = _approved_tx(env)
    tampered = ThresholdTx(chain_hash=token.chain_hash,
                           destination=req.context.destination_account,
                           amount=req.context.amount + 1,
                           currency=req.context.currency)
    _, R_a = agent_commit()
    contribution, reason = cosigner.cosign(tampered, R_a, token, req)
    assert contribution is None and "amount" in reason.lower()


def test_role1b_enforcer_refuses_invalid_token():
    # An unsigned/forged enforcer token must not unlock the enforcer's share.
    env = make_env()
    group, cosigner = _mpc_setup(env)
    req, token, tx = _approved_tx(env)
    token.signature = None  # forge: claim approval without the enforcer's signature
    _, R_a = agent_commit()
    contribution, reason = cosigner.cosign(tx, R_a, token, req)
    assert contribution is None and "token" in reason.lower()


# ---------- Receipts ----------

def test_receipt_chain_verifies_and_detects_tamper():
    env = make_env()
    log = ReceiptLog(env.enforcer_sk, env.enforcer_vk)
    req = build_chain(env)
    decision, token = env.verifier.evaluate(req)
    r = log.append(execution_id=token.execution_id, mandate_id=token.mandate_id,
                   chain_hash=token.chain_hash, policy_id="treasury_policy_v1",
                   decision="approved", payment_status="executed",
                   payment_ref="mockpay_tx_1", rail="mock")
    ok, _ = log.verify(r)
    assert ok
    r.payment_ref = "mockpay_tx_TAMPERED"
    ok2, _ = log.verify(r)
    assert not ok2
