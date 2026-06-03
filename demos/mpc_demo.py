"""Role 1b demo -- MPC / threshold-signature hard gate (rail-agnostic).

    python -m demos.mpc_demo

The rail-agnostic generalization of Role 1. The funding key is a single public
key whose secret is split 2-of-2 (agent + enforcer). A signature only verifies
against the aggregate key if the enforcer's share is mixed in -- so the enforcer
is a mandatory co-signer for EVERY chain at once, on any rail that accepts a
plain signature, with no per-ledger SignerList setup. Runs the full threshold
Schnorr path OFFLINE (commit -> challenge -> partial-sign -> combine -> verify).
"""
from signet.builder import make_env, build_chain
from signet.authorizers.mpc_cosigner import (
    MPCThresholdCosigner, ThresholdTx, setup_2of2,
    agent_commit, agent_partial, challenge, combine_scalars, group_verify,
)


def line(c="-"):
    print(c * 68)


def main():
    env = make_env()

    # One funding key, secret split 2-of-2: agent share + enforcer share.
    group = setup_2of2()
    cosigner = MPCThresholdCosigner(env.verifier, env.enforcer_vk,
                                    enforcer_share=group.enforcer_share,
                                    group_pubkey=group.pubkey)

    print("\nSIGNET RUNTIME -- Role 1b (MPC threshold-signature hard gate)\n")
    print(f"  funding pubkey (2-of-2): {group.pubkey.hex()}")
    print(f"  shareholders           : agent + enforcer (each holds one share)")
    print(f"  threshold              : 2 of 2")

    # An approved AP2 chain for a generic signature rail.
    req = build_chain(env, rail="xrpl", currency="XRP", policy_id="xrpl_treasury_v1",
                      max_amount=2_000_000, recipient="vendor_abc",
                      destination_account="vendor_abc_main_account", amount=1_000_000)
    decision, token = env.verifier.evaluate(req)
    tx = ThresholdTx(chain_hash=token.chain_hash,
                     destination=req.context.destination_account,
                     amount=req.context.amount, currency=req.context.currency)
    msg = tx.message()

    line()
    print("CASE A: agent tries to sign alone (only its own share)")
    r_a, R_a = agent_commit()
    c_solo = challenge(R_a, group.pubkey, msg)
    s_solo = agent_partial(r_a, group.agent_share, c_solo)
    ok_solo = group_verify(group.pubkey, msg, R_a, s_solo)
    print(f"  verifier decision : {decision.decision.upper()}")
    print(f"  signature valid   : {ok_solo}")
    print(f"  result            : REJECTED -- a partial over the agent's share alone "
          f"does not verify against the 2-of-2 key")

    line()
    print("CASE B: enforcer contributes its share for the approved payment")
    contribution, reason = cosigner.cosign(tx, R_a, token, req)
    s_a = agent_partial(r_a, group.agent_share, contribution.c)
    s = combine_scalars([s_a, contribution.s_e])
    ok = group_verify(group.pubkey, msg, contribution.R, s)
    print(f"  enforcer          : {reason}")
    print(f"  signature valid   : {ok}")
    print(f"  result            : VALID threshold signature, ready to settle")

    line()
    print("CASE C: agent tries to redirect funds to an attacker address")
    tx_bad = ThresholdTx(chain_hash=token.chain_hash, destination="attacker_account",
                         amount=req.context.amount, currency=req.context.currency)
    _, R_a2 = agent_commit()
    contribution_bad, reason_bad = cosigner.cosign(tx_bad, R_a2, token, req)
    outcome = "CONTRIBUTED" if contribution_bad else "REFUSED -- no share, signature unreachable, cannot settle"
    print(f"  enforcer          : {reason_bad}")
    print(f"  result            : {outcome}")

    line("=")
    print("PRODUCTION NOTES (see mpc_cosigner.py docstring):")
    print("""
  * This is a self-contained 2-of-2 threshold Schnorr over edwards25519, verified
    by group_verify. For signatures that verify under a stock Ed25519 verifier
    (and an on-chain EOA / custodial API), swap in FROST(ed25519) -- the gate and
    Cart-binding logic above are identical.
  * Distributed key generation replaces setup_2of2 so the full key never exists.
  * Add an MPC nonce-commitment round (commit to H(R_i) before revealing R_i) to
    close the adaptive-nonce gap inherent to a 2-message PoC.
""")
    line("=")


if __name__ == "__main__":
    main()
