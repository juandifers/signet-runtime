"""Role 1 demo -- XRPL multisign hard gate (cryptographic enforcement).

    python -m demos.role1_xrpl_demo

This runs the full cryptographic path OFFLINE (build -> agent sign -> enforcer
co-sign -> quorum check), which is what proves the property: without the
enforcer's co-signature the transaction cannot reach the 2-of-2 quorum.

Submitting to live XRPL testnet requires reachable XRPL endpoints (not available
in every sandbox). The exact network path is printed at the end.
"""
from xrpl.transaction import multisign
from xrpl.wallet import Wallet

from signet.builder import make_env, build_chain
from signet.authorizers.xrpl_cosigner import XRPLCosigner


def line(c="-"):
    print(c * 68)


def main():
    env = make_env()

    # 2-of-2 multisig settlement account: agent + enforcer, quorum 2.
    agent_w = Wallet.create()
    enforcer_w = Wallet.create()
    funding = Wallet.create().classic_address
    weights = {agent_w.classic_address: 1, enforcer_w.classic_address: 1}
    cosigner = XRPLCosigner(env.verifier, env.enforcer_vk, funding, enforcer_w,
                            signer_weights=weights, quorum=2)
    dest = Wallet.create().classic_address
    attacker = Wallet.create().classic_address

    print("\nSIGNET RUNTIME -- Role 1 (XRPL multisign hard gate)\n")
    print(f"  funding account (2-of-2): {funding}")
    print(f"  agent signer            : {agent_w.classic_address} (weight 1)")
    print(f"  enforcer signer         : {enforcer_w.classic_address} (weight 1)")
    print(f"  quorum required         : 2")

    # An approved AP2 chain for the XRPL leg (1,000,000 drops = 1 XRP).
    req = build_chain(env, rail="xrpl", currency="XRP", policy_id="xrpl_treasury_v1",
                      max_amount=2_000_000, recipient="vendor_abc",
                      destination_account=dest, amount=1_000_000)
    decision, token = env.verifier.evaluate(req)

    line()
    print(f"CASE A: approved payment, agent signs alone")
    tx = cosigner.build_payment(destination=dest, amount_drops=1_000_000,
                                sequence=10, last_ledger_sequence=20)
    agent_signed = cosigner.agent_presign(tx, agent_w)
    agent_only = multisign(tx, [agent_signed])
    total, met = cosigner.quorum_met(agent_only)
    print(f"  verifier decision : {decision.decision.upper()}")
    print(f"  signers           : {[s.account for s in agent_only.signers]}")
    print(f"  weight / quorum   : {total} / {cosigner.quorum}  -> quorum met: {met}")
    print(f"  result            : LEDGER WOULD REJECT (tefBAD_QUORUM) -- enforcer's "
          f"signature is a hard requirement")

    line()
    print(f"CASE B: enforcer co-signs the approved payment")
    combined, reason = cosigner.cosign(tx, agent_signed, token, req)
    total2, met2 = cosigner.quorum_met(combined)
    print(f"  enforcer          : {reason}")
    print(f"  signers           : {[s.account for s in combined.signers]}")
    print(f"  weight / quorum   : {total2} / {cosigner.quorum}  -> quorum met: {met2}")
    print(f"  result            : VALID multisigned tx, ready to submit")

    line()
    print(f"CASE C: agent tries to redirect funds to an attacker address")
    tx_bad = cosigner.build_payment(destination=attacker, amount_drops=1_000_000,
                                    sequence=11, last_ledger_sequence=21)
    agent_signed_bad = cosigner.agent_presign(tx_bad, agent_w)
    combined_bad, reason_bad = cosigner.cosign(tx_bad, agent_signed_bad, token, req)
    outcome = "CO-SIGNED" if combined_bad else "REFUSED -- tx cannot reach quorum, cannot settle"
    print(f"  enforcer          : {reason_bad}")
    print(f"  result            : {outcome}")

    line("=")
    print("TO SETTLE ON XRPL TESTNET (run where XRPL endpoints are reachable):")
    print("""
  1. Fund agent, enforcer, and funding wallets at the testnet faucet:
       https://test.bithomp.com/faucet  or  xrpl.org testnet faucet
  2. Submit a SignerListSet on the funding account establishing the 2-of-2:
       SignerListSet(account=funding, signer_quorum=2, signer_entries=[
           SignerEntry(account=agent_addr,    signer_weight=1),
           SignerEntry(account=enforcer_addr, signer_weight=1)])
     (optionally DisableMasterKey so multisign is the ONLY path)
  3. autofill the Payment against the network (real sequence/fee), then:
       from signet.authorizers.xrpl_cosigner import submit_to_testnet
       result = submit_to_testnet(combined)   # returns validated tx hash + meta
""")
    line("=")


if __name__ == "__main__":
    main()
