"""Role 1 -- the cryptographic hard gate: XRPL multisign co-signer.

The settlement account is a 2-of-2 multisig (agent + enforcer). A Payment is
only valid on the ledger if the summed weight of valid signers meets the
SignerQuorum. The enforcer contributes its signature ONLY after the verifier
approves and ONLY for the exact approved payment. Without the enforcer's
co-signature the transaction cannot reach quorum -- so the rail itself, not an
adapter check, is the fail-closed point. XRPL's per-account sequence number is
the native on-ledger consume-once primitive complementing our nonce registry.

This sandbox cannot reach XRPL testnet (egress is limited to PyPI/GitHub), so
`authorize()` runs the full cryptographic path offline (build -> agent sign ->
enforcer co-sign -> quorum check). `submit_to_testnet()` is the network path to
run where XRPL endpoints are reachable.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from xrpl.models.transactions import Payment
from xrpl.transaction import multisign, sign
from xrpl.wallet import Wallet

from .base import AuthorizationResult, Authorizer
from ..models import ExecutionRequest, ExecutionToken


class XRPLCosigner(Authorizer):
    rail = "xrpl"

    def __init__(self, verifier, enforcer_verify_key: str,
                 funding_account: str, enforcer_wallet: Wallet,
                 signer_weights: Dict[str, int], quorum: int):
        self._verifier = verifier
        self._enforcer_vk = enforcer_verify_key
        self.funding_account = funding_account
        self.enforcer_wallet = enforcer_wallet
        self.signer_weights = signer_weights      # {classic_address: weight}
        self.quorum = quorum

    # -- transaction construction --

    def build_payment(self, destination: str, amount_drops: int,
                      sequence: int, fee: str = "100",
                      last_ledger_sequence: Optional[int] = None) -> Payment:
        return Payment(
            account=self.funding_account,
            destination=destination,
            amount=str(amount_drops),
            sequence=sequence,
            fee=fee,
            last_ledger_sequence=last_ledger_sequence,
            signing_pub_key="",  # required empty for multisigned transactions
        )

    @staticmethod
    def agent_presign(tx: Payment, agent_wallet: Wallet) -> Payment:
        return sign(tx, agent_wallet, multisign=True)

    def quorum_met(self, combined: Payment) -> Tuple[int, bool]:
        total = 0
        for s in (combined.signers or []):
            total += self.signer_weights.get(s.account, 0)
        return total, total >= self.quorum

    # -- the enforcement step --

    def cosign(self, tx: Payment, agent_signed: Payment, token: ExecutionToken,
               req: ExecutionRequest) -> Tuple[Optional[Payment], str]:
        """Enforcer co-signs ONLY a valid, approved, exactly-matching payment."""
        if not self._verifier.verify_token(token, self._enforcer_vk):
            return None, "Enforcer token invalid/expired -- refusing to co-sign."
        # Bind the on-ledger action to the approved AP2 context (no redirection).
        if tx.destination != req.context.destination_account:
            return None, "XRPL destination does not match approved Cart -- refusing to co-sign."
        if tx.amount != str(req.context.amount):
            return None, "XRPL amount does not match approved Cart -- refusing to co-sign."
        enforcer_signed = sign(tx, self.enforcer_wallet, multisign=True)
        combined = multisign(tx, [agent_signed, enforcer_signed])
        return combined, "Enforcer co-signed; quorum reachable."

    def authorize(self, token: ExecutionToken,
                  req: ExecutionRequest) -> AuthorizationResult:
        # The 2-of-2 co-sign path needs the agent's pre-signed tx, so this rail deliberately
        # OVERRIDES the base template (its real entry point is `cosign(tx, agent_signed, ...)`,
        # a different signature). Bringing cosign under an analogous template is a separate pass
        # (it has the SAME verify_token + re-check convention gap, by design noted, not yet closed).
        raise NotImplementedError(
            "Use build_payment/agent_presign/cosign explicitly, or the demo helper."
        )

    # The base ABC now declares these hooks; the cosign path does not use the single-arg template,
    # so they are stubs that point at `cosign`. (Implemented only to keep the class instantiable.)
    def recheck_against_context(self, token, req):
        raise NotImplementedError("XRPL uses cosign(tx, agent_signed, token, req).")

    def produce_capability(self, token, req):
        raise NotImplementedError("XRPL uses cosign(tx, agent_signed, token, req).")


def submit_to_testnet(combined: Payment,
                      json_rpc_url: str = "https://s.altnet.rippletest.net:51234/"):
    """Network path -- run where XRPL testnet is reachable (NOT in this sandbox).

        from xrpl.clients import JsonRpcClient
        from xrpl.transaction import submit_and_wait
        client = JsonRpcClient(json_rpc_url)
        response = submit_and_wait(combined, client)
        return response.result   # contains validated 'hash' and 'meta'

    For setup you would also (one time, on the funding account):
      * fund agent + enforcer + funding wallets via the testnet faucet
      * submit a SignerListSet on the funding account establishing the 2-of-2
      * (optionally) DisableMasterKey so multisign is the only path
    """
    from xrpl.clients import JsonRpcClient
    from xrpl.transaction import submit_and_wait

    client = JsonRpcClient(json_rpc_url)
    response = submit_and_wait(combined, client)
    return response.result
