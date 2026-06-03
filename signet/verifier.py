"""The runtime verifier -- the security kernel.

Ordering is deliberate: cheap, deterministic, attacker-unfalsifiable checks run
first; the single stateful write (consume-once) runs LAST, just before issuing
the token. Verifying signatures before touching the nonce registry prevents a
cheap registry-flooding DoS.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from . import chain, crypto
from .canonical import canonical_json
from .models import Decision, ExecutionRequest, ExecutionToken
from .nonce import NonceRegistry
from .policy import PolicyEngine
from .revocation import RevocationRegistry


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Verifier:
    def __init__(
        self,
        keystore: crypto.KeyStore,
        nonces: NonceRegistry,
        revocation: RevocationRegistry,
        policy: PolicyEngine,
        enforcer_signing_key: str,
        token_ttl_seconds: int = 120,
        clock: Callable[[], datetime] = _utcnow,
    ):
        self.keystore = keystore
        self.nonces = nonces
        self.revocation = revocation
        self.policy = policy
        self.enforcer_signing_key = enforcer_signing_key
        self.token_ttl_seconds = token_ttl_seconds
        self.clock = clock

    # -- helpers --

    def _verify_principal_sig(self, principal_id: str, payload: dict,
                              signature: Optional[str]) -> bool:
        vk = self.keystore.verify_key_for(principal_id)
        if vk is None or signature is None:
            return False
        return crypto.verify(vk, canonical_json(payload), signature)

    def _issue_token(self, mandate_id: str, ch: str, nonce: str,
                     now: datetime) -> ExecutionToken:
        token = ExecutionToken(
            execution_id="exec_" + uuid.uuid4().hex[:12],
            mandate_id=mandate_id,
            chain_hash=ch,
            nonce=nonce,
            expires_at=now + timedelta(seconds=self.token_ttl_seconds),
        )
        token.signature = crypto.sign(
            self.enforcer_signing_key, canonical_json(token.signing_payload())
        )
        return token

    # -- the pipeline --

    def evaluate(self, req: ExecutionRequest):
        """Return (Decision, ExecutionToken | None)."""
        now = self.clock()
        intent, cart, payment, ctx = req.intent, req.cart, req.payment, req.context

        def blocked(reason: str):
            return Decision(decision="blocked", reason=reason), None

        # 1. Signatures (principal signs Intent and Cart in this PoC).
        if not self._verify_principal_sig(intent.principal_id,
                                          intent.signing_payload(), intent.signature):
            return blocked("Invalid Intent mandate signature.")
        if not self._verify_principal_sig(intent.principal_id,
                                          cart.signing_payload(), cart.signature):
            return blocked("Invalid Cart mandate signature.")

        # 2. Chain linkage (recompute every hash link).
        ok, reason = chain.verify_linkage(intent, cart, payment)
        if not ok:
            return blocked(reason)

        # 3. Agent identity consistency across the chain + runtime.
        if not (intent.agent_id == cart.agent_id == ctx.agent_id):
            return blocked("Agent identity mismatch across chain/runtime (confused deputy).")

        # 4. Action allowed by the Intent, and consistent at runtime.
        if cart.action not in intent.allowed_actions:
            return blocked(f"Action '{cart.action}' not in Intent.allowed_actions.")
        if ctx.action != cart.action or ctx.scope != intent.scope:
            return blocked("Runtime action/scope does not match the mandate.")

        # 5. Freshness / TTL (verifier-authoritative clock).
        if now < intent.valid_from:
            return blocked("Mandate not yet valid.")
        if now > intent.valid_until:
            return blocked("Mandate expired.")

        # 6. Revocation (checked at execution time).
        if self.revocation.is_revoked(intent.mandate_id):
            return blocked("Mandate revoked.")

        # 7. Context binding: runtime context must match what the Cart committed to.
        if chain.context_hash_from_runtime(ctx) != chain.context_hash_from_cart(cart):
            return blocked("Execution context does not match the approved Cart "
                           "(recipient/destination/merchant substitution or context redirect).")

        # 8. Exactness: amount/currency at runtime == cart, and within Intent cap.
        if ctx.amount != cart.amount or ctx.currency != cart.currency:
            return blocked("Runtime amount/currency does not match the Cart.")
        if cart.amount > intent.max_amount or cart.currency != intent.currency:
            return blocked("Cart exceeds Intent amount/currency bound.")
        if cart.recipient not in intent.allowed_recipients:
            return blocked("Recipient not in Intent allowlist.")

        # 9. Enterprise policy (caps, allowlist, currency, velocity, human-approval).
        pol = self.policy.evaluate(intent, cart, ctx, now=now)
        if not pol.ok:
            return Decision(decision="blocked", reason=pol.reason), None

        # 10. Atomic consume-once on the EXACT transaction -- the LAST gate
        #     before issuing the capability. Replaying the identical bound
        #     transaction is rejected; distinct carts under the same Intent are
        #     allowed (subject to velocity). XRPL's sequence number is the
        #     on-ledger analogue of this check.
        ch = chain.chain_hash(intent, cart, payment)
        if not self.nonces.consume_once(ch,
                                        ttl_seconds=self.token_ttl_seconds, now=now):
            return blocked("Replay detected: this exact transaction was already executed.")

        # 11. Record velocity spend (per principal) and issue the signed token.
        self.policy.record_spend(intent.principal_id, cart.amount, now=now)
        token = self._issue_token(intent.mandate_id, ch, intent.nonce, now)

        return Decision(
            decision="approved",
            reason="Intent/Cart/Payment chain satisfied; bound and consumed once.",
            chain_hash=ch,
            execution_id=token.execution_id,
            nonce=intent.nonce,
            expires_at=token.expires_at,
        ), token

    def verify_token(self, token: ExecutionToken,
                     enforcer_verify_key: str) -> bool:
        """An authorizer calls this before producing any rail capability."""
        if token.signature is None:
            return False
        if self.clock() > token.expires_at:
            return False
        return crypto.verify(
            enforcer_verify_key, canonical_json(token.signing_payload()), token.signature
        )
