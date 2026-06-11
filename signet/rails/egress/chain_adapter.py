"""Serialize an `EgressEffect` into the kernel's AP2 ExecutionRequest and mint a token through
the UNCHANGED kernel `Verifier` — the exact pattern DbBrokerCore uses for the DB rail.

The kernel gives us, with zero kernel edits, the signed token, the TTL, and atomic consume-once
keyed on `chain_hash`. The egress authorization decision is NOT the kernel policy — it is the
EgressAuthorizer's recheck against the frozen mandate. The chain is built by the broker from the
connection attempt, so it is self-consistent by construction and the kernel admits it.

`resolved_ip` is excluded from the chain (binding is host+port); only `bound_dict()` rides in.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ... import chain, crypto
from ...canonical import canonical_json, hash_obj
from ...models import (CartMandate, Decision, ExecutionRequest, ExecutionToken,
                       FundingInstrument, IntentMandate, PaymentMandate, RuntimeContext)
from ...nonce import NonceRegistry
from ...policy import Policy, PolicyEngine
from ...revocation import RevocationRegistry
from ...verifier import Verifier
from .effect import EgressEffect

RAIL = "egress"
CURRENCY = "EGRESS"
PRINCIPAL_ID = "signet_broker_principal"
POLICY_ID = "egress_broker_policy_v1"

# DO NOT set these to now(): wall-clock in the chain breaks consume-once across time (a replay at
# a later clock would get a fresh chain_hash and slip through). See the broker-slice report
# finding. The capability's real lifetime is the token TTL + admission, not this window.
_VALID_FROM = _dt.datetime(2000, 1, 1, tzinfo=_dt.timezone.utc)
_VALID_UNTIL = _dt.datetime(2100, 1, 1, tzinfo=_dt.timezone.utc)


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _det_id(prefix: str, *parts: str) -> str:
    return prefix + hash_obj(list(parts))[:16]


@dataclass
class EgressBrokerCore:
    """Long-lived enforcer/principal keys + the SHARED nonce registry (replay detection persists
    across connections). One per broker process. Mirrors DbBrokerCore."""
    keystore: crypto.KeyStore
    nonces: NonceRegistry
    revocation: RevocationRegistry
    principal_sk: str
    enforcer_sk: str
    enforcer_vk: str
    clock: Callable[[], _dt.datetime]
    token_ttl_seconds: int = 60

    @classmethod
    def create(cls, clock: Optional[Callable[[], _dt.datetime]] = None,
               token_ttl_seconds: int = 60) -> "EgressBrokerCore":
        clock = clock or _utcnow
        principal_sk, principal_vk = crypto.generate_keypair()
        enforcer_sk, enforcer_vk = crypto.generate_keypair()
        keystore = crypto.KeyStore()
        keystore.register(PRINCIPAL_ID, principal_vk)
        return cls(keystore, NonceRegistry(), RevocationRegistry(),
                   principal_sk, enforcer_sk, enforcer_vk, clock, token_ttl_seconds)

    def _verifier_for(self, effect: EgressEffect) -> Verifier:
        policy = PolicyEngine()
        policy.add(Policy(
            policy_id=POLICY_ID,
            max_amount_per_transaction=0,
            max_amount_per_day=0,
            allowed_recipients=[effect.target()],
            allowed_currencies=[CURRENCY],
            allowed_actions=[f"egress.{effect.protocol}"],
            require_human_approval_above=None,
        ))
        return Verifier(self.keystore, self.nonces, self.revocation, policy,
                        enforcer_signing_key=self.enforcer_sk,
                        token_ttl_seconds=self.token_ttl_seconds, clock=self.clock)

    def build_request(self, effect: EgressEffect, task_id: str, agent_id: str,
                      request_nonce: str = "") -> ExecutionRequest:
        seed = (task_id, effect.effect_hash(), request_nonce)
        blob = canonical_json(effect.bound_dict()).decode()    # host+port+protocol, NO ip
        nonce = _det_id("n_", *seed)

        intent = IntentMandate(
            mandate_id=_det_id("m_", *seed),
            principal_id=PRINCIPAL_ID,
            agent_id=agent_id,
            scope=RAIL,
            allowed_actions=[f"egress.{effect.protocol}"],
            max_amount=0,
            currency=CURRENCY,
            allowed_recipients=[effect.target()],
            valid_from=_VALID_FROM,
            valid_until=_VALID_UNTIL,
            nonce=nonce,
            policy_id=POLICY_ID,
            prompt_playback=f"egress {effect.protocol} to {effect.target()} for task {task_id}",
        )
        intent.signature = crypto.sign(self.principal_sk,
                                       canonical_json(intent.signing_payload()))

        cart = CartMandate(
            cart_id=_det_id("c_", *seed),
            intent_mandate_id=intent.mandate_id,
            intent_hash=chain.intent_hash(intent),
            agent_id=agent_id,
            merchant_id=RAIL,
            action=f"egress.{effect.protocol}",
            recipient=effect.target(),
            amount=0,
            currency=CURRENCY,
            destination_account=blob,
            invoice_id=None,
        )
        cart.signature = crypto.sign(self.principal_sk,
                                     canonical_json(cart.signing_payload()))

        payment = PaymentMandate(
            payment_id=_det_id("p_", *seed),
            cart_id=cart.cart_id,
            cart_hash=chain.cart_hash(cart),
            intent_hash=chain.intent_hash(intent),
            amount=0,
            currency=CURRENCY,
            funding_instrument=FundingInstrument(rail=RAIL, token="cap"),
        )

        ctx = RuntimeContext(
            task_id=task_id, agent_id=agent_id, merchant_id=RAIL, scope=RAIL,
            action=f"egress.{effect.protocol}", recipient=effect.target(),
            amount=0, currency=CURRENCY, destination_account=blob, rail=RAIL,
        )

        return ExecutionRequest(request_id=_det_id("req_", *seed),
                                intent=intent, cart=cart, payment=payment, context=ctx)

    def mint_token(self, effect: EgressEffect, task_id: str, agent_id: str,
                   request_nonce: str = "") -> Tuple[Decision, Optional[ExecutionToken],
                                                      ExecutionRequest, Verifier]:
        verifier = self._verifier_for(effect)
        req = self.build_request(effect, task_id, agent_id, request_nonce)
        decision, token = verifier.evaluate(req)
        return decision, token, req, verifier


def effect_from_request(req: ExecutionRequest) -> EgressEffect:
    import json
    return EgressEffect.from_bound_dict(json.loads(req.cart.destination_account))
