"""Serialize a `DbEffect` into the kernel's AP2 ExecutionRequest, and mint a token through the
UNCHANGED kernel `Verifier`.

This is the "DB effect must serialize into this model" seam. The broker does NOT fork the
kernel: it encodes the requested effect as a fully self-consistent Intent->Cart->Payment chain
and runs the real `Verifier.evaluate`, which gives us — for free, with zero kernel edits — the
signed `ExecutionToken`, the verifier-authoritative TTL, and atomic consume-once keyed on
`chain_hash` (kernel invariant #4).

Why a permissive chain is correct here: the chain is built by the broker FROM the agent's
request, so it is internally consistent by construction and the kernel admits it (exactly the
"self-consistent correctly-signed chain" CLAUDE.md says the kernel passes). The REAL
authorization gate is NOT the kernel policy — it is the Supabase authorizer's
`recheck_against_context`, which re-checks the requested effect against the operator's FROZEN
task mandate (trusted input the agent cannot forge). The kernel's job is only: bind + sign +
consume-once.

All chain identifiers are derived DETERMINISTICALLY from (task_id, effect, request_nonce) so an
identical capability request collides on `chain_hash` and is rejected as a replay; a distinct
effect (or a distinct caller-supplied request_nonce) gets a fresh hash.
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
from .effect import DbEffect

RAIL = "supabase"
CURRENCY = "DBOP"                         # DB operations carry no monetary amount
PRINCIPAL_ID = "signet_broker_principal"
POLICY_ID = "db_broker_policy_v1"


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _det_id(prefix: str, *parts: str) -> str:
    return prefix + hash_obj(list(parts))[:16]


@dataclass
class DbBrokerCore:
    """Holds the long-lived enforcer/principal keys and the SHARED nonce registry (so replay
    detection persists across requests). One per broker process."""
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
               token_ttl_seconds: int = 60) -> "DbBrokerCore":
        clock = clock or _utcnow
        principal_sk, principal_vk = crypto.generate_keypair()
        enforcer_sk, enforcer_vk = crypto.generate_keypair()
        keystore = crypto.KeyStore()
        keystore.register(PRINCIPAL_ID, principal_vk)
        return cls(keystore, NonceRegistry(), RevocationRegistry(),
                   principal_sk, enforcer_sk, enforcer_vk, clock, token_ttl_seconds)

    def _verifier_for(self, effect: DbEffect) -> Verifier:
        """A per-request Verifier whose policy admits exactly this effect (the chain is
        self-consistent by construction). Shares the long-lived nonce registry + keys so
        consume-once and token signatures are stable across requests."""
        policy = PolicyEngine()
        policy.add(Policy(
            policy_id=POLICY_ID,
            max_amount_per_transaction=0,
            max_amount_per_day=0,
            allowed_recipients=[effect.target()],
            allowed_currencies=[CURRENCY],
            allowed_actions=[f"db.{effect.op}"],
            require_human_approval_above=None,
        ))
        return Verifier(self.keystore, self.nonces, self.revocation, policy,
                        enforcer_signing_key=self.enforcer_sk,
                        token_ttl_seconds=self.token_ttl_seconds, clock=self.clock)

    def build_request(self, effect: DbEffect, task_id: str, agent_id: str,
                      request_nonce: str = "") -> ExecutionRequest:
        seed = (task_id, effect.effect_hash(), request_nonce)
        blob = canonical_json(effect.to_dict()).decode()
        nonce = _det_id("n_", *seed)
        # The validity window is FIXED (not clock-derived) so chain_hash is time-independent and
        # an identical request always collides for consume-once. The capability's real lifetime
        # is the token TTL + the JWT exp, not this window — this window only has to be wide.
        valid_from = _dt.datetime(2000, 1, 1, tzinfo=_dt.timezone.utc)
        valid_until = _dt.datetime(2100, 1, 1, tzinfo=_dt.timezone.utc)

        intent = IntentMandate(
            mandate_id=_det_id("m_", *seed),
            principal_id=PRINCIPAL_ID,
            agent_id=agent_id,
            scope=effect.database,
            allowed_actions=[f"db.{effect.op}"],
            max_amount=0,
            currency=CURRENCY,
            allowed_recipients=[effect.target()],
            valid_from=valid_from,
            valid_until=valid_until,
            nonce=nonce,
            policy_id=POLICY_ID,
            prompt_playback=f"DB {effect.op} on {effect.target()} for task {task_id}",
        )
        intent.signature = crypto.sign(self.principal_sk,
                                       canonical_json(intent.signing_payload()))

        cart = CartMandate(
            cart_id=_det_id("c_", *seed),
            intent_mandate_id=intent.mandate_id,
            intent_hash=chain.intent_hash(intent),
            agent_id=agent_id,
            merchant_id=effect.database,
            action=f"db.{effect.op}",
            recipient=effect.target(),
            amount=0,
            currency=CURRENCY,
            destination_account=blob,          # the canonical effect rides here (cart == ctx)
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
            task_id=task_id,
            agent_id=agent_id,
            merchant_id=effect.database,
            scope=effect.database,
            action=f"db.{effect.op}",
            recipient=effect.target(),
            amount=0,
            currency=CURRENCY,
            destination_account=blob,
            rail=RAIL,
        )

        return ExecutionRequest(
            request_id=_det_id("req_", *seed),
            intent=intent, cart=cart, payment=payment, context=ctx,
        )

    def mint_token(self, effect: DbEffect, task_id: str, agent_id: str,
                   request_nonce: str = "") -> Tuple[Decision, Optional[ExecutionToken],
                                                      ExecutionRequest, Verifier]:
        """Run the UNCHANGED kernel verifier over the serialized DB effect.
        Returns (decision, token, request, verifier-bound-to-this-request)."""
        verifier = self._verifier_for(effect)
        req = self.build_request(effect, task_id, agent_id, request_nonce)
        decision, token = verifier.evaluate(req)
        return decision, token, req, verifier


def effect_from_request(req: ExecutionRequest) -> DbEffect:
    """Recover the bound DB effect from the (kernel-validated) Cart blob."""
    import json
    return DbEffect.from_dict(json.loads(req.cart.destination_account))
