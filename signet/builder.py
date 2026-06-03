"""Test/demo helpers: build a fully-signed, internally-consistent mandate chain,
plus an environment (verifier + policy + keys). Override hooks let tests mutate
one field to create each attack variant.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from . import chain, crypto
from .canonical import canonical_json
from .models import (CartMandate, ExecutionRequest, FundingInstrument,
                     IntentMandate, PaymentMandate, RuntimeContext)
from .nonce import NonceRegistry
from .policy import Policy, PolicyEngine
from .revocation import RevocationRegistry
from .verifier import Verifier


@dataclass
class Env:
    verifier: Verifier
    keystore: crypto.KeyStore
    policy: PolicyEngine
    revocation: RevocationRegistry
    nonces: NonceRegistry
    principal_sk: str
    principal_vk: str
    enforcer_sk: str
    enforcer_vk: str
    clock: Callable[[], datetime]


def make_env(now: Optional[datetime] = None) -> Env:
    now = now or datetime(2026, 5, 30, 12, 0, 0, tzinfo=timezone.utc)
    clock = lambda: now

    principal_sk, principal_vk = crypto.generate_keypair()
    enforcer_sk, enforcer_vk = crypto.generate_keypair()

    keystore = crypto.KeyStore()
    keystore.register("acme_cfo", principal_vk)

    policy = PolicyEngine()
    policy.add(Policy(
        policy_id="treasury_policy_v1",
        max_amount_per_transaction=5000,
        max_amount_per_day=10000,
        allowed_recipients=["vendor_abc", "vendor_xyz"],
        allowed_currencies=["EUR"],
        allowed_actions=["pay_invoice"],
        require_human_approval_above=None,
    ))
    # A policy for the XRPL settlement leg (amounts in drops, currency XRP).
    policy.add(Policy(
        policy_id="xrpl_treasury_v1",
        max_amount_per_transaction=2_000_000,
        max_amount_per_day=5_000_000,
        allowed_recipients=["vendor_abc", "vendor_xyz"],
        allowed_currencies=["XRP"],
        allowed_actions=["pay_invoice"],
        require_human_approval_above=None,
    ))

    nonces = NonceRegistry()
    revocation = RevocationRegistry()
    verifier = Verifier(keystore, nonces, revocation, policy,
                        enforcer_signing_key=enforcer_sk, clock=clock)

    return Env(verifier, keystore, policy, revocation, nonces,
               principal_sk, principal_vk, enforcer_sk, enforcer_vk, clock)


def build_chain(
    env: Env,
    *,
    amount: int = 4800,
    currency: str = "EUR",
    intent_currency: Optional[str] = None,
    policy_id: str = "treasury_policy_v1",
    max_amount: int = 5000,
    recipient: str = "vendor_abc",
    destination_account: str = "vendor_abc_main_account",
    action: str = "pay_invoice",
    scope: str = "pay_invoice",
    agent_id: str = "invoice_agent_01",
    nonce: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    valid_until: Optional[datetime] = None,
    rail: str = "mock",
    # runtime-only overrides (to diverge runtime context from the signed cart):
    ctx_recipient: Optional[str] = None,
    ctx_destination: Optional[str] = None,
    ctx_amount: Optional[int] = None,
    # chain-tamper override (swap a cart field AFTER signing -> breaks signature):
    tamper_cart_amount: Optional[int] = None,
    # break chain linkage while keeping all signatures valid:
    break_linkage: bool = False,
) -> ExecutionRequest:
    now = env.clock()
    nonce = nonce or "nonce_" + uuid.uuid4().hex[:8]
    valid_from = valid_from or (now - timedelta(hours=1))
    valid_until = valid_until or (now + timedelta(days=30))

    intent = IntentMandate(
        mandate_id="mandate_" + uuid.uuid4().hex[:8],
        principal_id="acme_cfo",
        agent_id=agent_id,
        scope=scope,
        allowed_actions=["pay_invoice"],
        max_amount=max_amount,
        currency=intent_currency or currency,
        allowed_recipients=["vendor_abc", "vendor_xyz"],
        valid_from=valid_from,
        valid_until=valid_until,
        nonce=nonce,
        policy_id=policy_id,
        prompt_playback="Pay approved supplier invoices up to the mandate cap.",
    )
    intent.signature = crypto.sign(env.principal_sk,
                                   canonical_json(intent.signing_payload()))

    cart = CartMandate(
        cart_id="cart_" + uuid.uuid4().hex[:8],
        intent_mandate_id=intent.mandate_id,
        intent_hash=chain.intent_hash(intent),
        agent_id=agent_id,
        merchant_id="merchant_acme",
        action=action,
        recipient=recipient,
        amount=amount,
        currency=currency,
        destination_account=destination_account,
        invoice_id="INV-8821",
    )
    cart.signature = crypto.sign(env.principal_sk,
                                 canonical_json(cart.signing_payload()))

    # Optional post-signature tamper: change the amount WITHOUT re-signing,
    # simulating tampering with a signed Cart -> caught by the signature check.
    if tamper_cart_amount is not None:
        cart.amount = tamper_cart_amount

    payment_cart_hash = chain.cart_hash(cart)
    if break_linkage:
        # Payment commits to a different Cart than the one supplied (all sigs
        # still valid) -> caught by chain-linkage recomputation.
        payment_cart_hash = "sha256:stale_cart_" + uuid.uuid4().hex[:8]

    payment = PaymentMandate(
        payment_id="pay_" + uuid.uuid4().hex[:8],
        cart_id=cart.cart_id,
        cart_hash=payment_cart_hash,
        intent_hash=chain.intent_hash(intent),
        amount=amount,
        currency=currency,
        funding_instrument=FundingInstrument(rail=rail, token="tok_xxx"),
    )

    ctx = RuntimeContext(
        task_id="task_" + uuid.uuid4().hex[:6],
        agent_id=agent_id,
        merchant_id="merchant_acme",
        scope=scope,
        action=action,
        recipient=ctx_recipient or recipient,
        amount=ctx_amount if ctx_amount is not None else amount,
        currency=currency,
        destination_account=ctx_destination or destination_account,
        rail=rail,
    )

    return ExecutionRequest(
        request_id="req_" + uuid.uuid4().hex[:8],
        intent=intent, cart=cart, payment=payment, context=ctx,
    )
