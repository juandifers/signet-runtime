"""Chain hashing + linkage integrity + context binding.

The interesting context-binding surface in AP2 is not a single context hash but
*chain linkage*: does the Cart satisfy/reference the Intent, and does the
Payment Mandate's embedded hash match the exact Cart that was approved? A naive
implementation verifies three signatures independently and never recomputes the
linkage -- which is exactly where a Cart-substitution attack lives.
"""
from __future__ import annotations

from .canonical import hash_obj
from .models import CartMandate, IntentMandate, PaymentMandate, RuntimeContext


def intent_hash(intent: IntentMandate) -> str:
    return hash_obj(intent.signing_payload())


def cart_hash(cart: CartMandate) -> str:
    return hash_obj(cart.signing_payload())


def context_hash_from_cart(cart: CartMandate) -> str:
    """The context the Cart commits to."""
    return hash_obj({
        "agent_id": cart.agent_id,
        "merchant_id": cart.merchant_id,
        "scope_action": cart.action,
        "recipient": cart.recipient,
        "amount": cart.amount,
        "currency": cart.currency,
        "destination_account": cart.destination_account,
    })


def context_hash_from_runtime(ctx: RuntimeContext) -> str:
    """The context reconstructed from what the agent presents at execution."""
    return hash_obj({
        "agent_id": ctx.agent_id,
        "merchant_id": ctx.merchant_id,
        "scope_action": ctx.action,
        "recipient": ctx.recipient,
        "amount": ctx.amount,
        "currency": ctx.currency,
        "destination_account": ctx.destination_account,
    })


def chain_hash(intent: IntentMandate, cart: CartMandate,
               payment: PaymentMandate) -> str:
    return hash_obj({
        "intent_hash": intent_hash(intent),
        "cart_hash": cart_hash(cart),
        "payment_id": payment.payment_id,
        "amount": payment.amount,
        "currency": payment.currency,
        "rail": payment.funding_instrument.rail,
    })


def verify_linkage(intent: IntentMandate, cart: CartMandate,
                   payment: PaymentMandate) -> tuple[bool, str]:
    """Recompute every hash link in the chain. Fail closed on any mismatch."""
    ih = intent_hash(intent)
    ch = cart_hash(cart)

    if cart.intent_mandate_id != intent.mandate_id:
        return False, "Cart references a different Intent mandate_id."
    if cart.intent_hash != ih:
        return False, "Cart.intent_hash does not match the supplied Intent (Cart substitution)."
    if payment.cart_id != cart.cart_id:
        return False, "Payment references a different Cart."
    if payment.cart_hash != ch:
        return False, "Payment.cart_hash does not match the supplied Cart (Cart substitution)."
    if payment.intent_hash != ih:
        return False, "Payment.intent_hash does not match the supplied Intent."
    if payment.amount != cart.amount or payment.currency != cart.currency:
        return False, "Payment amount/currency does not match the Cart."
    return True, "Chain linkage intact."
