"""Data models for the AP2-shaped mandate chain and Signet runtime objects.

AP2 represents a transaction as a chain of three signed Verifiable Credentials:
  IntentMandate  -> what the principal authorized (scope, caps, allowlist, TTL)
  CartMandate    -> the specific assembled transaction, bound to the Intent
  PaymentMandate -> the network-facing credential, carrying the matched hashes

Signet adds runtime objects:
  RuntimeContext  -> what the agent actually presents at execution time
  ExecutionRequest -> the full bundle the verifier evaluates
  Decision / ExecutionToken -> the rail-agnostic "decision as capability"
  Receipt -> the signed, hash-chained evidence artifact
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------- The mandate chain ----------

class IntentMandate(BaseModel):
    mandate_id: str
    principal_id: str
    agent_id: str
    scope: str
    allowed_actions: List[str]
    max_amount: int
    currency: str
    allowed_recipients: List[str]
    valid_from: datetime
    valid_until: datetime
    nonce: str
    policy_id: str
    prompt_playback: Optional[str] = None
    signature: Optional[str] = None

    def signing_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"signature"})


class CartMandate(BaseModel):
    cart_id: str
    intent_mandate_id: str
    intent_hash: str
    agent_id: str
    merchant_id: str
    action: str
    recipient: str
    amount: int
    currency: str
    destination_account: str
    invoice_id: Optional[str] = None
    signature: Optional[str] = None

    def signing_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"signature"})


class FundingInstrument(BaseModel):
    rail: str               # e.g. "xrpl", "card", "ach", "stablecoin"
    token: str              # tokenized reference, never the raw instrument


class PaymentMandate(BaseModel):
    payment_id: str
    cart_id: str
    cart_hash: str
    intent_hash: str
    amount: int
    currency: str
    funding_instrument: FundingInstrument
    agent_present: str = "HNP"   # "HP" or "HNP"
    signature: Optional[str] = None


# ---------- Runtime ----------

class RuntimeContext(BaseModel):
    """What the agent actually presents at the moment of execution.

    The verifier reconstructs a context hash from these fields and requires it
    to match the context the Cart committed to. This is what catches
    recipient/destination substitution and cross-context replay.
    """
    task_id: str
    agent_id: str
    merchant_id: str
    scope: str
    action: str
    recipient: str
    amount: int
    currency: str
    destination_account: str
    rail: str


class ExecutionRequest(BaseModel):
    request_id: str
    intent: IntentMandate
    cart: CartMandate
    payment: PaymentMandate
    context: RuntimeContext


class Decision(BaseModel):
    decision: str                       # "approved" | "blocked"
    reason: str
    chain_hash: Optional[str] = None
    execution_id: Optional[str] = None
    nonce: Optional[str] = None
    expires_at: Optional[datetime] = None

    @property
    def approved(self) -> bool:
        return self.decision == "approved"


class ExecutionToken(BaseModel):
    """The enforcer's signed, one-time, intent-bound authorization.

    This is the rail-agnostic "decision as a capability." An authorizer turns
    it into a rail-specific necessary input (an XRPL co-signature, a minted
    credential, etc.). The token signature is the enforcer's; the action cannot
    proceed without it.
    """
    execution_id: str
    mandate_id: str
    chain_hash: str
    nonce: str
    expires_at: datetime
    status: str = "approved"
    signature: Optional[str] = None

    def signing_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"signature"})


class Receipt(BaseModel):
    receipt_id: str
    execution_id: str
    mandate_id: str
    chain_hash: str
    policy_id: str
    decision: str
    payment_status: str
    payment_ref: Optional[str]
    rail: str
    timestamp: datetime
    prev_receipt_hash: Optional[str] = None
    receipt_hash: Optional[str] = None
    signature: Optional[str] = None

    def hashing_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"receipt_hash", "signature"})
