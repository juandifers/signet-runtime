"""Thin composition layer over the REAL Signet kernel.

This module does NOT reimplement any verification logic. It builds a signed,
internally-consistent AP2-shaped mandate chain (Intent -> Cart -> Payment) plus
the RuntimeContext the agent presents at execution, then routes the decision
through the unmodified ``signet.verifier.Verifier`` and a ``MockCredentialBroker``
authorizer. The verdict is 100% the verifier's; this file only translates
AgentDojo banking-tool arguments into Signet objects.

Mapping conventions (AgentDojo banking -> Signet):
  * recipient IBAN            -> Cart.recipient / Cart.destination_account
  * amount (float, e.g 98.70) -> integer cents (Signet amounts are ints)
  * currency                  -> a single constant ("EUR"); the banking suite
                                 has no currency field, so it is held fixed and
                                 is therefore never the discriminating check.
  * every money-moving action -> Signet action "pay_invoice" (scope "banking")

The discriminating gate is Signet's context-binding + exactness: the Cart is
built from the AUTHORIZED transaction while the RuntimeContext is built from the
ACTUAL tool-call arguments. If they diverge (recipient substitution, amount
tamper) the verifier blocks before any side effect.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from signet import chain, crypto
from signet.authorizers.base import AuthorizationResult
from signet.authorizers.mock_broker import MockCredentialBroker
from signet.builder import Env, make_env
from signet.canonical import canonical_json
from signet.models import (CartMandate, Decision, ExecutionRequest,
                           FundingInstrument, IntentMandate, PaymentMandate,
                           RuntimeContext)
from signet.nonce import NonceRegistry
from signet.policy import Policy, SpendLedger

AGENT_ID = "banking_agent_01"
SCOPE = "banking"
ACTION = "pay_invoice"
CURRENCY = "EUR"
RAIL = "mock"
# Sentinel recipient used when a task authorizes NO money movement. Any real
# transfer will fail context-binding / allowlist against this -- the block is
# produced by the real verifier, not by a gate-side shortcut.
NO_AUTHORIZED_TRANSFER = "__NO_AUTHORIZED_TRANSFER__"


def to_cents(amount: float) -> int:
    """Float currency amount -> integer cents (Signet amounts are ints).

    Applied identically to the cached chain's Cart.amount and the per-call
    RuntimeContext.amount so context-binding/exactness never mismatch on floats.
    """
    return int(round(float(amount) * 100))


def canonical_action(recipient: str, amount_cents: int) -> tuple:
    """The single source of truth for 'same authorized action'.

    Used for BOTH the chain-cache key and the metric classification so the two
    can never drift. In this harness destination == recipient, currency and
    action are constants, so the discriminating tuple is recipient+amount; we
    spell out all five fields the brief names for clarity.
    """
    r = str(recipient).upper()
    return (r, int(amount_cents), r, CURRENCY, ACTION)


@dataclass
class GateOutcome:
    approved: bool
    reason: str
    decision: Decision
    authorization: Optional[AuthorizationResult]


class SignetHarness:
    """Owns one Signet environment (verifier + keys + policy + broker) for a run.

    A fresh per-task policy is registered so the Intent's allowlist/cap reflect
    exactly what that user task authorized. The kernel is never modified.
    """

    def __init__(self) -> None:
        self.env: Env = make_env()
        self.broker = MockCredentialBroker(self.env.verifier, self.env.enforcer_vk)
        self._policy_seq = 0
        # Cache of signed mandate chains, keyed by (task_id, canonical_action).
        # Reset per episode so consume-once is scoped to a single episode.
        self._chain_cache: dict = {}

    # -- episode lifecycle --

    def reset_episode(self) -> None:
        """Reset all consume-once-scoped state at an episode boundary.

        AgentDojo runs each (user_task x injection_task x condition) as an
        INDEPENDENT episode with a fresh environment, so a legitimate transfer
        recurring in a later episode must NOT be replay-blocked. We therefore
        scope consume-once state per episode: a fresh NonceRegistry on the
        (unmodified) verifier, an empty chain cache, and a fresh velocity ledger.
        Keys / keystore / policies stay stable -- they are not consume-once state.
        """
        self.env.verifier.nonces = NonceRegistry()
        self.env.policy.spend = SpendLedger()
        self._chain_cache.clear()

    # -- policy registration (per task) --

    def register_policy(self, allowed_recipients: list[str], cap_cents: int,
                        daily_cap_cents: Optional[int] = None) -> str:
        """Register a per-task policy and return its policy_id.

        daily cap defaults very high: velocity/structuring is a separate Signet
        defence and is not the property under test in this harness, so we do not
        want unrelated tasks in one run to accumulate into a spurious velocity
        block. (It remains configurable for the structuring boundary probe.)
        """
        self._policy_seq += 1
        policy_id = f"banking_eval_policy_{self._policy_seq}"
        # Guard against a zero/negative cap (deny-sentinel case) tripping nothing
        # useful: keep cap >= 1 so the discriminating block is recipient/context.
        cap = max(int(cap_cents), 1)
        self.env.policy.add(Policy(
            policy_id=policy_id,
            max_amount_per_transaction=cap,
            max_amount_per_day=daily_cap_cents if daily_cap_cents is not None else 10 ** 15,
            allowed_recipients=list(allowed_recipients),
            allowed_currencies=[CURRENCY],
            allowed_actions=[ACTION],
            require_human_approval_above=None,
        ))
        return policy_id

    # -- chain construction --

    def _authorized_chain(self, task_id: str, policy_id: str,
                          authorized_recipient: str, authorized_amount_cents: int):
        """Return the STABLE signed (intent, cart, payment) for an authorized
        action, minted ONCE per (task_id, canonical_action) and memoized.

        IDs are derived deterministically from (task_id, recipient, amount) so:
          * the same authorized action within a task always yields the same
            chain_hash (so a within-episode repeat is caught by consume_once), and
          * two DIFFERENT tasks authorizing an identical transfer get different
            mandate_ids -> different chain_hash -> no spurious cross-task replay.
        """
        key = (task_id,) + canonical_action(authorized_recipient, authorized_amount_cents)
        cached = self._chain_cache.get(key)
        if cached is not None:
            return cached

        env = self.env
        now = env.clock()
        amount = max(int(authorized_amount_cents), 1)
        seed = hashlib.sha256(
            f"{task_id}|{authorized_recipient}|{authorized_amount_cents}|{ACTION}".encode()
        ).hexdigest()

        intent = IntentMandate(
            mandate_id="mandate_" + seed[:12],
            principal_id="acme_cfo",
            agent_id=AGENT_ID,
            scope=SCOPE,
            allowed_actions=[ACTION],
            max_amount=amount,
            currency=CURRENCY,
            allowed_recipients=[authorized_recipient],
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(days=30),
            nonce="nonce_" + seed[12:24],
            policy_id=policy_id,
            prompt_playback="AgentDojo banking task: authorized transaction from task ground truth.",
        )
        intent.signature = crypto.sign(env.principal_sk,
                                       canonical_json(intent.signing_payload()))

        cart = CartMandate(
            cart_id="cart_" + seed[24:36],
            intent_mandate_id=intent.mandate_id,
            intent_hash=chain.intent_hash(intent),
            agent_id=AGENT_ID,
            merchant_id="agentdojo_banking",
            action=ACTION,
            recipient=authorized_recipient,
            amount=amount,
            currency=CURRENCY,
            destination_account=authorized_recipient,
            invoice_id="task_" + task_id,
        )
        cart.signature = crypto.sign(env.principal_sk,
                                     canonical_json(cart.signing_payload()))

        payment = PaymentMandate(
            payment_id="pay_" + seed[36:48],
            cart_id=cart.cart_id,
            cart_hash=chain.cart_hash(cart),
            intent_hash=chain.intent_hash(intent),
            amount=cart.amount,
            currency=CURRENCY,
            funding_instrument=FundingInstrument(rail=RAIL, token="tok_eval"),
        )

        self._chain_cache[key] = (intent, cart, payment)
        return intent, cart, payment

    def build_request(
        self,
        *,
        policy_id: str,
        authorized_recipient: str,
        authorized_amount_cents: int,
        actual_recipient: str,
        actual_amount_cents: int,
        task_id: str,
    ) -> ExecutionRequest:
        """Assemble an ExecutionRequest: the STABLE authorized chain (memoized)
        plus a per-call RuntimeContext built from the ACTUAL tool-call args.

        The RuntimeContext is not part of chain_hash, so the chain_hash stays
        stable across calls that bind to the same authorized action -- which is
        exactly what lets consume_once detect a within-episode replay.
        """
        intent, cart, payment = self._authorized_chain(
            task_id, policy_id, authorized_recipient, authorized_amount_cents)

        ctx = RuntimeContext(
            task_id=task_id,
            agent_id=AGENT_ID,
            merchant_id="agentdojo_banking",
            scope=SCOPE,
            action=ACTION,
            recipient=actual_recipient,
            amount=int(actual_amount_cents),
            currency=CURRENCY,
            destination_account=actual_recipient,
            rail=RAIL,
        )

        return ExecutionRequest(
            request_id="req_" + uuid.uuid4().hex[:8],
            intent=intent, cart=cart, payment=payment, context=ctx,
        )

    # -- the decision: real verifier, then real authorizer --

    def decide(self, req: ExecutionRequest) -> GateOutcome:
        decision, token = self.env.verifier.evaluate(req)
        if not decision.approved or token is None:
            return GateOutcome(False, decision.reason, decision, None)
        auth = self.broker.authorize(token, req)
        if not auth.executed:
            return GateOutcome(False, auth.reason, decision, auth)
        return GateOutcome(True, decision.reason, decision, auth)
