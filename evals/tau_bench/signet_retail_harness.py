"""Thin composition layer over the REAL Signet kernel, for tau-bench retail.

Mirrors ``evals/agentdojo/signet_harness.py`` exactly in spirit: it does NOT
reimplement any verification logic. It builds a signed, internally-consistent
AP2-shaped chain (Intent -> Cart -> Payment) plus the RuntimeContext presented at
execution, then routes the verdict through the unmodified
``signet.verifier.Verifier`` + ``MockCredentialBroker``. The decision is 100% the
verifier's; this file only translates a retail *effect* into Signet objects.

Why this reuses the kernel unchanged (the key idea: BIND THE EFFECT, not the tool)
---------------------------------------------------------------------------------
The banking harness mapped ``send_money(recipient, amount)`` onto the kernel by
putting the IBAN in ``recipient`` and cents in ``amount``; the discriminating
gate was context-binding + allowlist + exactness over (recipient, amount).

Retail high-impact actions (cancel / return / exchange / modify_*) have no single
"recipient/amount". What we want to bind is the **effect**: "this action_type on
this order". So we map:

    recipient / destination_account  <-  the EFFECT KEY  "tool|order_id"
    amount                           <-  held constant (1)   } so neither amount
    currency                         <-  held constant       } nor currency is the
    action                           <-  held constant        } discriminating check

and register the per-task allowlist = the set of **admitted** effect keys (the
ones that are both inside the frozen trusted-intent envelope AND pass the standing
policy's structural constraints). The kernel then does, unchanged:

    * context-binding  -> proposed effect key must equal the bound Cart's key
    * allowlist        -> effect key must be an admitted one
    * consume-once     -> the identical effect cannot replay within an episode

An out-of-envelope action (wrong order, foreign order, redirected refund) is bound
to a NO_AUTHORIZED sentinel / excluded from the allowlist, so the BLOCK is produced
by the real verifier, never by an adapter-side shortcut. This is the literal
rail-agnostic generalisation the kernel was built for: a new "rail" = a new effect
encoding, kernel untouched.
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

AGENT_ID = "retail_agent_01"
SCOPE = "retail"
ACTION = "retail_action"          # held constant; the effect key carries the detail
CURRENCY = "USD"                  # held constant; never the discriminating check
AMOUNT = 1                        # held constant; never the discriminating check
RAIL = "mock"
# Sentinel effect bound when an action is NOT admitted (out-of-envelope or fails a
# structural constraint). Any real effect fails context-binding/allowlist against
# this -- the block is the verifier's, not a gate-side shortcut.
NO_AUTHORIZED_EFFECT = "__NO_AUTHORIZED_EFFECT__"


def effect_key(tool: str, order_id: Optional[str]) -> str:
    """The single source of truth for 'same authorized retail effect'.

    Binds (action_type, target id). order_id is normalised (upper, stripped) so a
    trivial reformatting can't dodge context-binding. Used for BOTH the chain-cache
    key and allowlist membership so the two can never drift.
    """
    oid = "" if order_id is None else str(order_id).strip().upper()
    return f"{tool}|{oid}"


@dataclass
class GateOutcome:
    approved: bool
    reason: str
    decision: Decision
    authorization: Optional[AuthorizationResult]


class RetailSignetHarness:
    """Owns one Signet environment (verifier + keys + policy + broker) for a run.

    A fresh per-task policy is registered whose allowlist = the admitted effect
    keys for that task. The kernel is never modified.
    """

    def __init__(self) -> None:
        self.env: Env = make_env()
        self.broker = MockCredentialBroker(self.env.verifier, self.env.enforcer_vk)
        self._policy_seq = 0
        # Cache of signed chains keyed by (task_id, effect_key); reset per episode
        # so consume-once is scoped to a single task conversation.
        self._chain_cache: dict = {}

    # -- episode lifecycle --

    def reset_episode(self) -> None:
        """Reset all consume-once-scoped state at a task boundary: a fresh
        NonceRegistry on the (unmodified) verifier, an empty chain cache, and a
        fresh velocity ledger. Keys / policies stay stable."""
        self.env.verifier.nonces = NonceRegistry()
        self.env.policy.spend = SpendLedger()
        self._chain_cache.clear()

    # -- policy registration (per task) --

    def register_policy(self, admitted_effects: list[str]) -> str:
        """Register a per-task policy whose allowlist = the admitted effect keys.

        Velocity/caps are not the property under test here (retail actions carry no
        comparable per-call amount), so the cap is held high and amount constant;
        the discriminating gate is context-binding + allowlist over the effect key.
        """
        self._policy_seq += 1
        policy_id = f"retail_eval_policy_{self._policy_seq}"
        allow = list(admitted_effects) if admitted_effects else [NO_AUTHORIZED_EFFECT]
        self.env.policy.add(Policy(
            policy_id=policy_id,
            max_amount_per_transaction=10 ** 9,
            max_amount_per_day=10 ** 15,
            allowed_recipients=allow,
            allowed_currencies=[CURRENCY],
            allowed_actions=[ACTION],
            require_human_approval_above=None,
        ))
        return policy_id

    # -- chain construction --

    def _authorized_chain(self, task_id: str, policy_id: str, bound_effect: str):
        """Return the STABLE signed (intent, cart, payment) bound to ``bound_effect``,
        minted once per (task_id, effect) and memoized so an identical effect within
        a task yields the same chain_hash (caught by consume_once), while different
        tasks get different mandate_ids (no spurious cross-task replay)."""
        key = (task_id, bound_effect)
        cached = self._chain_cache.get(key)
        if cached is not None:
            return cached

        env = self.env
        now = env.clock()
        seed = hashlib.sha256(f"{task_id}|{bound_effect}|{ACTION}".encode()).hexdigest()

        intent = IntentMandate(
            mandate_id="mandate_" + seed[:12],
            # Must match the principal registered in make_env()'s keystore, else
            # the verifier can't resolve the verify key -> "invalid signature".
            principal_id="acme_cfo",
            agent_id=AGENT_ID,
            scope=SCOPE,
            allowed_actions=[ACTION],
            max_amount=AMOUNT,
            currency=CURRENCY,
            allowed_recipients=[bound_effect],
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(days=30),
            nonce="nonce_" + seed[12:24],
            policy_id=policy_id,
            prompt_playback="tau-bench retail task: effect authorized from trusted user intent.",
        )
        intent.signature = crypto.sign(env.principal_sk,
                                       canonical_json(intent.signing_payload()))

        cart = CartMandate(
            cart_id="cart_" + seed[24:36],
            intent_mandate_id=intent.mandate_id,
            intent_hash=chain.intent_hash(intent),
            agent_id=AGENT_ID,
            merchant_id="tau_bench_retail",
            action=ACTION,
            recipient=bound_effect,
            amount=AMOUNT,
            currency=CURRENCY,
            destination_account=bound_effect,
            invoice_id="task_" + str(task_id),
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

    def build_request(self, *, policy_id: str, bound_effect: str,
                      proposed_effect: str, task_id: str) -> ExecutionRequest:
        """Assemble an ExecutionRequest: the STABLE authorized chain (bound to
        ``bound_effect``) plus a per-call RuntimeContext built from the PROPOSED
        effect. If the two diverge, context-binding blocks; if ``bound_effect`` is
        the sentinel, allowlist+binding block."""
        intent, cart, payment = self._authorized_chain(task_id, policy_id, bound_effect)
        ctx = RuntimeContext(
            task_id=str(task_id),
            agent_id=AGENT_ID,
            merchant_id="tau_bench_retail",
            scope=SCOPE,
            action=ACTION,
            recipient=proposed_effect,
            amount=AMOUNT,
            currency=CURRENCY,
            destination_account=proposed_effect,
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
