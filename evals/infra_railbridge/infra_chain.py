"""Build a signed, internally-consistent AP2 mandate chain for an infra change-set APPLY, mirroring
the deploy rail's `deploy_chain.py` -- WITHOUT touching the kernel. The decision routes through the
UNMODIFIED `signet.verifier.Verifier`.

The discriminating gate is the kernel's context-binding (step 7) + exactness (step 8): the Cart is
built from the AUTHORIZED apply while the RuntimeContext is built from the ACTUAL apply. Diverge them
(ADD or REMOVE a resource from the set, swap the account/cluster, swap the plan) and the verifier
blocks before any side effect -- the TOCTOU / "slip an extra resource into the apply" defense.

Mapping (AP2 -> Signet), per the §6 encoding:
    recipient           = effect_key(effect_class, target_id)   # binds account+cluster+SET+plan
    action              = effect_class                          # infra_apply / infra_apply_protected
    amount              = 1                                      # applies are unpriced
    destination_account = plan_fingerprint(plan_hash)           # extra bind + receipt anchor
    rail                = "infra"

NOTE vs deploy: `effect_class` is passed EXPLICITLY (it depends on the resource TYPES in the plan,
which are not recoverable from the bound account/cluster/address-set/plan_hash alone). The caller
computes it from the Plan via `domain.effect_class_for`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Optional, Tuple

from signet import chain, crypto
from signet.builder import Env, make_env
from signet.canonical import canonical_json
from signet.models import (CartMandate, ExecutionRequest, FundingInstrument, IntentMandate,
                           PaymentMandate, RuntimeContext)
from signet.policy import Policy

from .domain import (CONFIGURED_ACCOUNTS, CONFIGURED_CLUSTERS, EFFECT_INFRA_APPLY, effect_key,
                     plan_fingerprint, target_id)
from .policy import DEFAULT_INFRA_POLICY, InfraPolicy

AGENT_ID = "infra_apply_agent_01"
SCOPE = "infra_apply"
CURRENCY = "infra"          # applies are unpriced; currency is a held-constant constant
RAIL = "infra"
MERCHANT = "infra_controller"
PRINCIPAL = "acme_cfo"      # the identity make_env() registers in the keystore


def make_infra_env(now: Optional[datetime] = None) -> Env:
    """A standard Signet env (verifier + keys + policy engine). Reuses the kernel builder unchanged;
    the infra policy is registered per-chain by build_infra_chain."""
    return make_env(now)


def build_infra_chain(
    env: Env,
    *,
    account: str = CONFIGURED_ACCOUNTS[0],
    cluster: str = CONFIGURED_CLUSTERS[0],
    resource_set: Tuple[str, ...] = ("aws_s3_bucket.assets",),
    plan_hash: str = "plan-001",
    effect_class: str = EFFECT_INFRA_APPLY,
    author: str = "alice",
    allowed_actions=None,
    policy: InfraPolicy = DEFAULT_INFRA_POLICY,
    policy_id: Optional[str] = None,
    nonce: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    valid_until: Optional[datetime] = None,
    # runtime-only overrides (diverge the RuntimeContext from the signed Cart):
    ctx_account: Optional[str] = None,
    ctx_cluster: Optional[str] = None,
    ctx_resource_set: Optional[Tuple[str, ...]] = None,
    ctx_plan_hash: Optional[str] = None,
    ctx_effect_class: Optional[str] = None,
    # post-signature tamper / linkage break (mirror builder.build_chain):
    tamper_cart_recipient: Optional[str] = None,
    break_linkage: bool = False,
) -> ExecutionRequest:
    now = env.clock()
    nonce = nonce or "nonce_" + uuid.uuid4().hex[:8]
    valid_from = valid_from or (now - timedelta(hours=1))
    valid_until = valid_until or (now + timedelta(days=30))
    # The principal authorizes ordinary (non-protected) applies only; a protected apply falls outside
    # Intent.allowed_actions (out-of-envelope). This is the STANDING authorized set.
    allowed_actions = list(allowed_actions) if allowed_actions is not None else [EFFECT_INFRA_APPLY]

    # ---- the AUTHORIZED apply (the Cart commits to this) ----
    ec_cart = effect_class
    rec_cart = effect_key(ec_cart, target_id(account, cluster, resource_set, plan_hash))
    dest_cart = plan_fingerprint(plan_hash)

    # ---- the ACTUAL apply presented at runtime (the RuntimeContext) ----
    a2 = ctx_account or account
    cl2 = ctx_cluster or cluster
    rs2 = ctx_resource_set if ctx_resource_set is not None else resource_set
    p2 = ctx_plan_hash or plan_hash
    ec_ctx = ctx_effect_class or effect_class
    rec_ctx = effect_key(ec_ctx, target_id(a2, cl2, rs2, p2))
    dest_ctx = plan_fingerprint(p2)

    policy_id = policy_id or "infra_railbridge_" + uuid.uuid4().hex[:8]
    env.policy.add(Policy(
        policy_id=policy_id,
        max_amount_per_transaction=1,
        max_amount_per_day=int(policy.applies_per_day),
        allowed_recipients=[rec_cart],
        allowed_currencies=[CURRENCY],
        allowed_actions=[EFFECT_INFRA_APPLY],
        require_human_approval_above=None,
    ))

    intent = IntentMandate(
        mandate_id="mandate_" + uuid.uuid4().hex[:8],
        principal_id=PRINCIPAL,
        agent_id=AGENT_ID,
        scope=SCOPE,
        allowed_actions=allowed_actions,
        max_amount=1,
        currency=CURRENCY,
        allowed_recipients=[rec_cart],
        valid_from=valid_from,
        valid_until=valid_until,
        nonce=nonce,
        policy_id=policy_id,
        prompt_playback=f"Apply non-protected change-sets within {account}/{cluster}.",
    )
    intent.signature = crypto.sign(env.principal_sk,
                                   canonical_json(intent.signing_payload()))

    cart = CartMandate(
        cart_id="cart_" + uuid.uuid4().hex[:8],
        intent_mandate_id=intent.mandate_id,
        intent_hash=chain.intent_hash(intent),
        agent_id=AGENT_ID,
        merchant_id=MERCHANT,
        action=ec_cart,
        recipient=rec_cart,
        amount=1,
        currency=CURRENCY,
        destination_account=dest_cart,
        invoice_id=f"infra_{account}@{cluster}",
    )
    cart.signature = crypto.sign(env.principal_sk,
                                 canonical_json(cart.signing_payload()))

    if tamper_cart_recipient is not None:
        cart.recipient = tamper_cart_recipient

    payment_cart_hash = chain.cart_hash(cart)
    if break_linkage:
        payment_cart_hash = "sha256:stale_cart_" + uuid.uuid4().hex[:8]

    payment = PaymentMandate(
        payment_id="pay_" + uuid.uuid4().hex[:8],
        cart_id=cart.cart_id,
        cart_hash=payment_cart_hash,
        intent_hash=chain.intent_hash(intent),
        amount=1,
        currency=CURRENCY,
        funding_instrument=FundingInstrument(rail=RAIL, token="tok_infra"),
    )

    ctx = RuntimeContext(
        task_id="task_" + uuid.uuid4().hex[:6],
        agent_id=AGENT_ID,
        merchant_id=MERCHANT,
        scope=SCOPE,
        action=ec_ctx,
        recipient=rec_ctx,
        amount=1,
        currency=CURRENCY,
        destination_account=dest_ctx,
        rail=RAIL,
    )

    return ExecutionRequest(
        request_id="req_" + uuid.uuid4().hex[:8],
        intent=intent, cart=cart, payment=payment, context=ctx,
    )
