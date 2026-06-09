"""Build a signed, internally-consistent AP2 mandate chain for an artifact promotion (deploy),
mirroring the merge rail's `merge_chain.py` -- WITHOUT touching the kernel. The decision routes
through the UNMODIFIED `signet.verifier.Verifier`.

The discriminating gate is the kernel's context-binding (step 7) + exactness (step 8): the Cart
is built from the AUTHORIZED promotion while the RuntimeContext is built from the ACTUAL
promotion. Diverge them (swap the artifact digest, swap the environment, swap the config) and the
verifier blocks before any side effect -- the supply-chain / TOCTOU defense.

Mapping (AP2 -> Signet), per the §6 encoding:
    recipient           = effect_key(effect_class, target_id)        # binds service+env+digest+config
    action              = effect_class                               # deploy / deploy_protected
    amount              = 1                                           # deploys are unpriced
    destination_account = config_fingerprint(config_hash)            # extra bind + receipt anchor
    rail                = "deploy"
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Optional

from signet import chain, crypto
from signet.builder import Env, make_env
from signet.canonical import canonical_json
from signet.models import (CartMandate, ExecutionRequest, FundingInstrument, IntentMandate,
                           PaymentMandate, RuntimeContext)
from signet.policy import Policy

from .domain import (CONFIGURED_SERVICES, EFFECT_DEPLOY, config_fingerprint, effect_class_for,
                     effect_key, target_id)
from .policy import DEFAULT_DEPLOY_POLICY, DeployPolicy

AGENT_ID = "deploy_promote_agent_01"
SCOPE = "deploy_promote"
CURRENCY = "deploy"          # deploys are unpriced; currency is a held-constant constant
RAIL = "deploy"
MERCHANT = "deploy_controller"
PRINCIPAL = "acme_cfo"       # the identity make_env() registers in the keystore


def make_deploy_env(now: Optional[datetime] = None) -> Env:
    """A standard Signet env (verifier + keys + policy engine). Reuses the kernel builder
    unchanged; the deploy policy is registered per-chain by build_deploy_chain."""
    return make_env(now)


def build_deploy_chain(
    env: Env,
    *,
    service: str = CONFIGURED_SERVICES[0],
    environment: str = "staging",
    artifact_digest: str = "sha256:aaaa1111",
    config_hash: str = "cfg-001",
    author: str = "alice",
    allowed_actions=None,
    policy: DeployPolicy = DEFAULT_DEPLOY_POLICY,
    policy_id: Optional[str] = None,
    nonce: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    valid_until: Optional[datetime] = None,
    # runtime-only overrides (diverge the RuntimeContext from the signed Cart):
    ctx_service: Optional[str] = None,
    ctx_environment: Optional[str] = None,
    ctx_artifact_digest: Optional[str] = None,
    ctx_config_hash: Optional[str] = None,
    # post-signature tamper / linkage break (mirror builder.build_chain):
    tamper_cart_recipient: Optional[str] = None,
    break_linkage: bool = False,
) -> ExecutionRequest:
    now = env.clock()
    nonce = nonce or "nonce_" + uuid.uuid4().hex[:8]
    valid_from = valid_from or (now - timedelta(hours=1))
    valid_until = valid_until or (now + timedelta(days=30))
    # The principal authorizes ordinary deploys only; a protected (prod) deploy falls outside
    # Intent.allowed_actions (out-of-envelope). This is the STANDING authorized set.
    allowed_actions = list(allowed_actions) if allowed_actions is not None else [EFFECT_DEPLOY]

    # ---- the AUTHORIZED promotion (the Cart commits to this) ----
    ec_cart = effect_class_for(environment, policy.protected_environments)
    rec_cart = effect_key(ec_cart, target_id(service, environment, artifact_digest, config_hash))
    dest_cart = config_fingerprint(config_hash)

    # ---- the ACTUAL promotion presented at runtime (the RuntimeContext) ----
    s2 = ctx_service or service
    e2 = ctx_environment or environment
    d2 = ctx_artifact_digest or artifact_digest
    c2 = ctx_config_hash or config_hash
    ec_ctx = effect_class_for(e2, policy.protected_environments)
    rec_ctx = effect_key(ec_ctx, target_id(s2, e2, d2, c2))
    dest_ctx = config_fingerprint(c2)

    policy_id = policy_id or "deploy_railbridge_" + uuid.uuid4().hex[:8]
    env.policy.add(Policy(
        policy_id=policy_id,
        max_amount_per_transaction=1,
        max_amount_per_day=int(policy.deploys_per_day),
        allowed_recipients=[rec_cart],
        allowed_currencies=[CURRENCY],
        allowed_actions=[EFFECT_DEPLOY],
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
        prompt_playback=f"Promote scanned+signed builds of {service} to allowed environments.",
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
        invoice_id=f"deploy_{service}@{environment}",
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
        funding_instrument=FundingInstrument(rail=RAIL, token="tok_deploy"),
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
