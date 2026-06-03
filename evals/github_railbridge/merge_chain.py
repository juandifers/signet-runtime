"""Build a signed, internally-consistent AP2 mandate chain for a GitHub merge,
mirroring `signet/builder.build_chain` -- WITHOUT touching the kernel.

This is the GitHub analogue of `evals/agentdojo/signet_harness.py`: it translates
a merge effect into Signet objects and routes the decision through the UNMODIFIED
`signet.verifier.Verifier`. The discriminating gate is the kernel's context-binding
(step 7) + exactness (step 8): the Cart is built from the AUTHORIZED merge while the
RuntimeContext is built from the ACTUAL merge. Diverge them (force-push -> new
head_sha, base swap, protected paths) and the verifier blocks before any side effect.

Mapping (AP2 -> Signet), per the §6 encoding:
    recipient           = effect_key(effect_class, target_id)   # binds head_sha + base
    action              = effect_class                          # merge_pr / merge_pr_protected
    amount              = 1                                      # merges are unpriced
    destination_account = diff_hash(touched_paths)              # extra bind + receipt anchor
    rail                = "github"
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Optional

from signet import chain, crypto
from signet.builder import Env, make_env
from signet.canonical import canonical_json
from signet.models import (CartMandate, ExecutionRequest, FundingInstrument,
                           IntentMandate, PaymentMandate, RuntimeContext)
from signet.policy import Policy

from .domain import (CONFIGURED_REPO, EFFECT_MERGE, diff_hash, effect_class_for,
                     effect_key, target_id)

AGENT_ID = "github_merge_agent_01"
SCOPE = "github_merge"
CURRENCY = "github"          # merges are unpriced; currency is a held-constant constant
RAIL = "github"
MERCHANT = "github_app_octo"
PRINCIPAL = "acme_cfo"       # the identity make_env() registers in the keystore
# Merges-per-principal-per-window cap. amount==1 per merge, so this reuses the kernel's
# existing per-principal velocity (policy.max_amount_per_day) as a merges/day rate limit.
# A small conservative default -- it is config, not logic.
GITHUB_DAILY_MERGE_CAP = 10


def make_github_env(now: Optional[datetime] = None) -> Env:
    """A standard Signet env (verifier + keys + policy engine). Reuses the kernel
    builder unchanged; the GitHub policy is registered per-chain by build_merge_chain."""
    return make_env(now)


def build_merge_chain(
    env: Env,
    *,
    repo: str = CONFIGURED_REPO,
    pr: int = 42,
    base: str = "main",
    head_sha: str = "sha42aaaaaa",
    touched_paths=("src/app/widget.py",),
    author: str = "alice",
    allowed_actions=None,
    daily_merge_cap: int = GITHUB_DAILY_MERGE_CAP,
    policy_id: Optional[str] = None,
    nonce: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    valid_until: Optional[datetime] = None,
    # runtime-only overrides (diverge the RuntimeContext from the signed Cart):
    ctx_repo: Optional[str] = None,
    ctx_pr: Optional[int] = None,
    ctx_base: Optional[str] = None,
    ctx_head_sha: Optional[str] = None,
    ctx_paths=None,
    # post-signature tamper / linkage break (mirror builder.build_chain):
    tamper_cart_recipient: Optional[str] = None,
    break_linkage: bool = False,
) -> ExecutionRequest:
    now = env.clock()
    nonce = nonce or "nonce_" + uuid.uuid4().hex[:8]
    valid_from = valid_from or (now - timedelta(hours=1))
    valid_until = valid_until or (now + timedelta(days=30))
    # The principal authorizes ordinary merges only; a protected merge falls outside
    # Intent.allowed_actions (out-of-envelope). This is the STANDING authorized set.
    allowed_actions = list(allowed_actions) if allowed_actions is not None else [EFFECT_MERGE]

    # ---- the AUTHORIZED merge (the Cart commits to this) ----
    ec_cart = effect_class_for(touched_paths)
    rec_cart = effect_key(ec_cart, target_id(repo, pr, base, head_sha))
    diff_cart = diff_hash(touched_paths)

    # ---- the ACTUAL merge presented at runtime (the RuntimeContext) ----
    r2 = ctx_repo or repo
    p2 = ctx_pr if ctx_pr is not None else pr
    b2 = ctx_base or base
    h2 = ctx_head_sha or head_sha
    paths2 = ctx_paths if ctx_paths is not None else touched_paths
    ec_ctx = effect_class_for(paths2)
    rec_ctx = effect_key(ec_ctx, target_id(r2, p2, b2, h2))
    diff_ctx = diff_hash(paths2)

    # Per-chain policy: only ordinary merges to this exact authorized recipient.
    policy_id = policy_id or "github_railbridge_" + uuid.uuid4().hex[:8]
    env.policy.add(Policy(
        policy_id=policy_id,
        max_amount_per_transaction=1,
        max_amount_per_day=int(daily_merge_cap),   # per-principal merges/day rate limit
        allowed_recipients=[rec_cart],
        allowed_currencies=[CURRENCY],
        allowed_actions=[EFFECT_MERGE],
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
        prompt_playback=f"Merge approved pull requests in {repo} to allowed branches.",
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
        destination_account=diff_cart,
        invoice_id=f"pr_{repo}#{pr}",
    )
    cart.signature = crypto.sign(env.principal_sk,
                                 canonical_json(cart.signing_payload()))

    # Optional post-signature tamper (mirror builder.build_chain): change a signed
    # field WITHOUT re-signing -> caught by the signature check.
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
        funding_instrument=FundingInstrument(rail=RAIL, token="tok_github"),
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
        destination_account=diff_ctx,
        rail=RAIL,
    )

    return ExecutionRequest(
        request_id="req_" + uuid.uuid4().hex[:8],
        intent=intent, cart=cart, payment=payment, context=ctx,
    )
