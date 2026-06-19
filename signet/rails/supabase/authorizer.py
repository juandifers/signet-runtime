"""The Supabase DB authorizer — a Role-2 authorizer that mints a scoped ES256 JWT.

It subclasses the UNCHANGED `signet.authorizers.base.Authorizer` and fills ONLY the two content
hooks. `base.authorize` still owns the order and the fail-closed flow:

    verify_token  ->  recheck_against_context  ->  produce_capability

  * recheck_against_context: (1) the token is bound to THIS exact transaction; (2) the runtime
    effect equals the signed Cart effect (no substitution); (3) the effect lies within the
    FROZEN task mandate ∩ standing policy (the real keyholder gate, on trusted input).
  * produce_capability: mint a short-lived ES256 JWT whose `role` claim selects a RESTRICTED
    Postgres role and whose `signet_effect_hash` binds it to exactly this operation. The signing
    key never leaves the broker; the agent receives only the JWT, verifiable against the JWKS.

No kernel logic leaks here, and this rail never edits the kernel or the authorizer template.
"""
from __future__ import annotations

import datetime as _dt
from typing import Callable, Optional, Tuple

from ...authorizers.base import AuthorizationResult, Authorizer
from ...models import ExecutionRequest, ExecutionToken
from ..supabase import chain_adapter
from .effect import DbEffect
from .es256 import Es256Key
from .roles import role_for_effect
from ...broker.mandate import MandateProvider, StandingPolicy, effective_permits


class SupabaseAuthorizer(Authorizer):
    rail = "supabase"

    def __init__(self, verifier, enforcer_verify_key: str, *,
                 mandate_provider: MandateProvider, standing_policy: StandingPolicy,
                 minter: Es256Key, ttl_seconds: int = 60,
                 clock: Optional[Callable[[], _dt.datetime]] = None):
        super().__init__(verifier, enforcer_verify_key)
        self._mandates = mandate_provider
        self._standing = standing_policy
        self._minter = minter
        self._ttl = ttl_seconds
        self._clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
        # surfaced for the broker's receipt (which mandate decided this request)
        self.last_mandate_hash: Optional[str] = None

    # -- the content hooks; base.Authorizer.authorize owns verify_token + the order --
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        # 1. token bound to THIS exact transaction (independent recompute)
        recomputed = chain_adapter.chain.chain_hash(req.intent, req.cart, req.payment)
        if recomputed != token.chain_hash:
            return False, "unbound-token"
        # 2. runtime effect == signed Cart effect (no destination/effect substitution)
        if (req.cart.destination_account != req.context.destination_account
                or req.cart.recipient != req.context.recipient
                or req.cart.action != req.context.action):
            return False, "effect-context-mismatch"
        # 3. the real keyholder gate: effect ∈ frozen mandate ∩ standing policy
        eff = chain_adapter.effect_from_request(req)
        mandate = self._mandates.get(req.context.task_id)
        if mandate is None:
            return False, "no-frozen-mandate"
        self.last_mandate_hash = mandate.mandate_hash()
        now = self._clock()
        if mandate.is_expired(now):
            return False, "mandate-expired"
        ok, cause = effective_permits(eff, mandate, self._standing)
        return ok, cause

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        """Mint the scoped ES256 JWT. Reached ONLY after verify_token + recheck both pass."""
        eff = chain_adapter.effect_from_request(req)
        role = role_for_effect(eff)
        now = self._clock()
        claims = {
            "role": role,
            "sub": req.context.task_id,
            "iss": "signet-broker",
            "signet_effect_hash": eff.effect_hash(),
            "signet_chain_hash": token.chain_hash,
        }
        jwt_token = self._minter.mint_jwt(claims, now=now, ttl_seconds=self._ttl)
        return AuthorizationResult(
            True,
            f"minted ES256 JWT role={role} ttl={self._ttl}s for {eff.target()}.{eff.op}",
            payment_ref=jwt_token, rail=self.rail)
