"""The egress authorizer — a Role-2 authorizer that admits an outbound connection inline.

Subclasses the UNCHANGED `signet.authorizers.base.Authorizer` and fills ONLY the two content
hooks, exactly like SupabaseAuthorizer. `base.authorize` still owns
`verify_token -> recheck_against_context -> produce_capability` and the fail-closed flow.

  * recheck_against_context: (1) token bound to THIS exact connection; (2) runtime effect ==
    signed Cart effect; (3) the destination lies within the FROZEN mandate ∩ standing policy.
    Raw-IP targets are admitted only if they match the TRUSTED resolution of an allowlisted host
    (closes raw-IP evasion); hostnames are matched against the allow-set patterns.
  * produce_capability: the ADMISSION decision for this connection. There is NO bearer token —
    the proxy (the same process) consumes it inline and forwards the bytes. Consume-once on
    chain_hash happened in the kernel mint; the receipt is written by the proxy surface.

No kernel logic leaks here; this rail never edits the kernel or the authorizer template.
"""
from __future__ import annotations

import datetime as _dt
from typing import Callable, Optional, Tuple

from ...authorizers.base import AuthorizationResult, Authorizer
from ... import chain
from ...models import ExecutionRequest, ExecutionToken
from ...broker.mandate import MandateProvider
from .chain_adapter import effect_from_request
from .effect import EgressEffect
from .mandate import EgressStandingPolicy, effective_admits
from .resolver import TrustedResolver, is_ip_literal


class EgressAuthorizer(Authorizer):
    rail = "egress"

    def __init__(self, verifier, enforcer_verify_key: str, *,
                 mandate_provider: MandateProvider, standing_policy: EgressStandingPolicy,
                 resolver: TrustedResolver,
                 clock: Optional[Callable[[], _dt.datetime]] = None):
        super().__init__(verifier, enforcer_verify_key)
        self._mandates = mandate_provider
        self._standing = standing_policy
        self._resolver = resolver
        self._clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
        self.last_mandate_hash: Optional[str] = None

    def _raw_ip_in_resolved_allowset(self, eff: EgressEffect, mandate) -> bool:
        """A raw-IP target is admitted only if (ip, port) matches the trusted resolution of a
        CONCRETE allowlisted host that the standing policy also permits. Wildcard grants cannot
        be resolved (no concrete host), so raw-IP to a wildcard-allowed host is refused (v0)."""
        for g in mandate.grants:
            if g.host == "*" or g.host.startswith("*."):
                continue
            res = self._resolver.resolve(g.host)
            for logical_port in g.ports:
                phys = res.port if res.port is not None else logical_port
                if (eff.host == res.ip and eff.port == phys
                        and self._standing.permits(EgressEffect(g.host, logical_port,
                                                                 eff.protocol))):
                    return True
        return False

    # -- the content hooks; base.Authorizer.authorize owns verify_token + the order --
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        if chain.chain_hash(req.intent, req.cart, req.payment) != token.chain_hash:
            return False, "unbound-token"
        if (req.cart.destination_account != req.context.destination_account
                or req.cart.recipient != req.context.recipient
                or req.cart.action != req.context.action):
            return False, "effect-context-mismatch"

        eff = effect_from_request(req)
        mandate = self._mandates.get(req.context.task_id)
        if mandate is None:
            return False, "no-frozen-mandate"
        self.last_mandate_hash = mandate.mandate_hash()
        if mandate.is_expired(self._clock()):
            return False, "mandate-expired"

        if is_ip_literal(eff.host):
            ok = self._raw_ip_in_resolved_allowset(eff, mandate)
            return (True, "raw-ip matches a resolved allowlisted host") if ok \
                else (False, "out-of-mandate-destination")
        return effective_admits(eff, mandate, self._standing)

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        """The inline admission decision. Reached ONLY after verify_token + recheck pass. No
        bearer token is produced — the proxy forwards the connection to the bound destination."""
        eff = effect_from_request(req)
        return AuthorizationResult(
            True, f"admit egress {eff.protocol} to {eff.target()} (chain {token.chain_hash[:12]})",
            payment_ref=None, rail=self.rail)
