"""The egress authorizer — a Role-2 authorizer that admits an outbound connection inline, now a
COMPOSITION over the rail algebra (signet.rail_algebra): PatternAllowlist (Policy) × EffectKeyOneShot
(Bind) × NetworkSolePath (Door).

It still subclasses the UNCHANGED `signet.authorizers.base.Authorizer` and fills ONLY the two content
hooks; `base.authorize` owns `verify_token -> recheck_against_context -> produce_capability` and the
fail-closed flow. What changed is that the two hooks now DELEGATE to the composition rather than
carrying bespoke enforcement control flow:

  * recheck_against_context = Bind.recheck (TOCTOU: chain_hash bound + effect == signed Cart) +
    frozen-mandate lifecycle, THEN Policy.decide (destination within mandate ∩ standing, with the
    raw-IP literal admitted only on a TRUSTED-resolution match). The rail supplies the field-level
    content (which fields bind, which host patterns match) — the same discipline role_b uses for its
    gate predicates; the ORDER + fail-closed live in the algebra/template.
  * produce_capability = Door.enforce — NetworkSolePath wraps the inline admission (no bearer token;
    the proxy forwards the bytes). Its soundness is ADVISORY in v0 (no netns) — ONLY-DOOR-OR-DECLARE.

The exact cause strings are preserved (the broker/receipts + tests read them), so behavior is
unchanged (BEHAVIOR-PRESERVED). No kernel logic leaks here; this rail never edits the kernel, the
authorizer template, or netns.py.
"""
from __future__ import annotations

import datetime as _dt
from typing import Callable, Dict, Optional, Tuple

from ...authorizers.base import AuthorizationResult, Authorizer
from ... import chain
from ...models import ExecutionRequest, ExecutionToken
from ...broker.mandate import MandateProvider
from ...rail_algebra import (Capability, Composition, Effect, EffectKeyOneShot, NetworkSolePath,
                             PatternAllowlist)
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
        # ---- the rail algebra composition (assembled once; reused per admission) ----
        self.composition = Composition(
            policy=PatternAllowlist(name="egress", project_features=self._project_features),
            bind=EffectKeyOneShot(recheck_fn=self._chain_bound),
            door=NetworkSolePath(admit=self._admit, sole_path=False),   # v0: advisory (no netns)
            name="egress",
        )

    # -- Bind content: which fields bind (the TOCTOU/freshness gate) --
    def _chain_bound(self, token: ExecutionToken, req: ExecutionRequest) -> bool:
        """The kernel context-bind: the token is bound to THIS exact connection and the runtime
        effect equals the signed Cart effect. Returns bool; the rail derives the reason on failure."""
        if chain.chain_hash(req.intent, req.cart, req.payment) != token.chain_hash:
            return False
        return (req.cart.destination_account == req.context.destination_account
                and req.cart.recipient == req.context.recipient
                and req.cart.action == req.context.action)

    def _bind_reason(self, token: ExecutionToken, req: ExecutionRequest) -> Optional[str]:
        """Telemetry: WHY the chain-bind failed (the rail's binding-field labels)."""
        if chain.chain_hash(req.intent, req.cart, req.payment) != token.chain_hash:
            return "unbound-token"
        return "effect-context-mismatch"

    # -- Policy content: project the destination to the OWN ceiling/grant + trusted-resolution booleans --
    def _project_features(self, mandate, eff: EgressEffect) -> Dict:
        if is_ip_literal(eff.host):
            return {"agent_host": eff.host, "port": eff.port, "is_ip_literal": True,
                    "raw_ip_resolved_match": self._raw_ip_in_resolved_allowset(eff, mandate),
                    "in_standing": False, "in_mandate": False}
        return {"agent_host": eff.host, "port": eff.port, "is_ip_literal": False,
                "raw_ip_resolved_match": False,
                "in_standing": self._standing.permits(eff),
                "in_mandate": mandate.permits(eff)}

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

    # -- Door content: the inline admission (no bearer token; the proxy forwards) --
    def _admit(self, cap) -> Tuple[bool, str, Optional[str]]:
        token, eff = cap.handle, cap.effect
        return (True,
                f"admit egress {eff.protocol} to {eff.target()} (chain {token.chain_hash[:12]})",
                None)

    # ============================================================================
    # the two template hooks (base.Authorizer.authorize owns verify_token + the order)
    # ============================================================================
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        # Bind — TOCTOU freshness (chain_hash bound + effect == signed Cart).
        if not self.composition.bind.recheck(token, req):
            return False, self._bind_reason(token, req)

        # Bind — frozen-mandate lifecycle (the capability's authorization envelope).
        eff = effect_from_request(req)
        mandate = self._mandates.get(req.context.task_id)
        if mandate is None:
            return False, "no-frozen-mandate"
        self.last_mandate_hash = mandate.mandate_hash()
        if mandate.is_expired(self._clock()):
            return False, "mandate-expired"

        # Policy — destination within mandate ∩ standing (raw-IP via trusted resolution).
        verdict = self.composition.policy.decide(
            self.composition.policy.project(mandate, eff))
        return verdict.is_allow, verdict.reason

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        """The inline admission decision via the Door. Reached ONLY after verify_token + recheck
        pass. No bearer token is produced — the proxy forwards the connection to the bound
        destination."""
        eff = effect_from_request(req)
        cap = Capability(effect=eff, lifecycle=self.composition.bind.lifecycle(), handle=token)
        outcome = self.composition.door.enforce(cap)
        if isinstance(outcome, Effect):
            return AuthorizationResult(True, outcome.detail, payment_ref=outcome.ref, rail=self.rail)
        return AuthorizationResult(False, outcome.reason, payment_ref=outcome.ref, rail=self.rail)


# Keep `effective_admits` reachable for any caller that imported it via this module historically.
__all__ = ["EgressAuthorizer", "effective_admits"]
