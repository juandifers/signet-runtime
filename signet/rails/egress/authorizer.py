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

from ...authorizers.base import (AuthorizationResult, Authorizer, ComponentOutcome,
                                 ScheduledComponent)
from ... import chain
from ...models import ExecutionRequest, ExecutionToken
from ...broker.mandate import MandateProvider
from ...rail_algebra import (Capability, Composition, EGRESS_SCHEDULE, Effect, EffectKeyOneShot,
                             NetworkSolePath, PatternAllowlist, Phase, phase_scope)
from ...rail_algebra.schedule import BIND, DOOR, POLICY, mark
from .chain_adapter import effect_from_request
from .effect import EgressEffect
from .mandate import EgressStandingPolicy, effective_admits
from .resolver import TrustedResolver, is_ip_literal


class MandateFreshness:
    """A Bind-class lifecycle component (marks BIND, fires @ ADMIT): the frozen task mandate EXISTS
    and is NOT expired, recording `last_mandate_hash` as a side effect. It promotes the two formerly
    INLINE egress lifecycle guards (no-frozen-mandate / mandate-expired) into a first-class scheduled
    component (PROMOTION.md A2), so (a) the driven ADMIT phase still enforces them
    (COMPONENT-COMPLETENESS — no guard silently dropped), and (b) the schedule faithfully MODELS what
    runs (it is a marked BIND step between Bind and Policy in EGRESS_SCHEDULE), dissolving the
    disclosure asymmetry the schedule verification flagged. The two guards + the side effect live in
    the rail's `check` callable; this component only marks + adapts the verdict."""

    label = BIND

    def __init__(self, check: Callable[[], Tuple[bool, str]]):
        self._check = check

    def invoke(self) -> ComponentOutcome:
        mark(BIND)                                          # phase from the rail's active phase_scope
        ok, reason = self._check()
        return ComponentOutcome(ok, reason)


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
            schedule=EGRESS_SCHEDULE,    # all three axes @ ADMIT (the inline-admission shape)
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
    # the ADMIT-phase components (the single source of truth for Bind / MandateFreshness / Policy /
    # Door; shared by the schedule-driven path and the legacy hooks; the caller sets the phase_scope)
    # ============================================================================
    def _check_mandate_freshness(self, req: ExecutionRequest) -> Tuple[bool, str]:
        """The frozen-mandate lifecycle guard: the mandate EXISTS and is NOT expired (and record its
        hash). The body MandateFreshness wraps — preserves the two guards + the side effect exactly
        as the formerly-inline code did (BEHAVIOR-PRESERVED / COMPONENT-COMPLETENESS)."""
        mandate = self._mandates.get(req.context.task_id)
        if mandate is None:
            return False, "no-frozen-mandate"
        self.last_mandate_hash = mandate.mandate_hash()     # PRESERVE the side effect
        if mandate.is_expired(self._clock()):
            return False, "mandate-expired"
        return True, "mandate-fresh"

    def _bind_outcome(self, token: ExecutionToken, req: ExecutionRequest) -> ComponentOutcome:
        """Bind @ ADMIT: EffectKeyOneShot.recheck (TOCTOU: chain_hash bound + effect == signed Cart)."""
        if self.composition.bind.recheck(token, req):
            return ComponentOutcome(True)
        return ComponentOutcome(False, self._bind_reason(token, req))

    def _policy_outcome(self, req: ExecutionRequest) -> ComponentOutcome:
        """Policy @ ADMIT: destination within mandate ∩ standing (raw-IP via trusted resolution).
        The mandate is guaranteed present here — MandateFreshness gates it earlier in the schedule."""
        eff = effect_from_request(req)
        mandate = self._mandates.get(req.context.task_id)
        verdict = self.composition.policy.decide(self.composition.policy.project(mandate, eff))
        return ComponentOutcome(verdict.is_allow, verdict.reason)

    def _door_result(self, token: ExecutionToken,
                     req: ExecutionRequest) -> AuthorizationResult:
        """Door @ ADMIT: the inline admission via NetworkSolePath. Returns the final
        AuthorizationResult; never calls on_rejected (matches the legacy produce_capability)."""
        eff = effect_from_request(req)
        cap = Capability(effect=eff, lifecycle=self.composition.bind.lifecycle(), handle=token)
        outcome = self.composition.door.enforce(cap)
        if isinstance(outcome, Effect):
            return AuthorizationResult(True, outcome.detail, payment_ref=outcome.ref, rail=self.rail)
        return AuthorizationResult(False, outcome.reason, payment_ref=outcome.ref, rail=self.rail)

    # -- COMPOSED path: the components base.run_phase drives at ADMIT, in EGRESS_SCHEDULE order
    #    (private plumbing — the public content surface stays the two hooks) --
    def _components_for(self, phase, token: ExecutionToken, req: ExecutionRequest):
        if phase is not Phase.ADMIT:
            return []
        freshness = MandateFreshness(lambda: self._check_mandate_freshness(req))
        return [
            ScheduledComponent(BIND, lambda: self._bind_outcome(token, req)),
            ScheduledComponent(BIND, freshness.invoke),     # MandateFreshness (Bind-class)
            ScheduledComponent(POLICY, lambda: self._policy_outcome(req)),
            ScheduledComponent(DOOR, lambda: self._door_result(token, req), is_door=True),
        ]

    # ============================================================================
    # the two template hooks remain DEFINED (the ABC requires them; tests assert they are in
    # EgressAuthorizer.__dict__). The composed rail reaches the components via authorize() instead;
    # these delegate to the SAME components so there is one implementation, no drift.
    # ============================================================================
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        with phase_scope(Phase.ADMIT):                      # Bind -> MandateFreshness -> Policy @ ADMIT
            out = self._bind_outcome(token, req)
            if not out.ok:
                return False, out.reason
            ok, reason = self._check_mandate_freshness(req)
            if not ok:
                return False, reason
            out = self._policy_outcome(req)
            return out.ok, out.reason

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        with phase_scope(Phase.ADMIT):                      # Door @ ADMIT
            return self._door_result(token, req)


# Keep `effective_admits` reachable for any caller that imported it via this module historically.
__all__ = ["EgressAuthorizer", "effective_admits"]
