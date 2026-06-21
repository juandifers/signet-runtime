"""Authorizer interface — now a CONCRETE TEMPLATE METHOD so containment is STRUCTURAL, not
convention.

The verifier decides; an Authorizer turns that decision into a rail-specific *necessary input* for
the irreversible action. The principle: the agent must hold no standalone capability to reach the
irreversible step — every path is either a co-signature the enforcer must contribute or a
credential the enforcer mints just-in-time. The verifier stays rail-agnostic; only the authorizer
is per-rail.

Previously every authorizer re-implemented the same opening: verify the enforcer token, then
independently re-check the runtime effect vs the signed Cart, then act. That was CONVENTION — a
rail that "forgot" `verify_token` still satisfied the old ABC (inventory GAP #6). Now `authorize`
is a FINAL template that OWNS that order:

    verify_token  ->  recheck_against_context  ->  produce_capability

A rail fills in only the two content hooks; it CANNOT skip the token check or run before the
re-check. `produce_capability` is reached ONLY when both guards pass. A rail whose
`produce_capability` would mint unconditionally still cannot execute on an invalid token or a
context mismatch — the template blocks it first.

Cosigners (xrpl/mpc) deliberately OVERRIDE `authorize` to `raise` (their real path is `cosign(...)`,
a different signature); they implement the hooks trivially. Bringing the cosign path under an
analogous template is a separate, flagged pass.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from ..models import ExecutionRequest, ExecutionToken
from ..rail_algebra import phase_scope


@dataclass
class AuthorizationResult:
    executed: bool
    reason: str
    payment_ref: Optional[str] = None
    rail: str = ""


# ============================================================================
# Schedule-driven dispatch (PROMOTION.md) — the composed-rail half of authorize()
# ============================================================================
@dataclass(frozen=True)
class ComponentOutcome:
    """A GATE component's verdict on the driven path: did it pass, and (on failure) the cause string
    the rail surfaces. The terminal Door does not return this — it returns an AuthorizationResult."""
    ok: bool
    reason: str = ""


@dataclass
class ScheduledComponent:
    """One step of a driven schedule: the schedule LABEL it satisfies (must equal the Schedule's
    Step.component at this phase, in order — that is how the schedule DRIVES invocation) and a
    zero-arg callable. A gate component's callable returns a ComponentOutcome; the terminal Door
    component (`is_door=True`) returns the final AuthorizationResult (success OR its own fail-closed
    Blocked, exactly as the legacy produce_capability did — the Door never triggers on_rejected)."""
    label: str
    run: Callable[[], object]
    is_door: bool = False


class Authorizer(ABC):
    rail: str = "abstract"

    def __init__(self, verifier, enforcer_vk: str):
        self._verifier = verifier
        self._enforcer_vk = enforcer_vk

    # A rail that COMPOSES the algebra and DECLARES a Schedule (sets `self.composition` with a
    # non-None `.schedule`) is driven per-phase (run_phase); every other rail stays on the legacy
    # hooks below, byte-for-byte. COEXISTENCE is the safety boundary (PROMOTION.md §2).
    composition = None

    def authorize(self, token: ExecutionToken,
                  req: ExecutionRequest) -> AuthorizationResult:
        """FINAL containment flow — DO NOT override in a rail (override the hooks / components). The
        order + fail-closed live here, not in the rail:

          1. the enforcer token MUST be valid (verify_token) — else refuse;
          2a. COMPOSED rail (a declared Schedule): drive the authorizer's terminal phase via the
              Schedule (run_phase) — the components fire in declared order, fail-closed; OR
          2b. LEGACY rail: the runtime effect MUST match the signed Cart (recheck_against_context) —
              else refuse, after on_rejected — then ONLY THEN produce_capability.
        """
        if not self._verifier.verify_token(token, self._enforcer_vk):
            return AuthorizationResult(False, "Enforcer token invalid/expired.", rail=self.rail)
        composition = self.composition
        if composition is not None and getattr(composition, "schedule", None) is not None:
            # schedule-driven: the authorizer drives the phase its Door fires in (merge: AUTHORIZE;
            # egress: ADMIT). Merge's Policy at RESOLVE is NOT here — it is owned upstream by the
            # resolver seam (PHASE-ISOLATION holds structurally: run_phase only pulls steps_for the
            # driven phase, and Policy is scheduled at RESOLVE).
            return self.run_phase(composition.schedule.driven_phase(), composition, token, req)
        ok, reason = self.recheck_against_context(token, req)
        if not ok:
            self.on_rejected(token, req, reason)
            return AuthorizationResult(False, reason, rail=self.rail)
        return self.produce_capability(token, req)

    def run_phase(self, phase, composition,
                  token: ExecutionToken, req: ExecutionRequest) -> AuthorizationResult:
        """Invoke EXACTLY the components the Schedule places at `phase`, in declared order,
        fail-closed (PROMOTION.md §1). The rail supplies the per-phase components (components_for);
        this method owns the order + the fail-closed flow + the phase context, exactly as the legacy
        `authorize` owns recheck-before-produce. The SCHEDULE drives: the rail's component labels
        MUST equal the declared Step.component labels for this phase, in order — a mismatch, an
        unknown/empty-but-required phase, a missing terminal Door, or any raising component is a
        BLOCK, never a crash-through and never an implicit allow (FAIL-CLOSED)."""
        steps = composition.schedule.steps_for(phase) if phase is not None else ()
        components = self._components_for(phase, token, req)
        if not steps or [c.label for c in components] != [s.component for s in steps]:
            return AuthorizationResult(
                False, f"schedule/component mismatch at {getattr(phase, 'name', phase)}",
                rail=self.rail)
        *gates, last = components
        with phase_scope(phase):
            for comp in gates:
                try:
                    outcome = comp.run()
                except Exception as e:                      # FAIL-CLOSED on a raising gate
                    self.on_rejected(token, req, f"{comp.label}: {e}")
                    return AuthorizationResult(False, f"{comp.label} raised: {e}", rail=self.rail)
                if not outcome.ok:                          # a gate refused -> rail-native record + deny
                    self.on_rejected(token, req, outcome.reason)
                    return AuthorizationResult(False, outcome.reason, rail=self.rail)
            if not last.is_door:                            # the terminal step must be the Door
                return AuthorizationResult(False, "schedule has no terminal Door", rail=self.rail)
            try:
                return last.run()                           # the Door owns the final AuthorizationResult
            except Exception as e:                          # FAIL-CLOSED on a raising Door
                return AuthorizationResult(False, f"door raised: {e}", rail=self.rail)

    def _components_for(self, phase, token: ExecutionToken,
                        req: ExecutionRequest) -> List[ScheduledComponent]:
        """A COMPOSED rail returns the ordered ScheduledComponents it places at `phase` (labels must
        match its declared Schedule). Legacy rails never reach run_phase, so the default is empty.

        PRIVATE on purpose: this is internal driving plumbing, NOT a public content hook. A rail's
        public content surface stays exactly the two hooks (recheck_against_context /
        produce_capability) — `_components_for` only re-expresses the SAME content as ordered,
        phase-tagged steps so the Schedule can drive it. (demos/two_functions_proof.py treats
        underscore-prefixed methods as private helpers — the two-functions claim is preserved.)"""
        return []

    @abstractmethod
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        """Independently re-check the runtime effect against the signed Cart + that the token is
        bound to THIS exact transaction. Return (ok, reason). MUST NOT have an irreversible side
        effect — it runs before the capability is produced and may be followed by `on_rejected`."""
        ...

    @abstractmethod
    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        """Mint/execute the rail's necessary input — reached ONLY when verify_token AND
        recheck_against_context both pass."""
        ...

    def on_rejected(self, token: ExecutionToken, req: ExecutionRequest, reason: str) -> None:
        """Optional rail-native record of a rejection (e.g. conclude a Check Run / deploy gate as
        failure). Default: no-op. Must not change the (False) verdict."""
        return None
