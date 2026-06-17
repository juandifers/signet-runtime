"""The orchestrator-agnostic seam — the control-plane primitive.

Given a proposed `(tool, args)` from ANY agent runtime, the `EffectInterceptor`:
  (a) canonicalizes it to a rail Effect (via the handling `RailBinding`),
  (b) REFUSES to trust the proposal — it becomes, at most, a Role-B candidate pick,
  (c) drives the EXISTING rail pipeline (resolve-bounded-to-own -> gate -> authorizer),
  (d) returns one `Decision`: ALLOW (effect authorized + receipt) / BLOCK (contained +
      receipt) / ESCALATE (ambiguous or a human-approval tier + the owned candidate set).

This module is orchestrator-agnostic (no LangGraph import) AND rail-agnostic (no kernel edit
and no GitHub import — the rail specifics live behind a `RailBinding`). The seam never
executes an effect itself: ALLOW means the rail's AUTHORIZER concluded the effect.

The mandate is loaded + frozen by the CALLER before any world/proposal is read (Role-A
isolation, mirroring `l3_run`'s "load the grant FIRST"). The seam never ingests runtime data
into the mandate or the fence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class ProposedEffect:
    """What an agent runtime PROPOSES. UNTRUSTED — never acted on directly. The seam turns it
    into a Role-B candidate pick the rail gate clamps; it is never a license to act."""
    tool: str
    args: dict = field(default_factory=dict)


class Outcome(Enum):
    ALLOW = "allow"          # the effect was AUTHORIZED (the rail authorizer concluded success)
    BLOCK = "block"          # contained: off-fence / not-owned / no-match / kernel-blocked / replay
    ESCALATE = "escalate"    # ambiguous (cardinality>=2 / structural) or a human-approval tier


@dataclass(frozen=True)
class Decision:
    """The seam's single, signed-receipt-bearing verdict for one proposed effect."""
    outcome: Outcome
    cause: str
    candidates: tuple = ()            # owned ids surfaced on ESCALATE (NEVER an attacker id)
    receipt: object = None            # the signed receipt appended for THIS decision
    escalation_source: str = ""       # resolved | layer_a_structural | layer_b_cardinality |
                                      # gate_contained | no_match | human_approval_tier |
                                      # kernel_blocked | no_binding
    bound_target: str = ""            # the effect-key/target when RESOLVED
    tier: str = ""                    # the rail tier that decided (auto / approve / cosign / deny)
    check_ref: Optional[str] = None   # the rail capability ref (Check Run id) when one was posted

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW


@runtime_checkable
class RailBinding(Protocol):
    """Adapts ONE certified rail to the seam. The GitHub binding wraps the existing merge
    pipeline; it rewrites NO rail logic and ships NO fence of its own."""
    name: str

    def handles(self, eff: ProposedEffect) -> bool: ...

    def resolver_for(self, proposal):
        """Coerce a RAW agent pick (an owned id, an iterable of ids, or None) into the rail's
        Role-B `Resolver`, so the EXISTING resolve_task_mandate runs the clamp + cardinality +
        gate on it. A `Resolver` (anything with `.resolve`) passed to the seam is used as-is."""
        ...

    def submit(self, eff: ProposedEffect, *, mandate, world, env, bridge, receipts,
               resolver) -> "Decision": ...


def _is_resolver(obj) -> bool:
    """A proposer is already a Role-B Resolver if it exposes `.resolve(criterion, candidates)`.
    Otherwise it is a RAW pick the binding wraps into one."""
    return callable(getattr(obj, "resolve", None))


class EffectInterceptor:
    """The control-plane primitive. Holds the TRUSTED frozen mandate (Role A) and a set of
    `RailBinding`s. An agent's proposal becomes, at most, a Role-B candidate pick; containment
    is the rail pipeline, never the proposal."""

    def __init__(self, mandate, bindings, *, env, bridge, receipts, world=None):
        self.mandate = mandate                 # the frozen Role-A grant (OpenMandate-shaped)
        self.bindings = list(bindings)
        self.env = env
        self.bridge = bridge
        self.receipts = receipts
        self.world = world                     # default runtime world (override per-intercept)

    def _binding_for(self, eff: ProposedEffect) -> Optional[RailBinding]:
        for b in self.bindings:
            try:
                if b.handles(eff):
                    return b
            except Exception:                  # a misbehaving binding never crashes the gate
                continue
        return None

    def intercept(self, eff: ProposedEffect, *, proposer, world=None) -> Decision:
        """Route ONE proposed effect through the rail pipeline. `proposer` is either a Role-B
        `Resolver` (used as-is — test/CI path) or a RAW agent pick the handling binding wraps.
        `world` overrides the interceptor's default runtime world (used on resume so a
        post-approval mutation is re-read). Fail closed: an unhandled effect, or any raising
        step, is a BLOCK — never an execute."""
        binding = self._binding_for(eff)
        if binding is None:
            return Decision(Outcome.BLOCK, f"no rail binding handles tool {eff.tool!r}",
                            escalation_source="no_binding")
        w = world if world is not None else self.world
        try:
            resolver = proposer if _is_resolver(proposer) else binding.resolver_for(proposer)
            return binding.submit(eff, mandate=self.mandate, world=w, env=self.env,
                                  bridge=self.bridge, receipts=self.receipts, resolver=resolver)
        except Exception as e:                 # A7 fail closed: a crash is a rejection, not a pass
            return Decision(Outcome.BLOCK, f"fail-closed (binding raised: {e})",
                            escalation_source="gate_contained")

    def resume(self, eff: ProposedEffect, decision: Decision, approval, *,
               frozen_world, current_world=None) -> Decision:
        """Continue an ESCALATE after a human resumed (LangGraph `Command(resume=...)`, the local
        gate's approval, etc.). The handling binding RE-GATES the human's choice and authorizes
        the FROZEN bound effect against the current world — the kernel re-checks the effect-key, so
        a post-approval mutation is blocked. Approval never widens authority (A3). Fail closed."""
        binding = self._binding_for(eff)
        if binding is None or not hasattr(binding, "resume"):
            return Decision(Outcome.BLOCK, f"no rail binding can resume tool {eff.tool!r}",
                            escalation_source="no_binding")
        try:
            return binding.resume(eff, decision, approval, mandate=self.mandate,
                                  frozen_world=frozen_world,
                                  current_world=current_world if current_world is not None
                                  else (frozen_world if self.world is None else self.world),
                                  env=self.env, bridge=self.bridge, receipts=self.receipts)
        except Exception as e:
            return Decision(Outcome.BLOCK, f"fail-closed (resume raised: {e})",
                            escalation_source="gate_contained")
