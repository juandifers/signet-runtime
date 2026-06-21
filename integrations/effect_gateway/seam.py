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


_SHAPES = frozenset({"resolution", "admission"})


@runtime_checkable
class RailBinding(Protocol):
    """Adapts ONE certified rail to the seam. The GitHub binding wraps the existing merge
    pipeline; it rewrites NO rail logic and ships NO fence of its own.

    A binding declares its `shape` — the rail FAMILY the seam routes by (the reshape that
    SEAM-SHAPE-OVERFIT earned, confirmed by two independent admission rails):

      * "resolution" — pick one owned candidate out of a `world`, then authorize the bound
        effect. `proposal_for` returns a Role-B `Resolver`; the bound effect is authorized
        through the seam's single `env.verifier`; cardinality>=2 / a human-approval tier can
        `resume`. (merge)
      * "admission"  — the effect is SELF-DESCRIBING (a destination, a db op); the only
        question is admit-or-deny. `proposal_for` is an honest identity-prepare (returns the
        effect); the kernel policy is EFFECT-SCOPED, so the binding mints a PER-EFFECT verifier
        (it does NOT read `env.verifier`); admission is binary — there is NO `resume`, and the
        seam REFUSES one structurally (RESUME-SHAPE-GATED). (egress, supabase)

    The verifier is therefore BINDING-DETERMINED and correlates with shape — the seam no longer
    claims one authoritative `env.verifier` (face 2 of the over-fit, now honest in the contract).
    """
    name: str
    shape: str                       # "resolution" | "admission"  (the rail family the seam routes by)

    def handles(self, eff: ProposedEffect) -> bool: ...

    def proposal_for(self, proposal):
        """Prepare the UNTRUSTED proposal into what `submit` consumes.

        - resolution rails: coerce a RAW agent pick (an owned id, an iterable of ids, or None)
          into the rail's Role-B `Resolver`, so the EXISTING resolve_task_mandate runs the clamp
          + cardinality + gate on it. A `Resolver` (anything with `.resolve`) passed to the seam
          is used as-is (the `_is_resolver` path).
        - admission rails: return the SELF-DESCRIBING effect — an honest identity-prepare, since
          there is no candidate set to pick from (the operation is read from `eff.args` in
          `submit`)."""
        ...

    def submit(self, eff: ProposedEffect, *, mandate, world, env, bridge, receipts,
               proposal) -> "Decision": ...


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
        shape = getattr(binding, "shape", None)
        if shape not in _SHAPES:               # SHAPE-COMPLETENESS: unknown/absent shape fails closed
            return Decision(Outcome.BLOCK,
                            f"rail binding for tool {eff.tool!r} declares no known shape "
                            f"(got {shape!r}; expected one of {sorted(_SHAPES)})",
                            escalation_source="no_binding")
        w = world if world is not None else self.world
        try:
            # Route by shape (no universal resolver coercion): resolution rails accept a pre-built
            # Role-B resolver as-is (`_is_resolver`) or wrap a raw pick; admission rails prepare the
            # self-describing effect. `submit`'s `proposal` is what the rail consumes.
            if shape == "resolution":
                proposal = proposer if _is_resolver(proposer) else binding.proposal_for(proposer)
            else:                              # "admission" — honest identity-prepare, no candidate set
                proposal = binding.proposal_for(proposer)
            return binding.submit(eff, mandate=self.mandate, world=w, env=self.env,
                                  bridge=self.bridge, receipts=self.receipts, proposal=proposal)
        except Exception as e:                 # A7 fail closed: a crash is a rejection, not a pass
            return Decision(Outcome.BLOCK, f"fail-closed (binding raised: {e})",
                            escalation_source="gate_contained")

    def resume(self, eff: ProposedEffect, decision: Decision, approval, *,
               frozen_world, current_world=None) -> Decision:
        """Continue an ESCALATE after a human resumed (LangGraph `Command(resume=...)`, the local
        gate's approval, etc.). The handling binding RE-GATES the human's choice and authorizes
        the FROZEN bound effect against the current world — the kernel re-checks the effect-key, so
        a post-approval mutation is blocked. Approval never widens authority (A3). Fail closed.

        RESUME-SHAPE-GATED: only RESOLUTION rails escalate, so resume is valid only for them. The
        seam REFUSES a resume on an admission binding structurally (not by duck-typing `resume`):
        NO-ESCALATE-V0 for egress + supabase is a seam-level guarantee, not merely an absent method."""
        binding = self._binding_for(eff)
        if binding is None or getattr(binding, "shape", None) != "resolution":
            return Decision(Outcome.BLOCK,
                            f"resume not valid for tool {eff.tool!r} (only resolution rails escalate)",
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
