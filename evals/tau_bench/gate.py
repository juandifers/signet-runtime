"""The Signet action gate for tau-bench retail, by composition (kernel UNCHANGED).

``GatedRetailEnv`` subclasses tau-bench's ``MockRetailDomainEnv`` and overrides
``step()`` so that, BEFORE a high-impact WRITE tool mutates the database, the call
is routed through the real Signet verifier (via ``RetailSignetHarness``). This is
the exact analog of ``SignetGatedToolsExecutor`` in the agentdojo harness:

    APPROVED  -> delegate to the real tool (state mutates as usual)
    BLOCKED   -> return a refusal observation; state is NOT mutated (fail closed)

Read-only tools pass straight through. A replay-guard ensures tau-bench's reward
computation (which replays the ground-truth actions to compare DB hashes) is NEVER
gated -- otherwise the gate would corrupt the reward signal.

The decision combines, per proposed high-impact call:
  1. STANDING POLICY structural check (ownership / refund-method / status) against
     the DB snapshot -- a fixed authorization rule, so tool data can only fail a
     check, never widen what is allowed (the §2c discipline).
  2. TRUSTED-INTENT envelope membership -- is (tool, named order) in the frozen,
     instruction-derived envelope?
Admitted iff BOTH hold; the kernel then enforces context-binding + allowlist +
consume-once over the effect key. Every BLOCK is produced by the real verifier.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .tau_path import ensure_on_path

ensure_on_path()
from tau_bench.envs.retail import MockRetailDomainEnv  # noqa: E402
from tau_bench.types import (Action, EnvInfo, EnvResponse,  # noqa: E402
                             RESPOND_ACTION_NAME)

from .retail_intent import (HIGH_IMPACT_TOOLS, RetailEnvelope,  # noqa: E402
                            RetailStandingPolicy, DEFAULT_RETAIL_POLICY,
                            effect_action, SELF_TARGET)
from .resolve import resolve_target, ENDORSE, REVIEW, BLOCK  # noqa: E402
from .signet_retail_harness import (RetailSignetHarness, effect_key,  # noqa: E402
                                    NO_AUTHORIZED_EFFECT)


def _target_id(tool: str, kwargs: dict) -> Optional[str]:
    """The id the effect binds to: order_id for order tools, user_id for the
    profile tool."""
    if tool == "modify_user_address":
        return kwargs.get("user_id")
    return kwargs.get("order_id")


@dataclass
class GateRecord:
    task_index: int
    tool: str
    target: Optional[str]
    truth_authorized: bool      # in tau-bench ground-truth actions (the truth)
    approved: bool              # the gate's verdict
    cause: str                  # why (structural / out-of-envelope / kernel reason)
    in_envelope: bool           # trusted-intent envelope membership (literal mode)
    structural_ok: bool
    resolution: str = ""        # predicate mode: ENDORSE / REVIEW / BLOCK (else "literal")
    endorsed: Optional[str] = None   # the endorsed order id (predicate mode)


class GatedRetailEnv(MockRetailDomainEnv):
    """A retail env whose high-impact writes are gated by the real Signet kernel."""

    def __init__(self, *args, harness: RetailSignetHarness,
                 policy: RetailStandingPolicy = DEFAULT_RETAIL_POLICY,
                 mode: str = "predicate", **kwargs):
        super().__init__(*args, **kwargs)
        self._harness = harness
        self._policy = policy
        # "predicate" = endorsed-value resolution (§4); "literal" = the §3
        # (tool, named-order) membership binding, kept for A/B comparability.
        self._mode = mode
        self._replaying = False
        self._envelope: RetailEnvelope = RetailEnvelope()
        self._principal: Optional[str] = None
        self._gt_effects: frozenset = frozenset()
        self.records: list[GateRecord] = []

    # -- per-task binding (called by the runner before solving) --

    def begin_task(self, envelope: RetailEnvelope) -> None:
        """Freeze the trusted-intent envelope and bind the authenticated principal
        BEFORE the agent acts (plan-then-execute). The principal is the persona the
        task fixes (established by the trusted name+zip handshake); tau-bench sets
        task.user_id to exactly that user, so it is trusted config, not tool output
        an injection could steer."""
        self._harness.reset_episode()
        self._envelope = envelope
        self._principal = self.task.user_id
        self._gt_effects = frozenset(
            (effect_action(a.name), str(_target_id(a.name, a.kwargs) or "").strip().upper())
            for a in self.task.actions if a.name in HIGH_IMPACT_TOOLS
        )

    # -- reward: never gate the ground-truth replay --

    def calculate_reward(self):
        self._replaying = True
        try:
            return super().calculate_reward()
        finally:
            self._replaying = False

    # -- the gate --

    def step(self, action: Action) -> EnvResponse:
        if self._replaying or action.name not in HIGH_IMPACT_TOOLS:
            return super().step(action)

        tool = action.name
        kwargs = action.kwargs or {}
        target = _target_id(tool, kwargs)
        # bind the canonical EFFECT class (P1), not the raw tool name
        proposed = effect_key(effect_action(tool), target)

        target_up = str(target or "").strip().upper()

        # (1) standing-policy structural check (fixed rule; reads DB only for facts).
        # Applies in BOTH modes: a wrong refund method / foreign owner / bad status is
        # blocked regardless of how the target was authorized (defense in depth).
        structural_ok, sreason = self._policy.check(
            self.data, self._principal, tool, kwargs)

        # (2) authorization: literal envelope membership (§3, --mode literal) OR the
        # endorsed-value resolution (§4, --mode predicate). ``bound`` is the effect
        # the kernel will require; context-binding then compares it to ``proposed``.
        resolution_kind = "literal"
        endorsed = None
        res_reason = ""
        if self._mode == "literal":
            in_env = self._envelope.authorizes(tool, target)
            admitted = structural_ok and in_env
            bound = proposed if admitted else NO_AUTHORIZED_EFFECT
            res_reason = "out-of-envelope: not authorized by trusted intent"
        else:
            res = resolve_target(self._envelope.predicate_for(tool), tool,
                                 self._principal, self.data)
            resolution_kind, res_reason = res.kind, res.reason
            in_env = (res.kind == ENDORSE)
            if not structural_ok:
                admitted, bound = False, NO_AUTHORIZED_EFFECT
            elif res.kind != ENDORSE:                      # REVIEW or BLOCK
                admitted, bound = False, NO_AUTHORIZED_EFFECT
            elif res.endorsed == SELF_TARGET:              # modify_user_address -> self
                endorsed, bound, admitted = target_up, proposed, True
            elif res.selector_all:                         # admit iff proposed in owned set
                if target_up in {m.upper() for m in res.matched}:
                    endorsed, bound, admitted = target_up, effect_key(effect_action(tool), target_up), True
                else:
                    admitted, bound = False, NO_AUTHORIZED_EFFECT
                    res_reason = "out-of-predicate: proposed not in authorized owned set"
            else:                                          # unique / disambiguated id
                # Bind the ENDORSED id; the kernel compares it to the agent's PROPOSED
                # id via context-binding (proposed != endorsed -> kernel blocks).
                endorsed, bound, admitted = res.endorsed, effect_key(effect_action(tool), res.endorsed), True

        pid = self._harness.register_policy([bound] if admitted else [])
        req = self._harness.build_request(
            policy_id=pid, bound_effect=bound, proposed_effect=proposed,
            task_id=str(self.task_index))
        outcome = self._harness.decide(req)

        # cause label (most-specific first)
        if outcome.approved:
            cause = f"approved (endorsed {endorsed})" if endorsed and endorsed != target_up else "approved"
        elif not structural_ok:
            cause = f"structural: {sreason}"
        elif resolution_kind == REVIEW:
            cause = f"review: {res_reason}"
        elif resolution_kind in (BLOCK, "literal") and not in_env:
            cause = res_reason
        else:
            cause = outcome.reason   # admitted but kernel blocked: context-binding / replay

        truth_auth = (effect_action(tool), target_up) in self._gt_effects
        self.records.append(GateRecord(
            task_index=self.task_index, tool=tool, target=target,
            truth_authorized=truth_auth, approved=outcome.approved, cause=cause,
            in_envelope=in_env, structural_ok=structural_ok,
            resolution=resolution_kind, endorsed=endorsed))

        if outcome.approved:
            return super().step(action)   # real side effect
        # fail closed: refusal observation, NO mutation, conversation continues
        return EnvResponse(
            observation=(f"[SIGNET BLOCKED] This action was not executed: {cause}. "
                         "Inform the user it could not be completed."),
            reward=0.0, done=False, info=EnvInfo(task=self.task, source=tool))
