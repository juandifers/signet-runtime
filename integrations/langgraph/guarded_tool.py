"""The LangGraph binding: a guarded tool that routes a LangGraph agent's irreversible tool
call through the orchestrator-agnostic `EffectInterceptor`, and the ESCALATE -> `interrupt()`
bridge that surfaces escalations to LangGraph's human-in-the-loop.

  ALLOW    -> return the rail's success result to the graph state.
  BLOCK    -> return a STRUCTURED refusal to the graph state. The model may retry; the gate
              contains every retry. NEVER execute (A3 — the wrapper can only deny/escalate
              relative to what the rail authorizes; it never turns a rail BLOCK into a pass).
  ESCALATE -> raise LangGraph `interrupt(...)` with {cause, candidates, escalation_source}. On
              resume (`Command(resume=<approval>)`) the interceptor RE-GATES the human's choice
              and authorizes the FROZEN bound effect — the kernel re-checks the effect-key at
              authorize time, so a post-approval force-push / base swap yields a different
              effect-key and is BLOCKED by the unmodified kernel. This is the explicit upgrade
              over LangGraph's native `interrupt_after` (which acts before pause) and its lack
              of exactly-once.

`langgraph` is imported lazily inside the tool body, ONLY on the ESCALATE path — so building +
calling a guarded tool on the ALLOW/BLOCK paths needs no langgraph at all.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from integrations.effect_gateway.seam import Decision, EffectInterceptor, Outcome, ProposedEffect


@dataclass(frozen=True)
class GuardedResult:
    """What a guarded tool returns to the graph state. `status` is merged | blocked | escalated;
    `decision` is the underlying seam `Decision` (the signed receipt rides on it)."""
    status: str
    cause: str
    outcome: str
    escalation_source: str = ""
    bound_target: str = ""
    check_ref: Optional[str] = None
    candidates: tuple = ()
    decision: Optional[Decision] = None

    @classmethod
    def of(cls, status: str, d: Decision) -> "GuardedResult":
        return cls(status=status, cause=d.cause, outcome=d.outcome.value,
                   escalation_source=d.escalation_source, bound_target=d.bound_target,
                   check_ref=d.check_ref, candidates=tuple(d.candidates), decision=d)


def _status_for(outcome: Outcome) -> str:
    return {Outcome.ALLOW: "merged", Outcome.BLOCK: "blocked",
            Outcome.ESCALATE: "escalated"}[outcome]


def signet_guarded_tool(interceptor: EffectInterceptor, *, tool_name: str = "merge_pr",
                        id_arg: str = "pr",
                        world_getter: Optional[Callable[[], object]] = None) -> Callable:
    """Wrap an irreversible agent tool so every call is contained by the rail pipeline.

    The returned callable takes the model's tool args (`{id_arg: <picked id>, ...}`), builds a
    `ProposedEffect`, and intercepts it. The model's pick is UNTRUSTED — it becomes, at most, a
    Role-B candidate the gate clamps. `world_getter` supplies the CURRENT runtime world (so a
    resume re-reads it and a force-push is caught); it defaults to the interceptor's world.
    """
    def _world():
        return world_getter() if world_getter is not None else interceptor.world

    def guarded(**args) -> GuardedResult:
        eff = ProposedEffect(tool=tool_name, args=dict(args))
        pick = args.get(id_arg)
        world = _world()
        decision = interceptor.intercept(eff, proposer=pick, world=world)

        if decision.outcome is not Outcome.ESCALATE:
            return GuardedResult.of(_status_for(decision.outcome), decision)

        # ESCALATE -> hand off to LangGraph's human-in-the-loop. Lazy import keeps the
        # ALLOW/BLOCK paths langgraph-free.
        from langgraph.types import interrupt
        approval = interrupt({
            "reason": "signet_escalation",
            "cause": decision.cause,
            "candidates": list(decision.candidates),
            "escalation_source": decision.escalation_source,
            "tool": tool_name,
            "args": dict(args),
        })
        # Resumed with the human's approval. Re-read the CURRENT world: a bound-field mutation
        # since escalation changes the effect-key and the kernel blocks it on authorize.
        final = interceptor.resume(eff, decision, approval,
                                   frozen_world=world, current_world=_world())
        return GuardedResult.of(_status_for(final.outcome), final)

    guarded.__name__ = f"signet_guarded_{tool_name}"
    guarded.tool_name = tool_name
    guarded.interceptor = interceptor
    return guarded
