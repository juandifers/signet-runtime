"""Generic EFFECT-KEY adapter — the §6 predicate-binding mechanism for AgentDojo's
non-payment domains (workspace, slack, travel).

These domains are NOT payments: the side effect is `(effect_class, target_id)` — an
email recipient, a shared file, a slack channel/user/url, a hotel reservation — exactly
like tau-bench retail's `(effect_class, order_id)`, not banking's `(recipient, amount)`.
So this module ports the tau-retail predicate/ownership pattern into a DOMAIN-PARAMETERIZED
form: a trusted predicate frozen from the instruction (control flow); the runtime target
endorsed over the principal's OWN bounded set (own contacts/files/users/channels, or a
queried city's hotels), bounded by the standing allowlist/budget (data flow may pick the
value; the criteria come only from the predicate). Computed-aggregate, off-allowlist,
ambiguous, and injection-channel targets ESCALATE — never guess.

The kernel binds the effect tau-style: `recipient = "{effect_class}:{target_id}"`,
`amount = price_or_1`, currency constant — REUSING `signet_harness` unchanged (the
recipient is an opaque string; no kernel edits). Banking's `gate.py`/`resolve.py`/
payment path are UNTOUCHED; this is a parallel adapter for the effect-key domains.

A `domain` here is an `EffectDomainSpec` (see `domains.py`) supplying the hooks the
generic resolver/gate call: canonicalize, own_candidates, match_descriptor,
selector_candidates, amount_for, literal_ok, authorized classes.
"""
from __future__ import annotations

from ast import literal_eval
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Optional

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import (ChatMessage, ChatToolResultMessage,
                             text_content_block_from_string)

from .gate import (AUTHORIZED_DUPLICATE, AUTHORIZED_FIRST, DIVERGENT,
                   MODE_POLICY, MODE_PREDICATE, MODE_STRICT)
from .signet_harness import NO_AUTHORIZED_TRANSFER, SignetHarness, canonical_action

# Resolution kinds + selectors (shared with the report).
ENDORSE = "ENDORSE"
REVIEW = "REVIEW"
BLOCK = "BLOCK"

SEL_NONE = "none"
SEL_CHEAPEST = "cheapest"       # min price (travel)
SEL_BEST_RATED = "best_rated"   # max rating (travel)
SEL_COMPUTED = "computed"       # an aggregate over data ("most active user") -> escalate
_SELECTORS = (SEL_NONE, SEL_CHEAPEST, SEL_BEST_RATED, SEL_COMPUTED)


@dataclass(frozen=True)
class Effect:
    """The canonical side effect (P1: bind the effect, not the tool)."""
    effect_class: str
    target_id: str
    amount_cents: int = 1            # 1 for non-priced effects; the price for travel


@dataclass(frozen=True)
class EffectPredicate:
    """A trusted, low-capacity predicate frozen from the instruction ONLY."""
    effect_class: str
    target_literal: Optional[str] = None   # a target named verbatim in the instruction
    descriptor: Optional[str] = None       # a NAME/keyword to resolve over own data
    selector: str = SEL_NONE               # cheapest/best_rated/computed (travel/aggregate)
    scope: Optional[str] = None            # a bounding scope from the instruction (e.g. a city)
    tiebreak: str = SEL_NONE               # secondary selector ("if multiple, higher price")


@dataclass
class Resolution:
    kind: str
    endorsed_target: Optional[str] = None
    endorsed_amount_cents: Optional[int] = None
    cause: str = ""
    candidates: list = field(default_factory=list)


def effect_key(effect_class: str, target_id: str) -> str:
    """The opaque string the kernel binds as the 'recipient'/destination."""
    return f"{effect_class}:{str(target_id).strip().lower()}"


# ============================================================================
# PREDICATE-mode resolver (the §4 mechanism, domain-parameterized)
# ============================================================================
def resolve_effect_predicate(pred: Optional[EffectPredicate], env, domain, *,
                             allowlist: Optional[set] = None,
                             cap_cents: Optional[int] = None) -> Resolution:
    """Endorse a runtime target over the principal's OWN bounded set. The criteria
    come only from the frozen predicate; the env supplies candidate values.
    """
    if pred is None:
        return Resolution(BLOCK, cause="out-of-predicate")
    ec = pred.effect_class
    if ec not in domain.authorized_classes:
        return Resolution(BLOCK, cause=f"out-of-envelope (effect_class {ec})")

    def _finish(target):
        amt = domain.amount_for(ec, target, env)
        if cap_cents is not None and amt is not None and amt > int(cap_cents):
            return Resolution(BLOCK, endorsed_target=target, endorsed_amount_cents=amt,
                              cause=f"over-budget ({amt} > cap {cap_cents})")
        return Resolution(ENDORSE, endorsed_target=target,
                          endorsed_amount_cents=(amt if amt is not None else 1),
                          cause="endorsed")

    # 1. literal target named in the instruction -> authorized by the instruction.
    if pred.target_literal:
        t = str(pred.target_literal).strip()
        if not domain.literal_ok(ec, t, env):
            return Resolution(BLOCK, cause="no-match (named target not found)")
        return _finish(t)

    # 2. a computed aggregate ("most active user", "channel with most users") is NOT
    #    low-capacity -> escalate, never compute-and-guess.
    if pred.selector == SEL_COMPUTED:
        return Resolution(REVIEW, cause="computed-aggregate (not low-capacity) -> review")

    # 3. a min/max SELECTOR over a bounded scope (travel: cheapest/best in a city),
    #    computed over NON-INJECTABLE fields (price/rating), tie -> review.
    if pred.selector in (SEL_CHEAPEST, SEL_BEST_RATED):
        cands = domain.selector_candidates(ec, pred.scope, env)   # [(id, price, rating)]
        if not cands:
            return Resolution(BLOCK, cause="no-match (no candidates in scope)")
        keyf = (lambda c: c[1]) if pred.selector == SEL_CHEAPEST else (lambda c: -c[2])
        cands_sorted = sorted(cands, key=keyf)
        best = keyf(cands_sorted[0])
        winners = [c for c in cands_sorted if keyf(c) == best]
        if len(winners) > 1:
            # break ties with a secondary selector from the instruction, else review.
            if pred.tiebreak in (SEL_CHEAPEST, SEL_BEST_RATED):
                k2 = (lambda c: c[1]) if pred.tiebreak == SEL_CHEAPEST else (lambda c: -c[2])
                winners = sorted(winners, key=k2)
                if k2(winners[0]) == k2(winners[1]):
                    return Resolution(REVIEW, cause="ambiguous (selector tie) -> review",
                                      candidates=[w[0] for w in winners])
            else:
                return Resolution(REVIEW, cause="ambiguous (selector tie) -> review",
                                  candidates=[w[0] for w in winners])
        return _finish(winners[0][0])

    # 4. a descriptor (a NAME/keyword) resolved over the principal's OWN data, then
    #    bounded by what the domain considers a safe/approved target (the ownership /
    #    standing-allowlist bound — e.g. internal-domain emails, existing slack users).
    if pred.descriptor:
        cands = [c for c in domain.match_descriptor(ec, pred.descriptor, env)
                 if domain.target_allowed(ec, c, env)]
        if not cands:
            return Resolution(BLOCK, cause="off-allowlist/no-match (descriptor not an own/approved target)")
        if len(set(cands)) > 1:
            return Resolution(REVIEW, cause="ambiguous (descriptor -> >1 own target) -> review",
                              candidates=list(cands))
        return _finish(cands[0])

    return Resolution(REVIEW, cause="no trusted target -> review")


# ============================================================================
# The effect-key gate (used by the tiny end-to-end sanity probe + future rollouts)
# ============================================================================
class EffectGatedToolsExecutor(BasePipelineElement):
    """Drop-in tools executor that gates a domain's HIGH-IMPACT tools through the
    unmodified Signet kernel via an effect key. STRICT/POLICY authorize the actual
    target by literal/allowlist membership; PREDICATE endorses an own-data target and
    the kernel context-binds proposed-vs-endorsed. Read-only tools pass through.
    """

    def __init__(self, harness: SignetHarness, domain, mode: str = MODE_PREDICATE,
                 output_formatter=tool_result_to_str):
        self.harness = harness
        self.domain = domain
        self.mode = mode
        self.output_formatter = output_formatter
        self.decisions: list = []
        self._predicate: Optional[EffectPredicate] = None
        self._literals: set = set()        # literal targets from the instruction (strict/policy)
        self._consumed: set = set()
        self._task_id = "?"

    def set_task(self, task_id: str, predicate: Optional[EffectPredicate],
                 literals: Optional[set] = None) -> None:
        self._task_id = task_id
        self._predicate = predicate
        self._literals = {str(x).strip().lower() for x in (literals or set())}

    def begin_episode(self) -> None:
        self.harness.reset_episode()
        self._consumed.clear()

    def _decide(self, eff: Effect):
        """Return (approved, reason, resolution, cause, endorsed_target)."""
        cap = self.domain.standing_policy.cap_cents
        actual = str(eff.target_id).strip().lower()

        if self.mode == MODE_PREDICATE:
            res = resolve_effect_predicate(self._predicate, self._env_ref, self.domain,
                                           cap_cents=cap)
            if res.kind != ENDORSE:
                return self._deny(eff, f"{res.kind}: {res.cause}", res.kind, res.cause)
            return self._authorize(eff, res.endorsed_target, res.endorsed_amount_cents,
                                   res.kind, res.cause)

        # STRICT: only a literal target from the instruction is authorized.
        if self.mode == MODE_STRICT:
            if actual in self._literals:
                return self._authorize(eff, eff.target_id, eff.amount_cents, "", "approved")
            return self._deny(eff, "STRICT: target not named in the instruction", "", "review")

        # POLICY: literal OR a standing-allowlisted target (within cap).
        if self.mode == MODE_POLICY:
            ok = actual in self._literals or self.domain.target_allowed(
                eff.effect_class, eff.target_id, self._env_ref)
            if ok and cap is not None and eff.amount_cents > int(cap):
                return self._deny(eff, "POLICY: over budget cap", "", "over-budget")
            if ok:
                return self._authorize(eff, eff.target_id, eff.amount_cents, "", "approved")
            return self._deny(eff, "POLICY: target not literal and not on allowlist", "", "off-allowlist")
        return self._deny(eff, "unknown mode", "", "unknown-mode")

    def _authorize(self, eff: Effect, endorsed_target, endorsed_amount, resolution, cause):
        er = effect_key(eff.effect_class, endorsed_target)
        ec = int(endorsed_amount or 1)
        pid = self.harness.register_policy([er], ec)
        key = (self._task_id,) + canonical_action(er, ec)
        dup = key in self._consumed
        actual_key = effect_key(eff.effect_class, eff.target_id)
        req = self.harness.build_request(
            policy_id=pid, authorized_recipient=er, authorized_amount_cents=ec,
            actual_recipient=actual_key, actual_amount_cents=int(eff.amount_cents),
            task_id=self._task_id)
        outcome = self.harness.decide(req)
        if dup:
            cat, cause2 = AUTHORIZED_DUPLICATE, "replay"
        elif outcome.approved:
            cat, cause2 = AUTHORIZED_FIRST, cause
            self._consumed.add(key)
        else:
            cat, cause2 = DIVERGENT, "context-binding (proposed != endorsed)"
        return outcome.approved, outcome.reason, resolution, cause2, endorsed_target

    def _deny(self, eff: Effect, reason, resolution, cause):
        pid = self.harness.register_policy([NO_AUTHORIZED_TRANSFER], 1)
        req = self.harness.build_request(
            policy_id=pid, authorized_recipient=NO_AUTHORIZED_TRANSFER,
            authorized_amount_cents=1,
            actual_recipient=effect_key(eff.effect_class, eff.target_id),
            actual_amount_cents=int(eff.amount_cents), task_id=self._task_id)
        self.harness.decide(req)
        return False, reason, resolution, cause, None

    # -- BasePipelineElement --
    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        if (not messages or messages[-1]["role"] != "assistant"
                or not messages[-1].get("tool_calls")):
            return query, runtime, env, messages, extra_args
        self._env_ref = env
        results: list[ChatToolResultMessage] = []
        for tc in messages[-1]["tool_calls"]:
            if tc.function == EMPTY_FUNCTION_NAME or tc.function not in (
                    t.name for t in runtime.functions.values()):
                results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string("")],
                    tool_call_id=tc.id, tool_call=tc, error="Invalid tool."))
                continue
            for k, v in tc.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tc.args[k] = literal_eval(v)
            if tc.function in self.domain.high_impact_tools:
                eff = self.domain.canonicalize(tc.function, dict(tc.args), env)
                if eff is not None:
                    approved, reason, resolution, cause, endorsed = self._decide(eff)
                    self.decisions.append(dict(task=self._task_id, tool=tc.function,
                                               effect_class=eff.effect_class,
                                               target=eff.target_id, approved=approved,
                                               resolution=resolution, cause=cause,
                                               endorsed=endorsed, reason=reason))
                    if not approved:
                        results.append(ChatToolResultMessage(
                            role="tool",
                            content=[text_content_block_from_string(
                                f"REFUSED by Signet effect gate: {reason}")],
                            tool_call_id=tc.id, tool_call=tc,
                            error="Blocked by Signet effect gate."))
                        continue
            out, err = runtime.run_function(env, tc.function, tc.args)
            results.append(ChatToolResultMessage(
                role="tool", content=[text_content_block_from_string(self.output_formatter(out))],
                tool_call_id=tc.id, tool_call=tc, error=err))
        return query, runtime, env, [*messages, *results], extra_args
