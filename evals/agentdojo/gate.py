"""SignetGatedToolsExecutor -- the action gate.

A drop-in replacement for AgentDojo's ``ToolsExecutor`` (a ``BasePipelineElement``)
that runs every BANKING TRANSACTION tool call through the REAL Signet verifier
*before* the side-effecting call. Non-transaction tools pass through unchanged.

Decision flow per gated call (BEFORE any state mutation):
  a. Build a Signet RuntimeContext from the actual call args (recipient/IBAN,
     amount). For ``update_scheduled_transaction``, unspecified fields are
     resolved from the live environment's scheduled transaction.
  b. Select which authorized transfer to bind the mandate to (exact match ->
     approve path; otherwise the task's canonical authorized transfer, or a
     deny-sentinel if the task authorizes no money movement) and route the
     decision through ``signet.verifier`` + the ``MockCredentialBroker``.
  c. APPROVED  -> delegate to the normal executor (state mutates as usual).
     BLOCKED   -> return a refusal string as the tool result; env untouched.
     Fail closed: any exception in the gate path -> BLOCK.

This element never reimplements verification -- it only translates tool-call
arguments into Signet objects and relays the verifier's verdict.
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

from .intent_provider import (CAP, EXACT, MONEY_MOVING_TOOLS,
                              AuthorizedIntentProvider,
                              resolve_effective_transfer)
from .resolve import BLOCK, ENDORSE, REVIEW, resolve_banking_target
from .signet_harness import (NO_AUTHORIZED_TRANSFER, SignetHarness,
                             canonical_action)

# Binding modes (which mechanism turns intent into the authorized envelope).
MODE_STRICT = "strict"        # literal recipient+amount from the instruction (§2b)
MODE_POLICY = "policy"        # instruction INTERSECT standing operator policy (§2c)
MODE_PREDICATE = "predicate"  # predicate-binding + endorsed value resolution (§4)

# Classification of a money-moving call against the ENFORCING provider's envelope
# (used for consume-once bookkeeping). Ground-truth authorization for the metrics
# is a SEPARATE axis: `GateDecision.truth_authorized` (membership in the oracle
# envelope), so a too-narrow extractor cannot disguise a false positive as a
# correctly-blocked "divergent" call.
DIVERGENT = "divergent"
AUTHORIZED_FIRST = "authorized-first"
AUTHORIZED_DUPLICATE = "authorized-duplicate"


@dataclass
class GateDecision:
    user_task_id: str
    tool: str
    actual_recipient: Optional[str]
    actual_amount: Optional[float]
    authorized: list           # list[(recipient, amount_cents)]
    approved: bool
    reason: str
    category: str = ""         # divergent | authorized-first | authorized-duplicate
    cell: str = ""             # set by the runner: "no-attack" | "attack"
    actual_amount_cents: Optional[int] = None
    # ---- predicate-mode diagnostic axes ----
    resolution: str = ""       # ENDORSE | REVIEW | BLOCK (predicate mode), else ""
    cause: str = ""            # cause label for the diagnostic cause breakdown
    endorsed_recipient: Optional[str] = None
    endorsed_amount_cents: Optional[int] = None
    # ---- ground-truth + dual-score axes (set in query()) ----
    truth_authorized: Optional[bool] = None  # in the ORACLE (ground-truth) envelope?
    oracle_approved: Optional[bool] = None    # shadow verdict of the oracle provider
    provider: str = ""         # which provider ENFORCED this decision


@dataclass
class _TaskBinding:
    policy_id: str
    envelope: list             # list[AuthorizedTransfer]


class SignetGatedToolsExecutor(BasePipelineElement):
    def __init__(
        self,
        harness: SignetHarness,
        provider: AuthorizedIntentProvider,
        suite,
        tool_output_formatter=tool_result_to_str,
        provider_label: str = "oracle",
        mode: str = MODE_STRICT,
    ) -> None:
        self.harness = harness
        self.provider = provider
        self.suite = suite
        self.output_formatter = tool_output_formatter
        self.provider_label = provider_label
        # Binding mode. STRICT/POLICY use the static-envelope match; PREDICATE resolves
        # + endorses the runtime value at the gate (reads the live env). The standing
        # policy (allowlist/cap/velocity) is taken from the provider when present.
        self.mode = mode
        self.standing_policy = getattr(provider, "policy", None)
        self.decisions: list[GateDecision] = []
        self._current_task = None
        self._bindings: dict[str, _TaskBinding] = {}   # task_id -> binding
        self._predicates: dict = {}                    # task_id -> frozen predicate (predicate mode)
        # Per-EPISODE set of (task_id,)+canonical_action that have been approved
        # (i.e. their chain_hash consumed). A later call with the same key in the
        # same episode is an authorized-duplicate (consume-once replay).
        self._consumed: set = set()
        # Optional ground-truth (oracle) scorer: a second, NON-ENFORCING gate that
        # decides the same call args under the oracle envelope. Used for single-
        # rollout dual-scoring (truth tag + oracle verdict) when this gate enforces
        # a fallible provider. Driven in lockstep via set_user_task/begin_episode.
        self.oracle_scorer: Optional["SignetGatedToolsExecutor"] = None

    def attach_oracle_scorer(self, scorer: "SignetGatedToolsExecutor") -> None:
        self.oracle_scorer = scorer

    # -- episode lifecycle (called by the runner before each gated episode) --

    def begin_episode(self) -> None:
        """Reset consume-once-scoped state for a fresh, independent episode."""
        self.harness.reset_episode()
        self._consumed.clear()
        if self.oracle_scorer is not None:
            self.oracle_scorer.begin_episode()

    # -- task wiring (called by the runner before each user task) --

    def set_user_task(self, user_task) -> None:
        self._current_task = user_task
        if self.oracle_scorer is not None:
            self.oracle_scorer.set_user_task(user_task)
        if self.mode == MODE_PREDICATE and user_task.ID not in self._predicates:
            # Freeze the trusted predicate (instruction only) before any episode.
            # Resolution + per-call policy registration happen at gate time.
            self._predicates[user_task.ID] = self.provider.predicate_for(user_task, self.suite)
        if user_task.ID in self._bindings:
            return
        envelope = self.provider.envelope_for(user_task, self.suite)
        if envelope:
            recipients = sorted({t.recipient for t in envelope})
            cap = max(t.amount_cents for t in envelope)
        else:
            recipients = [NO_AUTHORIZED_TRANSFER]
            cap = 1
        # A provider may expose a standing cumulative/velocity cap (the policy-
        # enriched provider does). When present, turn velocity ON for this task's
        # policy so the cap-bounded envelope is bounded cumulatively as well as
        # per-payment. None -> the harness default (velocity effectively off).
        daily = getattr(self.provider, "velocity_cap_cents", None)
        policy_id = self.harness.register_policy(recipients, cap, daily_cap_cents=daily)
        self._bindings[user_task.ID] = _TaskBinding(policy_id, envelope)

    # -- gating --

    def _resolve_actual(self, tool: str, args: dict, env) -> Optional[tuple[str, int]]:
        """(recipient_upper, amount_cents) for the ACTUAL call, or None if malformed."""
        scheduled_by_id = {}
        try:
            scheduled_by_id = {t.id: t for t in env.bank_account.scheduled_transactions}
        except AttributeError:
            pass
        transfer = resolve_effective_transfer(tool, args, scheduled_by_id)
        if transfer is None:
            return None
        return transfer.recipient, transfer.amount_cents

    @staticmethod
    def _match_envelope(envelope, recipient, cents):
        """Is (recipient, cents) inside the envelope? Returns (entry, bound_cents).

        EXACT entry matches iff recipient == and amount ==; the chain binds the
        exact amount. CAP entry matches iff recipient == and amount <= cap; the
        recipient is bound hard and the chain binds the ACTUAL amount while the
        policy cap (set from the envelope) enforces the <= cap bound.
        """
        for t in envelope:
            if t.recipient != recipient:
                continue
            if t.mode == EXACT and t.amount_cents == cents:
                return t, t.amount_cents
            if t.mode == CAP and cents <= t.amount_cents:
                return t, cents
        return None, None

    def _truth_member(self, tool: str, args: dict, env) -> bool:
        """Is the ACTUAL call inside THIS gate's envelope? For the oracle scorer
        (exact ground-truth envelope) this is ground-truth authorization."""
        resolved = self._resolve_actual(tool, args, env)
        if resolved is None:
            return False
        entry, _ = self._match_envelope(
            self._bindings[self._current_task.ID].envelope, resolved[0], resolved[1])
        return entry is not None

    # cause labels (the diagnostic cause breakdown)
    CAUSE_APPROVED = "approved"
    CAUSE_STRUCTURAL = "structural"          # policy/exactness violation (baseline also fails)
    CAUSE_REPLAY = "replay"                  # consume-once (authorized-duplicate)
    CAUSE_OUT_OF_ENVELOPE = "out-of-envelope"  # divergent vs the static envelope

    def _gate(self, tool: str, args: dict, env) -> tuple[bool, str, str, dict]:
        """Run the actual call through Signet. Returns (approved, reason, category,
        info) where info carries {cause, resolution, endorsed_recipient,
        endorsed_amount_cents}. Fail closed: any error -> blocked, classified divergent.
        """
        try:
            if self.mode == MODE_PREDICATE:
                return self._gate_predicate(tool, args, env)
            return self._gate_envelope(tool, args, env)
        except Exception as e:  # fail closed on ANY error
            return (False, f"Signet gate (fail-closed) error: {type(e).__name__}: {e}",
                    DIVERGENT, {"cause": "fail-closed", "resolution": ""})

    def _gate_envelope(self, tool: str, args: dict, env) -> tuple[bool, str, str, dict]:
        """STRICT / POLICY: match the actual call against the frozen static envelope."""
        task = self._current_task
        binding = self._bindings[task.ID]
        resolved = self._resolve_actual(tool, args, env)
        if resolved is None:
            return (False,
                    f"Signet gate (fail-closed): could not resolve recipient/amount for {tool}.",
                    DIVERGENT, {"cause": "fail-closed", "resolution": ""})
        actual_recipient, actual_cents = resolved

        match, bound_cents = self._match_envelope(binding.envelope, actual_recipient, actual_cents)
        if match is not None:
            authorized_recipient, authorized_cents = match.recipient, bound_cents
            key = (task.ID,) + canonical_action(match.recipient, bound_cents)
            already_consumed = key in self._consumed
        else:
            key = None
            already_consumed = False
            if binding.envelope:
                canonical = binding.envelope[0]
                authorized_recipient, authorized_cents = canonical.recipient, canonical.amount_cents
            else:
                authorized_recipient, authorized_cents = NO_AUTHORIZED_TRANSFER, 1

        req = self.harness.build_request(
            policy_id=binding.policy_id,
            authorized_recipient=authorized_recipient,
            authorized_amount_cents=authorized_cents,
            actual_recipient=actual_recipient, actual_amount_cents=actual_cents,
            task_id=task.ID,
        )
        outcome = self.harness.decide(req)

        if match is None:
            category, cause = DIVERGENT, self.CAUSE_OUT_OF_ENVELOPE
        elif already_consumed:
            category, cause = AUTHORIZED_DUPLICATE, self.CAUSE_REPLAY
        else:
            category = AUTHORIZED_FIRST
            cause = self.CAUSE_APPROVED if outcome.approved else self.CAUSE_STRUCTURAL
            if outcome.approved:
                self._consumed.add(key)
        return outcome.approved, outcome.reason, category, {"cause": cause, "resolution": ""}

    def _gate_predicate(self, tool: str, args: dict, env) -> tuple[bool, str, str, dict]:
        """PREDICATE: resolve + endorse the runtime value over the principal's OWN
        data (criteria from the frozen predicate), then context-bind the ENDORSED
        effect through the unmodified kernel. REVIEW/BLOCK -> deny-sentinel."""
        task = self._current_task
        pred = self._predicates.get(task.ID)
        sp = self.standing_policy
        allow = set(sp.approved_recipients) if sp is not None else set()
        cap = sp.per_recipient_cap_cents if sp is not None else None
        velocity = getattr(self.provider, "velocity_cap_cents", None)

        resolved = self._resolve_actual(tool, args, env)
        actual_recipient = resolved[0] if resolved else None
        actual_cents = resolved[1] if resolved else None

        res = resolve_banking_target(pred, env, allowlist=allow, cap_cents=cap)
        info = {"cause": res.cause, "resolution": res.kind,
                "endorsed_recipient": res.endorsed_recipient,
                "endorsed_amount_cents": res.endorsed_amount_cents}

        if res.kind != ENDORSE:
            # REVIEW / BLOCK: bind the deny-sentinel; the real verifier blocks. The
            # decision NEVER silently picks a target -- it escalates (REVIEW) or denies.
            policy_id = self.harness.register_policy([NO_AUTHORIZED_TRANSFER], 1)
            req = self.harness.build_request(
                policy_id=policy_id, authorized_recipient=NO_AUTHORIZED_TRANSFER,
                authorized_amount_cents=1,
                actual_recipient=(actual_recipient or NO_AUTHORIZED_TRANSFER),
                actual_amount_cents=(actual_cents or 1), task_id=task.ID)
            outcome = self.harness.decide(req)
            reason = f"{res.kind}: {res.cause}"
            return False, reason, DIVERGENT, info

        # ENDORSE: register a per-call policy that authorizes EXACTLY the endorsed
        # (recipient, amount); the kernel context-binds the agent's proposed args to it.
        er, ec = res.endorsed_recipient, int(res.endorsed_amount_cents)
        policy_id = self.harness.register_policy([er], ec, daily_cap_cents=velocity)
        key = (task.ID,) + canonical_action(er, ec)
        already_consumed = key in self._consumed
        if resolved is None:
            actual_recipient, actual_cents = NO_AUTHORIZED_TRANSFER, 1
        req = self.harness.build_request(
            policy_id=policy_id, authorized_recipient=er, authorized_amount_cents=ec,
            actual_recipient=actual_recipient, actual_amount_cents=actual_cents,
            task_id=task.ID)
        outcome = self.harness.decide(req)

        if already_consumed:
            category, info["cause"] = AUTHORIZED_DUPLICATE, self.CAUSE_REPLAY
        elif outcome.approved:
            category = AUTHORIZED_FIRST
            self._consumed.add(key)
        else:
            # endorsed, but the agent proposed something else -> kernel context-binding
            # blocked it (proposed != endorsed). Not a resolver escalation.
            category = DIVERGENT
            info["cause"] = "context-binding (proposed != endorsed)"
        return outcome.approved, outcome.reason, category, info

    def _record(self, tool, args, env, approved, reason, category,
                truth_authorized=None, oracle_approved=None, info=None) -> None:
        resolved = self._resolve_actual(tool, args, env)
        info = info or {}
        self.decisions.append(GateDecision(
            user_task_id=getattr(self._current_task, "ID", "?"),
            tool=tool,
            actual_recipient=(resolved[0] if resolved else args.get("recipient")),
            actual_amount=args.get("amount"),
            actual_amount_cents=(resolved[1] if resolved else None),
            authorized=[(t.recipient, t.amount_cents)
                        for t in self._bindings[self._current_task.ID].envelope],
            approved=approved,
            reason=reason,
            category=category,
            truth_authorized=truth_authorized,
            oracle_approved=oracle_approved,
            provider=self.provider_label,
            resolution=info.get("resolution", ""),
            cause=info.get("cause", ""),
            endorsed_recipient=info.get("endorsed_recipient"),
            endorsed_amount_cents=info.get("endorsed_amount_cents"),
        ))

    def _dual_score(self, tool, args, env, enforced_approved):
        """Single-rollout dual-score: ground-truth membership + oracle verdict on
        the SAME call args, without enforcing. If an oracle scorer is attached it
        provides both (the enforcing provider is fallible); otherwise this gate IS
        the oracle, so truth = own membership and oracle verdict = enforced verdict.
        """
        if self.oracle_scorer is not None:
            truth = self.oracle_scorer._truth_member(tool, args, env)
            oracle_appr, _, _, _ = self.oracle_scorer._gate(tool, args, env)
            return truth, oracle_appr
        return self._truth_member(tool, args, env), enforced_approved

    # -- BasePipelineElement interface (mirrors ToolsExecutor.query) --

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        tool_call_results: list[ChatToolResultMessage] = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error="Empty function name provided. Provide a valid function name.",
                ))
                continue
            if tool_call.function not in (tool.name for tool in runtime.functions.values()):
                tool_call_results.append(ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=f"Invalid tool {tool_call.function} provided.",
                ))
                continue

            # Same string-list arg coercion as the stock ToolsExecutor.
            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            # ---- the gate ----
            if tool_call.function in MONEY_MOVING_TOOLS and self._current_task is not None:
                approved, reason, category, info = self._gate(
                    tool_call.function, dict(tool_call.args), env)
                truth, oracle_appr = self._dual_score(
                    tool_call.function, dict(tool_call.args), env, approved)
                self._record(tool_call.function, dict(tool_call.args), env, approved,
                             reason, category, truth_authorized=truth,
                             oracle_approved=oracle_appr, info=info)
                if not approved:
                    # No state mutation. Hand the agent a refusal it can see.
                    refusal = (f"REFUSED by Signet enforcement gate: this transaction "
                               f"does not match a Signet-authorized mandate. Reason: {reason}")
                    tool_call_results.append(ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(refusal)],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Blocked by Signet enforcement gate.",
                    ))
                    continue
                # approved -> fall through to normal execution below

            tool_call_result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            formatted = self.output_formatter(tool_call_result)
            tool_call_results.append(ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string(formatted)],
                tool_call_id=tool_call.id,
                tool_call=tool_call,
                error=error,
            ))

        return query, runtime, env, [*messages, *tool_call_results], extra_args
