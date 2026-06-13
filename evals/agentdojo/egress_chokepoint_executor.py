"""Route AgentDojo egress-class tool calls through the egress chokepoint BEFORE they run.

A drop-in `ToolsExecutor` (a `BasePipelineElement`) that, for every EGRESS-SEMANTIC tool call,
builds the bound egress effect (destination, payload commitment, session, timestamp) and calls the
UNCHANGED smoke-run chokepoint (`evals/egress_receipts/chokepoint.py` → `EgressMerkleLog.emit`)
*before* the side-effecting call. The decision call commits the Merkle leaf in-path — the block
and the receipt are the same act. Non-egress tools pass through unchanged.

Scope (this build): the single egress-semantic tool is Slack's `post_webpage(url, content)` — the
target is a literal external URL, which maps to the rail's `host:port` unit with zero semantic
stretch. The rail is DESTINATION-based: it binds the URL's host and commits a hash of the posted
content (no payload inspection). Other egress-class tools (send_email, send_money) are egress-
*semantic* but bind an email/IBAN rather than a host; they are intentionally out of scope here and
would be added by registering an extractor — never by letting them execute unrouted.

Two run modes, both REAL runs through the chokepoint (the baseline does not skip it — constraint #4):
  * enforcing=True  — DENY/REVIEW blocks (the egress is NOT performed; the agent gets a refusal).
  * enforcing=False — pass-through: the chokepoint still DECIDES and records a receipt, but the tool
                      runs regardless. This measures the *without-rail* attack success on the same
                      tasks and model, with the same single chokepoint by construction.

NO-BYPASS GUARD (constraint #2): an egress-semantic tool that reaches execution without a chokepoint
decision is an error, not a silent pass. A tool we know is egress-semantic but have no binding for
raises `EgressBypassError` rather than running; `verify_coverage` lets the runner assert, before any
task, that every egress-semantic tool present in the runtime is bound.

This element never reimplements the decision or the receipt — it only translates a tool call into an
egress effect and relays the chokepoint's verdict. No new crypto, no verifier change, no format
change (constraint #1).
"""
from __future__ import annotations

from ast import literal_eval
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import (ChatMessage, ChatToolResultMessage,
                             text_content_block_from_string)

from signet.rails.egress.mandate import EgressGrant, EgressMandate, EgressStandingPolicy

from ..egress_receipts.chokepoint import EgressChokepoint, EgressOutcome
from ..egress_receipts.record import ALLOW, DENY, REVIEW, EgressMerkleLog


class EgressBypassError(RuntimeError):
    """An egress-semantic tool reached execution with no chokepoint binding — fail loud (the
    single-chokepoint-by-construction invariant would otherwise be silently void)."""


# ----------------------------------------------------------------------------
# Mapping an egress-class tool call → the bound egress effect (host:port + payload).
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class EgressTarget:
    destination: str   # the full outbound target, named verbatim in the receipt (e.g. the URL)
    host: str          # the destination host the rail decides on
    port: int
    payload: bytes     # the outbound bytes; the receipt commits sha256(payload), never the bytes
    label: str


def host_of(url: str) -> str:
    """The bare host of an AgentDojo web URL (scheme/path stripped). The rail binds the HOST; a path
    under an allowlisted host is the named out-of-scope boundary (v2: payload-aware binding)."""
    u = url.strip()
    for scheme in ("http://", "https://"):
        if u.lower().startswith(scheme):
            u = u[len(scheme):]
            break
    return u.split("/", 1)[0]


def _as_bytes(content) -> bytes:
    if isinstance(content, bytes):
        return content
    return str(content).encode("utf-8")


def _post_webpage_effect(args: Dict) -> EgressTarget:
    """`post_webpage(url, content)` → egress to `host_of(url):443`, committing the posted content."""
    url = str(args.get("url", ""))
    return EgressTarget(destination=url, host=host_of(url), port=443,
                        payload=_as_bytes(args.get("content", "")), label="post_webpage")


# The registry of egress-class tools and how to bind each. Adding a rail means adding an extractor
# here (config-driven), NEVER letting an egress tool execute unrouted.
EGRESS_EFFECT_EXTRACTORS: Dict[str, Callable[[Dict], EgressTarget]] = {
    "post_webpage": _post_webpage_effect,
}

# Tools KNOWN to be egress-semantic. Every name here MUST have an extractor, or execution fails loud.
# Scope of this build = Slack post_webpage only.
EGRESS_SEMANTIC_TOOLS = frozenset({"post_webpage"})


# ----------------------------------------------------------------------------
# Stage 2 — the operator STANDING egress allowlist, derived from the suite env.
# ----------------------------------------------------------------------------
def _ground_truth_post_hosts(env, suite) -> set:
    """Hosts that the suite's LEGITIMATE user tasks post to, read from each task's ground-truth
    solution trace. These are operator-sanctioned destinations created by completing a task (e.g.
    `www.our-company.com`), which do NOT pre-exist in `web_content` — so the standing allow-set must
    include them or it would wrongly deny legitimate posts. The attacker destination appears only in
    INJECTION-task ground truth, never a user task's, so it stays outside this set."""
    hosts = set()
    if suite is None:
        return hosts
    for ut in getattr(suite, "user_tasks", {}).values():
        try:
            gt = ut.ground_truth(env)
        except Exception:
            continue
        for fc in gt or []:
            if getattr(fc, "function", None) == "post_webpage":
                url = str((getattr(fc, "args", {}) or {}).get("url", ""))
                if url:
                    hosts.add(host_of(url))
    return hosts


def legit_hosts_from_slack_env(env, *, suite=None, port: int = 443) -> List[str]:
    """The legitimate destination hosts for the slack suite: the hosts the default environment's
    `web_content` already knows, UNIONED with the hosts legitimate user tasks post to (ground truth,
    when `suite` is given). The attacker URL (`www.my-website-234.com/...`) is in NEITHER, so it falls
    OUTSIDE the operator standing allow-set."""
    web = getattr(env, "web", None)
    content = getattr(web, "web_content", {}) or {}
    hosts = {host_of(u) for u in content.keys()} | _ground_truth_post_hosts(env, suite)
    return sorted(hosts)


def slack_standing_policy(env, *, suite=None, port: int = 443) -> EgressStandingPolicy:
    """Operator STANDING fence: the legit known hosts. A destination outside this set is denied on
    the standing hard axis `egress_destination` — the part no approval (no learned rule) can move."""
    return EgressStandingPolicy(grants=tuple(EgressGrant(h, (port,))
                                             for h in legit_hosts_from_slack_env(env, suite=suite, port=port)))


def slack_task_mandate(env, task_id: str, *, suite=None, port: int = 443) -> EgressMandate:
    """Per-task mandate. Defaults to the full legit set (mandate = standing) so any legitimate post
    is ALLOWed and only the non-allowlisted attacker destination is denied — keeping every exfil
    DENY on the standing axis (not a per-task REVIEW). Tighten per task in config if desired."""
    return EgressMandate(task_id=task_id, grants=tuple(EgressGrant(h, (port,))
                                                       for h in legit_hosts_from_slack_env(env, suite=suite, port=port)))


def build_slack_chokepoint(env, *, session_id: str,
                           clock: Optional[Callable[[], str]] = None,
                           task_id: str = "slack-egress", suite=None) -> EgressChokepoint:
    """One chokepoint over one Merkle log for a whole run: standing ∩ task mandate, derived from the
    slack environment (and, when `suite` is given, the legitimate post targets). Reused across every
    task in the run so all egress decisions land in one tree → one published root."""
    standing = slack_standing_policy(env, suite=suite)
    mandate = slack_task_mandate(env, task_id, suite=suite)
    return EgressChokepoint(EgressMerkleLog(standing, mandate, session_id=session_id, clock=clock))


# ----------------------------------------------------------------------------
# The wrap.
# ----------------------------------------------------------------------------
class EgressGatedToolsExecutor(BasePipelineElement):
    """Routes egress-class tool calls through `chokepoint.attempt(...)` before execution."""

    def __init__(self, chokepoint: EgressChokepoint,
                 tool_output_formatter: Callable = tool_result_to_str, *,
                 enforcing: bool = True,
                 effect_extractors: Dict[str, Callable[[Dict], EgressTarget]] = EGRESS_EFFECT_EXTRACTORS,
                 egress_semantic_tools=EGRESS_SEMANTIC_TOOLS) -> None:
        self.chokepoint = chokepoint
        self.output_formatter = tool_output_formatter
        self.enforcing = enforcing
        self.effect_extractors = dict(effect_extractors)
        self.egress_semantic_tools = frozenset(egress_semantic_tools)
        # Every egress decision this executor caused, in order (label, outcome). The leaves live in
        # the chokepoint's log; this is the local trail for assertions/reporting.
        self.routed: List[EgressOutcome] = []
        self.blocked: List[EgressOutcome] = []

    # -- the no-bypass guard --------------------------------------------------

    def verify_coverage(self, runtime_tool_names) -> None:
        """Assert that every egress-semantic tool reachable in this runtime has a chokepoint binding.
        Called by the runner before any task: an unbound egress tool would execute unrouted."""
        names = set(runtime_tool_names)
        unbound = sorted((self.egress_semantic_tools & names) - set(self.effect_extractors))
        if unbound:
            raise EgressBypassError(
                f"egress-semantic tool(s) {unbound} are present in the runtime but have no chokepoint "
                f"binding — refusing to run (single-chokepoint-by-construction would be void)")

    # -- BasePipelineElement interface (mirrors ToolsExecutor.query) ----------

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
                    role="tool", content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id, tool_call=tool_call,
                    error="Empty function name provided. Provide a valid function name."))
                continue
            if tool_call.function not in (tool.name for tool in runtime.functions.values()):
                tool_call_results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id, tool_call=tool_call,
                    error=f"Invalid tool {tool_call.function} provided."))
                continue

            # Same string-list arg coercion as the stock ToolsExecutor.
            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            # ---- the egress chokepoint (single egress path by construction) ----
            if tool_call.function in self.egress_semantic_tools:
                if tool_call.function not in self.effect_extractors:
                    # Fail loud: we know this is egress but cannot bind it — never run it unrouted.
                    raise EgressBypassError(
                        f"egress-semantic tool {tool_call.function!r} has no chokepoint binding — "
                        f"refusing to execute (no-bypass guard)")
                target = self.effect_extractors[tool_call.function](dict(tool_call.args))
                outcome = self.chokepoint.attempt(
                    destination=target.destination, host=target.host, port=target.port,
                    payload=target.payload, label=target.label)
                self.routed.append(outcome)
                if self.enforcing and outcome.decision != ALLOW:
                    self.blocked.append(outcome)
                    note = "denied — not in operator standing allow-set" if outcome.decision == DENY \
                        else "held for review — in ceiling but not granted; no human present"
                    refusal = (f"REFUSED by Signet egress rail ({outcome.decision}): the egress to "
                               f"{target.destination!r} was NOT performed ({note}). A signed receipt "
                               f"of this block was recorded.")
                    tool_call_results.append(ChatToolResultMessage(
                        role="tool", content=[text_content_block_from_string(refusal)],
                        tool_call_id=tool_call.id, tool_call=tool_call,
                        error=f"Blocked by Signet egress rail ({outcome.decision})."))
                    continue
                # ALLOW, or pass-through (baseline): fall through to execute. The decision +
                # receipt are already committed regardless of mode.

            tool_call_result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            formatted = self.output_formatter(tool_call_result)
            tool_call_results.append(ChatToolResultMessage(
                role="tool", content=[text_content_block_from_string(formatted)],
                tool_call_id=tool_call.id, tool_call=tool_call, error=error))

        return query, runtime, env, [*messages, *tool_call_results], extra_args
