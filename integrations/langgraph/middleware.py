"""`SignetMiddleware` — the native LangChain/LangGraph `wrap_tool_call` drop-in.

A LangGraph engineer adds ONE line:

    create_agent(model, tools=[...], middleware=[SignetMiddleware(
        transport=BrokerTransport(sock), task_id="task-001",
        guarded_tools={"db_write": DbToolSpec(effect_from_args=...)})])

and every call to a guarded tool is routed, BEFORE it runs, through the capability transport:

  * ALLOW  -> the broker minted a scoped, short-TTL JWT for THIS effect. The middleware places
              it in a per-call `_capability_scope` contextvar and calls `handler(request)`; the
              guarded db tool reads the capability from the scope, uses it, and the scope clears
              after the call (no capability leaks past the single tool call).
  * BLOCK  -> the tool NEVER runs. The middleware returns a structured `ToolMessage` carrying the
              cause + receipt_id — an early, legible, loop-able refusal the orchestrator can act
              on, instead of a late opaque resource-level 403.

The middleware holds ZERO authority. It imports no signing key, no key-issuing code, no DB
credential — only a `CapabilityTransport`. The boundary is the broker behind that transport (at Tier 1,
holds the only key and runs as a separate OS user). The middleware is capture + UX: a legible,
native mirror of a decision the broker enforces.

NO-ESCALATE-V0: DB admission is binary (consistent with the supabase rail). This middleware never
emits `Command(resume=...)`; the merge/resolution ESCALATE path lives in `guarded_tool.py`.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Callable, Optional
from uuid import uuid4

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

from integrations.effect_gateway.transport import CapabilityTransport

# ---------------------------------------------------------------------------------------------
# The per-call capability scope. The middleware sets this around `handler(request)` on ALLOW; a
# guarded db tool reads it via `current_capability()`. It is a contextvar so it is correct under
# concurrent tool calls and clears deterministically after each call (BLOCK-NEVER-RUNS / ALLOW-
# RUNS-WITH-CAP). The agent process holds NO static DB credential: no scope -> no capability ->
# the tool cannot reach the DB.
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Capability:
    token: str                 # the scoped ES256 JWT minted by the broker
    expires_at: Optional[str]  # ISO-8601


_CAP: ContextVar[Optional[Capability]] = ContextVar("signet_capability", default=None)


@contextmanager
def _capability_scope(token: Optional[str], expires_at: Optional[str]):
    """Make a minted capability visible to exactly the tool call it was granted for, then clear
    it. Used by `SignetMiddleware` around the ALLOW `handler(request)`."""
    cap = Capability(token=token, expires_at=expires_at) if token is not None else None
    reset = _CAP.set(cap)
    try:
        yield cap
    finally:
        _CAP.reset(reset)


def current_capability() -> Optional[Capability]:
    """The capability granted for the in-flight tool call, or None outside an ALLOW scope.
    A guarded db tool calls this to obtain its bearer JWT; outside a granted call it gets None
    and cannot reach the database."""
    return _CAP.get()


# ---------------------------------------------------------------------------------------------
# The guarded-tool spec: how to read a db effect out of a tool's args, and how to nonce it.
# ---------------------------------------------------------------------------------------------
@dataclass
class GuardedToolSpec:
    """Maps one tool name -> (read its db effect from the call args, choose a request_nonce).

    `effect_from_args(args) -> dict | None` returns the `effect_params`
    ({database, schema, table, op, predicate?}) for the broker, or None if the args do not encode
    a well-formed db effect (-> the middleware fails closed).

    `nonce()` defaults to a FRESH value per call, so two legitimate tool calls are two distinct
    capability requests (they do not collide on chain_hash). Override with a deterministic nonce
    to make a tool idempotent (identical calls collide on chain_hash -> consume-once refuses the
    replay)."""
    effect_from_args: Callable[[dict], Optional[dict]]
    nonce_fn: Optional[Callable[[], str]] = None

    def nonce(self) -> str:
        return self.nonce_fn() if self.nonce_fn is not None else uuid4().hex


class SignetMiddleware(AgentMiddleware):
    """Wrap every guarded tool call so it is admitted by the broker (via the transport) BEFORE it
    runs. Holds only a `CapabilityTransport` + the frozen task_id + the guarded-tool map — never a
    key. An ungated tool passes straight through, untouched."""

    def __init__(self, *, transport: CapabilityTransport, task_id: str,
                 guarded_tools: dict, agent_id: str = "agent"):
        super().__init__()
        self._transport = transport
        self._task_id = task_id
        self._guarded = dict(guarded_tools)
        self._agent_id = agent_id

    # -- LangChain v1 sync interceptor. handler(request) runs the tool; not calling it = deny. --
    def wrap_tool_call(self, request, handler):
        name = request.tool_call["name"]
        spec = self._guarded.get(name)
        if spec is None:
            return handler(request)                      # ungated tool — pass through untouched

        args = request.tool_call.get("args", {}) or {}
        try:
            effect_params = spec.effect_from_args(args)
        except Exception:
            effect_params = None                         # a raising reader is treated as malformed
        if not effect_params:
            return self._refuse(request, "malformed-or-missing-db-effect")   # FAIL-CLOSED

        out = self._transport.request(
            effect_kind="db.query", effect_params=effect_params,
            task_id=self._task_id, agent_id=self._agent_id, request_nonce=spec.nonce())

        if not out.granted:                              # BLOCK — never run the tool
            return self._refuse(request, out.cause, receipt_id=out.receipt_id)

        # ALLOW — make the scoped, short-TTL capability available to THIS tool call only.
        with _capability_scope(out.capability, out.expires_at):
            return handler(request)                      # tool runs, uses the cap, then it clears

    # -- a structured, loop-able refusal (early + legible, not a late opaque 403) --
    def _refuse(self, request, cause: str, *, receipt_id: Optional[str] = None) -> ToolMessage:
        payload = {"signet": "blocked", "cause": cause, "receipt_id": receipt_id,
                   "tool": request.tool_call["name"]}
        return ToolMessage(content=json.dumps(payload), name=request.tool_call["name"],
                           tool_call_id=request.tool_call["id"], status="error")
