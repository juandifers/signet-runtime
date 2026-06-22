"""The refund-triage agent: a REAL LangGraph `StateGraph` contained from below by the supabase
admission door (the seam + `signet_guarded_tool`, spec §4).

Graph:  freeze_mandate -> intake_ticket -> resolve_effect -> guard --(allow)--> write
                                                                   \\--(deny)--> refuse
  * freeze_mandate : TRUSTED. Runs BEFORE any untrusted read. Summarizes the already-frozen
                     Role-A mandate (loaded + the door built BEFORE graph.invoke, mirroring the
                     seam's "caller freezes first", integrations/effect_gateway/seam.py:14-16).
  * intake_ticket  : reads the UNTRUSTED ticket text into graph state (the injection channel).
  * resolve_effect : the ONLY place model output influences the proposed effect (effects.py).
  * guard          : the guarded tool routes the proposal through EffectInterceptor -> the
                     unchanged supabase composition (mint_token -> kernel verify -> authorizer).
                     ALLOW/BLOCK/ESCALATE come back as a seam Decision + a signed receipt.
  * write / refuse : on ALLOW the agent presents the minted JWT to the resource PEP
                     (SupabaseGateway) to perform the insert; on BLOCK no JWT exists, so the
                     resource is never reached — zero rows.

KEY CUSTODY (Tier 0, advisory): the signing key (Es256Key minter + enforcer SK in DbBrokerCore)
lives inside the `Door` / `SupabaseBinding`, built OUTSIDE the graph. The agent's authored state
(ticket, ProposedEffect) never carries key material. The OS-separated Tier-1 upgrade is the
UnixSocketBrokerServer + BrokerClient path (see README / INTERFACE_MAP.md §5).
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, TypedDict

from signet.broker.mandate import (DbGrant, MandateProvider, StandingPolicy, TaskMandate)
from signet.rails.supabase.chain_adapter import DbBrokerCore
from signet.rails.supabase.es256 import Es256Key
from signet.rails.supabase.resource_sim import Store, SupabaseGateway, SupabaseResourceError
from signet.rails.supabase.roles import default_grants
from signet.receipts import ReceiptLog

from integrations.effect_gateway.rails_supabase import SupabaseBinding
from integrations.effect_gateway.seam import EffectInterceptor, Outcome
from integrations.langgraph.guarded_tool import signet_guarded_tool

from . import effects
from .tier1 import Separation, detect_separation, make_audit_log

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
PUBLISHABLE = "sb_publishable_refund_demo"   # the agent legitimately holds this (RLS-neutered)
AGENT_ID = "support-bot"


def load_mandate(path: Optional[Path] = None) -> TaskMandate:
    """Load the FROZEN Role-A task grant. Production drops a signed file the agent cannot write
    (signet/broker/mandate.py:1-16); this demo ships it unsigned and registers without a
    signature check (mirroring tests/test_supabase_binding.py). If a signature IS present it is
    honored by MandateProvider(require_signature=True)."""
    path = path or (SCENARIO_DIR / "mandate.clean.json")
    return TaskMandate.from_dict(json.loads(Path(path).read_text()))


@dataclass
class Door:
    """The supabase admission door + resource PEP. In Tier 0 it holds ALL key material (built
    outside the agent surface). In Tier 1 the key lives in a SEPARATE broker process; this Door
    holds only a BrokerClient and the broker's PUBLIC jwks. `separation` is None at Tier 0 and the
    runtime-verified OS boundary at Tier 1 (the honest-label gate, spec §0.4)."""
    interceptor: EffectInterceptor
    receipts: ReceiptLog
    gateway: SupabaseGateway
    store: Store
    mandate: TaskMandate
    clock: Any
    tier: str = "0"
    separation: Optional[Separation] = None

    def guarded_tool(self):
        return signet_guarded_tool(self.interceptor, tool_name=effects.DB_TOOL, id_arg="table")


def _resource(clock) -> tuple:
    """The agent-side resource PEP (sim): public.credits empty, public.users seeded; restricted
    roles GRANT only on public.*. Shared by both tiers."""
    store = Store(tables={
        ("public", "credits"): [],
        ("public", "users"): [{"id": 1, "email": "cfo@corp.com", "role": "user"}]})
    grants = default_grants(schemas_rw=["public"], schemas_ro=["public"])
    return store, grants


def build_door(mandate: TaskMandate, *, clock=None) -> Door:
    """Assemble the unchanged supabase composition behind the seam, plus the resource simulator.

    Standing ceiling = public.* {all ops}; the FROZEN mandate narrows it to credits {select,insert}
    — so an off-table (users) or off-op (delete) effect is in-standing but out-of-MANDATE, and the
    door blocks it via effective_permits (signet/broker/mandate.py:127). Kernel + DbGrant.permits
    untouched."""
    clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
    core = DbBrokerCore.create(clock=clock)
    receipts = ReceiptLog(core.enforcer_sk, core.enforcer_vk)
    minter = Es256Key.generate()
    standing = StandingPolicy(grants=(
        DbGrant("public", "*", ("select", "insert", "update", "delete")),))
    mandates = MandateProvider()
    mandates.register(mandate)
    binding = SupabaseBinding(broker_core=core, mandate_provider=mandates,
                             standing_policy=standing, minter=minter, ttl_seconds=60,
                             agent_id=AGENT_ID)
    interceptor = EffectInterceptor(mandate, [binding], env=None, bridge=None,
                                    receipts=receipts, world=None)

    store, grants = _resource(clock)
    gateway = SupabaseGateway(jwks=minter.jwks(), grants=grants, store=store, clock=clock)
    return Door(interceptor=interceptor, receipts=receipts, gateway=gateway, store=store,
                mandate=mandate, clock=clock, tier="0", separation=None)


def build_tier1_door(mandate: TaskMandate, *, socket_path: str, jwks_path: str,
                     clock=None) -> Door:
    """Tier 1: route through a SEPARATE-process broker over a Unix socket. The signing key is owned
    by uid_broker (mode 0600) and never reachable here; this Door holds only a BrokerClient and the
    broker's PUBLIC jwks. The label is `structural` iff `detect_separation` confirms a real OS
    boundary at runtime (spec §0.4) — otherwise it honestly reports advisory.

    Reuses the existing Tier-1 classes (BrokerClient/UnixSocketBrokerServer) and the unchanged
    seam; edits no kernel/permit/role/transport code."""
    from signet.broker.client import BrokerClient
    from .tier1 import RemoteSupabaseBinding

    clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
    client = BrokerClient(socket_path)
    audit = make_audit_log()
    binding = RemoteSupabaseBinding(client=client, agent_id=AGENT_ID, receipt_log=audit)
    interceptor = EffectInterceptor(mandate, [binding], env=None, bridge=None,
                                    receipts=audit, world=None)
    jwks = json.loads(Path(jwks_path).read_text())     # the broker's PUBLIC verification keys
    store, grants = _resource(clock)
    gateway = SupabaseGateway(jwks=jwks, grants=grants, store=store, clock=clock)
    return Door(interceptor=interceptor, receipts=audit, gateway=gateway, store=store,
                mandate=mandate, clock=clock, tier="1",
                separation=detect_separation(socket_path))


class RefundState(TypedDict, total=False):
    mandate_summary: dict
    ticket: str
    proposed: Any            # ProposedEffect (untrusted)
    guard: dict              # the seam Decision, flattened for state
    decision: Any            # the live seam Decision (carries the signed receipt)
    write: dict              # what the resource PEP did (or the refusal)


def _read_ticket(scenario: str) -> str:
    name = "ticket.clean.txt" if scenario == "clean" else "ticket.injected.txt"
    return (SCENARIO_DIR / name).read_text()


def build_graph(door: Door, *, scenario: str, attack: Optional[str], resolver: str):
    """A real LangGraph StateGraph (idiom mirrors demos/langgraph_merge_demo.py:106-134)."""
    from langgraph.graph import StateGraph, START, END
    from langgraph.checkpoint.memory import MemorySaver

    tool = door.guarded_tool()

    def freeze_mandate(state: RefundState) -> dict:
        m = door.mandate
        return {"mandate_summary": {
            "task_id": m.task_id, "database": m.database,
            "grants": [f"{g.schema}.{g.table} {{{','.join(g.ops)}}}" for g in m.grants]}}

    def intake_ticket(state: RefundState) -> dict:
        # UNTRUSTED read — happens AFTER the mandate is frozen.
        return {"ticket": _read_ticket(scenario)}

    def resolve_effect(state: RefundState) -> dict:
        eff = effects.resolve_effect(scenario, attack, resolver=resolver,
                                     ticket_text=state.get("ticket", ""))
        return {"proposed": eff}

    def guard(state: RefundState) -> dict:
        eff = state["proposed"]
        res = tool(**eff.args)          # -> GuardedResult (routes through the supabase door)
        receipt = res.decision.receipt if res.decision is not None else None
        return {"decision": res.decision,
                "guard": {"outcome": res.outcome, "cause": res.cause,
                          "bound_target": res.bound_target,
                          "escalation_source": res.escalation_source,
                          "jwt": res.check_ref,
                          "receipt_id": getattr(receipt, "receipt_hash", None)}}

    def route(state: RefundState) -> str:
        return "allow" if state["guard"]["outcome"] == Outcome.ALLOW.value else "deny"

    def write(state: RefundState) -> dict:
        # The agent presents the MINTED JWT to the resource PEP. The agent holds no signing key;
        # the JWT is a short-lived bearer capability scoped at the resource by role->GRANT.
        eff = state["proposed"].args
        jwt = state["guard"]["jwt"]
        try:
            out = door.gateway.request(apikey=PUBLISHABLE, bearer_jwt=jwt,
                                       schema=eff["schema"], table=eff["table"], op=eff["op"],
                                       predicate=eff.get("predicate"), now=door.clock())
            rows = int(out.get("inserted", out.get("updated", out.get("deleted", 0))) or 0)
            return {"write": {"rows": rows, "via": out.get("via"), "role": out.get("role"),
                              "executed": True}}
        except SupabaseResourceError as e:   # resource-level refusal (defense in depth)
            return {"write": {"rows": 0, "executed": False, "resource_error": str(e)}}

    def refuse(state: RefundState) -> dict:
        # BLOCK/ESCALATE: no JWT was minted, so the resource is never reached. Zero writes.
        return {"write": {"rows": 0, "executed": False, "refused": True,
                          "cause": state["guard"]["cause"]}}

    g = StateGraph(RefundState)
    g.add_node("freeze_mandate", freeze_mandate)
    g.add_node("intake_ticket", intake_ticket)
    g.add_node("resolve_effect", resolve_effect)
    g.add_node("guard", guard)
    g.add_node("write", write)
    g.add_node("refuse", refuse)
    g.add_edge(START, "freeze_mandate")
    g.add_edge("freeze_mandate", "intake_ticket")
    g.add_edge("intake_ticket", "resolve_effect")
    g.add_edge("resolve_effect", "guard")
    g.add_conditional_edges("guard", route, {"allow": "write", "deny": "refuse"})
    g.add_edge("write", END)
    g.add_edge("refuse", END)
    return g.compile(checkpointer=MemorySaver())


@dataclass
class RunResult:
    scenario: str
    attack: Optional[str]
    resolver: str
    case: effects.RefundCase
    state: dict
    door: Door

    # convenience views for trace/tests
    @property
    def outcome(self) -> str: return self.state["guard"]["outcome"]
    @property
    def cause(self) -> str: return self.state["guard"]["cause"]
    @property
    def rows_written(self) -> int: return self.state["write"]["rows"]
    @property
    def token_minted(self) -> bool: return bool(self.state["guard"]["jwt"])
    @property
    def receipt_id(self) -> Optional[str]: return self.state["guard"]["receipt_id"]
    @property
    def decision(self): return self.state.get("decision")
    @property
    def tier(self) -> str: return self.door.tier
    @property
    def separation(self) -> Optional[Separation]: return self.door.separation


def _broker_socket(socket_path: Optional[str]) -> Optional[str]:
    return socket_path or os.environ.get("SIGNET_BROKER_SOCK")


def resolve_tier(tier: str, socket_path: Optional[str]) -> str:
    """Explicit tier selection. `auto` picks Tier 1 when a broker socket is configured (the
    platform-supports check is then enforced HONESTLY by detect_separation at label time), else
    Tier 0."""
    if tier == "auto":
        return "1" if _broker_socket(socket_path) else "0"
    if tier not in ("0", "1"):
        raise ValueError(f"unknown tier {tier!r} (expected '0', '1', or 'auto')")
    return tier


def run_scenario(*, scenario: str, attack: Optional[str] = None,
                 resolver: str = "deterministic", mandate_path: Optional[Path] = None,
                 clock=None, tier: str = "0", socket_path: Optional[str] = None,
                 jwks_path: Optional[str] = None, door: Optional[Door] = None) -> RunResult:
    """Build the door (Tier 0 in-proc, or Tier 1 over the broker socket), freeze the mandate, run
    the graph once, return a structured result. Single entry point for run.py and the tests.

    ADDITIVE `door` injection (default None = unchanged): when a pre-built `Door` is passed, it is
    used verbatim instead of building one from `tier`/`socket_path`. The on-ramp faithfulness test
    (`tests/test_onramp.py`) passes a `guard()`-assembled door to prove the facade reproduces the
    hand-wired run byte-for-byte. No behavior change for existing callers (they pass no `door`)."""
    case = effects.resolve_case(scenario, attack)
    if door is None:
        mandate = load_mandate(mandate_path)
        resolved = resolve_tier(tier, socket_path)
        if resolved == "1":
            sock = _broker_socket(socket_path)
            jwks = jwks_path or os.environ.get("SIGNET_BROKER_JWKS")
            if not sock or not jwks:
                raise RuntimeError("Tier 1 needs SIGNET_BROKER_SOCK + SIGNET_BROKER_JWKS "
                                   "(or socket_path/jwks_path)")
            door = build_tier1_door(mandate, socket_path=sock, jwks_path=jwks, clock=clock)
        else:
            door = build_door(mandate, clock=clock)
    graph = build_graph(door, scenario=scenario, attack=attack, resolver=resolver)
    state = graph.invoke({}, {"configurable": {"thread_id": f"refund-{scenario}-{attack or 'x'}"}})
    return RunResult(scenario=scenario, attack=attack, resolver=resolver, case=case,
                     state=dict(state), door=door)
