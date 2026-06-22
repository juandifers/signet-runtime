"""`guard(tool, mandate)` — wrap a LangGraph tool so its effects cross the Signet seam (spec §4).

FACADE ONLY (spec §0.2): `guard()` adds NO enforcement. It reads the mandate's rails, assembles the
matching `RailBinding`s by calling the EXISTING demo builders verbatim
(`examples/refund_triage/agent.py:build_door` / `build_tier1_door`, `egress.py:build_combined_door`),
constructs the unchanged `EffectInterceptor`, and returns the tool wrapped by the unchanged
`signet_guarded_tool` (integrations/langgraph/guarded_tool.py:53). A tool guarded here produces the
SAME verdicts, receipts, and session as the hand-wired demo — proven byte-for-byte by
tests/test_onramp.py.

THE TWO DOOR ARCHETYPES STAY DISTINCT (spec §0.2): the DB rail is capability-issuing (a JWT is
minted and presented to Postgres); the egress rail is effect-performing (the proxy connects/refuses;
the agent holds nothing, `check_ref is None`). `guard()` never mints a token for an egress effect — it
just routes the effect to the proxy binding the demo already provides.

Doors are CACHED per (mandate, config): guarding the DB tool and the egress tool with the SAME
mandate yields ONE shared `EffectInterceptor`, so both effects land in ONE session (spec §1/§6).
Call `guarded_door(mandate)` to get that shared door (and `.stop()` it when done).
"""
from __future__ import annotations

import logging
import os
from typing import Callable, Optional

from integrations.effect_gateway.seam import EffectInterceptor

from .config import SignetConfig
from .errors import SignetOnRampError, UnknownRailError, require
from .mandate import KNOWN_RAILS, Mandate

log = logging.getLogger("signet.onramp")

# rail -> the guarded-tool (tool_name, id_arg) the demo bindings expect.
# supabase: rails_supabase._DB_TOOLS / id "table"; egress: EgressProxyBinding._EGRESS_TOOLS / id "host".
_RAIL_TOOL = {"supabase": ("db_write", "table"), "egress": ("fetch_url", "host")}
# tool name -> rail, for inferring the rail from a tool that carries a .tool_name.
_TOOL_RAIL = {"db_write": "supabase",
              **{t: "egress" for t in ("egress", "http_connect", "fetch_url", "post_webpage",
                                       "requests_get", "requests_post", "http_get")}}


# ============================================================================================
# Door assembly — delegate to the EXISTING demo builders (faithfulness is structural, not re-coded)
# ============================================================================================
def build_onramp_door(mandate: Mandate, signet: Optional[SignetConfig] = None, *, clock=None):
    """Assemble (do not reuse-cache) a door for `mandate` under `signet`. Returns the demo's `Door`
    (DB-only) or `CombinedDoor` (DB + egress). Delegates to the unchanged builders so the wiring is
    identical to the hand-wired demo."""
    signet = signet or SignetConfig()
    rails = mandate.rails()
    if not rails:
        raise UnknownRailError("<empty>", KNOWN_RAILS)
    unknown = rails - set(KNOWN_RAILS)
    if unknown:
        raise UnknownRailError(sorted(unknown)[0], KNOWN_RAILS)

    tm = mandate.to_taskmandate()
    if "egress" in rails:
        return _build_combined(mandate, tm, signet, clock)

    # supabase only
    require("jwt", rail="supabase", extra="supabase")     # ES256 minting/verify (pyjwt[crypto])
    agent = _agent()
    if signet.tier == 1:
        sock = signet.broker_socket or os.environ.get("SIGNET_BROKER_SOCK")
        jwks = signet.jwks_path or os.environ.get("SIGNET_BROKER_JWKS")
        if not sock or not jwks:
            raise SignetOnRampError(
                "SignetConfig(tier=1) needs a structural DB broker: set broker_socket + jwks_path "
                "(or env SIGNET_BROKER_SOCK + SIGNET_BROKER_JWKS). See refund_triage README 'Tier 1'.")
        return agent.build_tier1_door(tm, socket_path=sock, jwks_path=jwks, clock=clock)
    return agent.build_door(tm, clock=clock)


def _build_combined(mandate: Mandate, tm, signet: SignetConfig, clock):
    """DB + egress under one frozen task. The DB rail is Tier 0 in-process (egress forces the
    advisory tier on this build); egress goes to the demo's auto offline proxy, or — if
    `signet.proxy` is set — to a caller-run proxy (still advisory until a netns; out of scope)."""
    require("jwt", rail="supabase", extra="supabase")     # the combined door has a DB rail
    eg = _egress()
    if signet.tier == 1:
        log.warning("on-ramp: egress is advisory on this build; the combined door keeps the DB rail "
                    "at Tier 0 (structural egress needs a netns — out of scope). Label: 0 (advisory).")
    if not signet.proxy:
        return eg.build_combined_door(tm, clock=clock)    # auto offline proxy (advisory)

    # caller-run external proxy: DB binding (unchanged) + an egress binding pointed at it.
    host, port = signet.proxy_hostport()
    agent = _agent()
    db_door = agent.build_door(tm, clock=clock)
    db_binding = db_door.interceptor.bindings[0]
    audit = _tier1().make_audit_log()
    eg_binding = eg.EgressProxyBinding(proxy_host=host, proxy_port=port,
                                       receipt_log=audit, agent_id=eg.AGENT_ID)
    interceptor = EffectInterceptor(tm, [db_binding, eg_binding], env=None, bridge=None,
                                    receipts=db_door.receipts, world=None)
    return eg.CombinedDoor(interceptor=interceptor, db_door=db_door, egress_env=None,
                           egress_binding=eg_binding, egress_receipts=audit, mandate=tm)


# ============================================================================================
# The shared, cached door (so two guard() calls under one mandate share ONE session)
# ============================================================================================
def _cache_key(signet: SignetConfig):
    return (signet.tier, signet.broker_socket, signet.jwks_path, signet.proxy)


def guarded_door(mandate: Mandate, signet: Optional[SignetConfig] = None, *, clock=None):
    """Return the door shared by every `guard()` call for this (mandate, config) — building it once
    and caching it on the mandate. Stop it with `.stop()` when the session is done."""
    signet = signet or SignetConfig()
    cache = mandate.__dict__.setdefault("_onramp_doors", {})
    key = _cache_key(signet)
    if key not in cache:
        cache[key] = build_onramp_door(mandate, signet, clock=clock)
        log.info("signet on-ramp: doors assembled at tier %s for rails %s",
                 signet.label(), sorted(mandate.rails()))
    return cache[key]


def _interceptor_of(door):
    return door.interceptor


# ============================================================================================
# guard() — the wrap
# ============================================================================================
def guard(tool: Callable, mandate: Mandate, *, signet: Optional[SignetConfig] = None,
          rail: Optional[str] = None, tool_name: Optional[str] = None,
          id_arg: Optional[str] = None, clock=None) -> Callable:
    """Wrap `tool` so its proposed effect crosses the Signet seam for `mandate`. Returns a drop-in
    callable (same kwargs interface) that yields a `GuardedResult` — ALLOW lets the effect proceed,
    BLOCK refuses it with a signed receipt. Local-dev default is Tier 0 advisory (`SignetConfig`
    makes the DB rail structural). Fail-closed: an unreachable door BLOCKs at call time (the binding's
    posture), never a silent pass."""
    signet = signet or SignetConfig()
    rail = rail or _infer_rail(tool, mandate)
    if rail not in KNOWN_RAILS:
        raise UnknownRailError(rail, KNOWN_RAILS)
    if rail not in mandate.rails():
        hint = '.allow_egress(host)' if rail == 'egress' else '.allow_db("schema.table")'
        raise SignetOnRampError(
            f"cannot guard the {rail!r} rail: the mandate grants no {rail!r} scope "
            f"(it has {sorted(mandate.rails())}). Add it on the builder, e.g. {hint}.")

    door = guarded_door(mandate, signet, clock=clock)
    default_tool, default_id = _RAIL_TOOL[rail]
    return _wrap(_interceptor_of(door), tool_name=tool_name or default_tool,
                 id_arg=id_arg or default_id)


def _wrap(interceptor, *, tool_name: str, id_arg: str) -> Callable:
    from integrations.langgraph.guarded_tool import signet_guarded_tool
    return signet_guarded_tool(interceptor, tool_name=tool_name, id_arg=id_arg)


def _infer_rail(tool, mandate: Mandate) -> str:
    name = getattr(tool, "tool_name", None) or getattr(tool, "__name__", "")
    if name in _TOOL_RAIL:
        return _TOOL_RAIL[name]
    rails = mandate.rails()
    if len(rails) == 1:
        return next(iter(rails))
    raise SignetOnRampError(
        f"could not infer the rail for tool {name or tool!r}: the mandate spans {sorted(rails)}. "
        f"Pass rail=\"supabase\" or rail=\"egress\" to guard().")


# ============================================================================================
# Lazy imports of the demo modules (keep `Mandate`/`SignetConfig` import-light; give teaching errors)
# ============================================================================================
def _agent():
    # build_door/build_tier1_door need no langgraph (the StateGraph is imported lazily only when a
    # graph is RUN). pyjwt is required by the supabase binding and is checked by the caller.
    from examples.refund_triage import agent
    return agent


def _egress():
    from examples.refund_triage import egress
    return egress


def _tier1():
    from examples.refund_triage import tier1
    return tier1
