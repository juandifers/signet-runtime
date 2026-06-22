"""Additive, machine-readable SESSION emitter for the refund-triage demo (Session Viewer spec §2).

The demo otherwise only PRINTS the CLI panels (`trace.panel`). This module re-runs the exact same
`run_scenario` path and serialises the result into the session contract the viewer consumes (spec
§4) — a mandate header plus one record per proposed effect. It is **read-only over emitted data**:
it authors no verdict, mints nothing, and changes no behavior (every field below is read off the
`RunResult` the unchanged door already produced).

Field provenance (all cited in viewer/README.md):
  * mandate.principal      <- agent.AGENT_ID
  * mandate.granted_scope  <- door.mandate.grants (DbGrant.schema/.table/.ops), agent.py:163-167
  * effects[].proposed     <- RefundCase.proposed_effect().{tool,args}, effects.py:54-59
  * effects[].decision     <- RunResult.outcome (seam Outcome value), seam.py:33-37
  * effects[].reason       <- RunResult.cause (Decision.cause), seam.py:42
  * effects[].token_minted <- RunResult.token_minted, agent.py:246
  * effects[].performed    <- RunResult.state["write"], agent.py:192-210
  * effects[].receipt_id   <- RunResult.receipt_id (Receipt.receipt_hash), receipts.py:43
  * effects[].note         <- RefundCase.note (the A3 honest granularity note), effects.py:95-96
  * tier                   <- trace._tier_label / Separation.label, tier1.py / trace.py:17-23

HONESTY: the rail capability ref (`Decision.check_ref` — the short-lived ES256 JWT) is NEVER
serialised. The viewer must never render a secret (spec §3); `token_minted` (a bool) is all it sees.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Optional

from . import effects
from .agent import AGENT_ID, RunResult, run_scenario
from .trace import _tier_label

VIEWER_DIR = Path(__file__).resolve().parent / "viewer"
SESSION_JSON = VIEWER_DIR / "session.json"
COMBINED_JSON = VIEWER_DIR / "session.combined.json"
INDEX_HTML = VIEWER_DIR / "index.html"
_INLINE_START = "/*SIGNET_SESSION_START*/"
_INLINE_END = "/*SIGNET_SESSION_END*/"

# The default showcase, in narrative order: the legitimate refund, then the three injected attacks.
DEFAULT_RUNS: tuple[tuple[str, Optional[str]], ...] = (
    ("clean", None), ("injected", "a1"), ("injected", "a2"), ("injected", "a3"))

# rail FAMILY for an effect, from its tool name. Open set (supabase | egress | github, spec §4); the
# viewer renders per-rail, so a future egress effect needs no viewer change (spec §6).
_RAIL_BY_TOOL = {effects.DB_TOOL: "supabase"}


def _rail_for(tool: str) -> str:
    return _RAIL_BY_TOOL.get(tool, tool)


def _detail(args: dict) -> str:
    """Human-legible row detail for the proposed effect (legibility only — the door ignores it)."""
    parts = [f"{k}={args[k]}" for k in ("order_id", "amount", "currency", "set", "predicate")
             if k in args]
    return ", ".join(parts)


def _granted_scope(mandate) -> list[dict]:
    """The frozen Role-A grant, expanded per (rail, action, target) so the viewer header reads as a
    flat allow-list. `database`/`schema`/`table`/`ops` come straight off DbGrant."""
    scope = []
    for g in mandate.grants:
        for op in g.ops:
            scope.append({"rail": "supabase", "action": op, "target": f"{g.schema}.{g.table}"})
    return scope


def _performed(r: RunResult) -> dict:
    """Rail-shaped record of what actually happened (spec §4: `performed` varies by rail). For the
    supabase rail it is the row count + whether the resource was reached."""
    w = r.state.get("write", {})
    out = {"rows": int(w.get("rows", 0) or 0), "executed": bool(w.get("executed"))}
    if w.get("refused"):
        out["refused"] = True
    return out


def effect_record(seq: int, r: RunResult) -> dict:
    pe = r.case.proposed_effect()
    args = pe.args
    receipt = r.decision.receipt if r.decision is not None else None
    receipt_ok = bool(receipt is not None and r.door.receipts.verify(receipt)[0])
    return {
        "seq": seq,
        "rail": _rail_for(pe.tool),
        "label": r.case.label,
        "proposed": {
            "action": args["op"],
            "target": f"{args['schema']}.{args['table']}",
            "detail": _detail(args),
        },
        "decision": r.outcome.upper(),                       # ALLOW | BLOCK | ESCALATE
        "reason": r.cause,
        "escalation_source": r.state["guard"].get("escalation_source", ""),
        "token_minted": r.token_minted,
        "performed": _performed(r),
        "receipt_id": r.receipt_id,
        "receipt_verified": receipt_ok,
        "note": r.case.note or None,
    }


def build_session(runs=DEFAULT_RUNS, *, tier: str = "auto",
                  socket_path: Optional[str] = None, jwks_path: Optional[str] = None,
                  resolver: Optional[str] = None) -> dict:
    """Run each (scenario, attack) once through the unchanged door and serialise the session.

    The tier label is taken VERBATIM from what the run emitted (`trace._tier_label`) — `structural`
    only under a runtime-verified OS boundary, `advisory` otherwise (spec §0.4 honesty)."""
    records, mandate, label = [], None, "0 (advisory)"
    for i, (scenario, attack) in enumerate(runs, start=1):
        res = resolver or ("adversarial" if scenario == "injected" else "deterministic")
        r = run_scenario(scenario=scenario, attack=attack, resolver=res, tier=tier,
                         socket_path=socket_path, jwks_path=jwks_path)
        records.append(effect_record(i, r))
        mandate = r.door.mandate
        label = _tier_label(r)
    return {
        "session_id": "refund-triage-demo",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "tier": label,                                       # verbatim, e.g. "0 (advisory)"
        "tier_structural": label.strip().startswith("1"),    # badge color only; label is authoritative
        "mandate": {
            "principal": AGENT_ID,
            "task_id": mandate.task_id,
            "database": mandate.database,
            "granted_scope": _granted_scope(mandate),
        },
        "effects": records,
    }


def _combined_granted_scope(mandate) -> list[dict]:
    """The frozen task's grant across BOTH rails: the DB projection (supabase) + the egress
    projection (one allowlisted host). One task, two rail-scoped mandates (egress.py docstring)."""
    from .egress import ALLOWED_HOST, EGRESS_PORT
    scope = _granted_scope(mandate)                          # supabase entries
    scope.append({"rail": "egress", "action": "connect",
                  "target": f"{ALLOWED_HOST}:{EGRESS_PORT}"})
    return scope


def _combined_effect_record(seq: int, r) -> dict:
    """Serialise one EffectResult (egress.py) into the §4 per-effect contract — rail-agnostic, so
    the supabase ALLOW and the egress BLOCK share the exact same shape the viewer iterates."""
    receipt = r.receipt
    receipt_ok = bool(receipt is not None and r.receipt_log is not None
                      and r.receipt_log.verify(receipt)[0])
    return {
        "seq": seq,
        "rail": r.rail,
        "label": r.label,
        "proposed": {"action": r.action, "target": r.target, "detail": r.detail},
        "decision": r.outcome.upper(),                       # ALLOW | BLOCK
        "reason": r.reason,
        "escalation_source": r.escalation_source,
        "token_minted": r.token_minted,                      # egress is ALWAYS False (holds nothing)
        "performed": r.performed,                            # {rows:..} (db) | {egress:..} (egress)
        "receipt_id": getattr(receipt, "receipt_hash", None),
        "receipt_verified": receipt_ok,
        "note": r.note,
    }


def build_combined_session(*, clock=None, door=None) -> dict:
    """One agent, two rails, one session: the legitimate DB credit (ALLOW) and the injected egress
    exfil (BLOCK, advisory). Read-only — re-runs the unchanged doors and serialises the result.

    The egress effect carries `rail:"egress"`, `performed:{egress:"blocked"}`, and an `advisory`
    note — it renders in the viewer with NO viewer change (the timeline iterates effects[]).

    ADDITIVE `door` injection (default None = unchanged): a pre-built `CombinedDoor` is threaded
    through to `run_combined`, so the on-ramp can serialise a session off a `guard()`-assembled door
    and the faithfulness test can assert byte-identity with the hand-wired session."""
    from .egress import run_combined
    mandate, results, tier = run_combined(clock=clock, door=door)
    records = [_combined_effect_record(i, r) for i, r in enumerate(results, start=1)]
    return {
        "session_id": "refund-triage-combined",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "tier": tier,                                        # "0 (advisory)" — both rails advisory
        "tier_structural": tier.strip().startswith("1"),
        "mandate": {
            "principal": AGENT_ID,
            "task_id": mandate.task_id,
            "database": mandate.database,
            "granted_scope": _combined_granted_scope(mandate),
        },
        "effects": records,
    }


def _inline_into_index(session: dict) -> bool:
    """Rewrite the inlined default session inside index.html between the markers, so opening the
    viewer by double-click renders THIS session with zero network requests (spec §3). Returns False
    (without raising) if the viewer html isn't present yet."""
    if not INDEX_HTML.exists():
        return False
    html = INDEX_HTML.read_text()
    if _INLINE_START not in html or _INLINE_END not in html:
        return False
    blob = json.dumps(session, indent=2)
    pre, rest = html.split(_INLINE_START, 1)
    _, post = rest.split(_INLINE_END, 1)
    new = f"{pre}{_INLINE_START}\n  window.SIGNET_SESSION = {blob};\n  {_INLINE_END}{post}"
    INDEX_HTML.write_text(new)
    return True


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="examples.refund_triage.session", description=__doc__)
    p.add_argument("--out", type=Path, default=SESSION_JSON,
                   help=f"where to write the session JSON (default: {SESSION_JSON})")
    p.add_argument("--tier", choices=["0", "1", "auto"], default="auto",
                   help="tier to run at; the emitted label stays HONEST regardless (spec §0.4)")
    p.add_argument("--no-inline", action="store_true",
                   help="do not rewrite the inlined default session in index.html")
    p.add_argument("--combined", action="store_true",
                   help="emit the two-rail combined session (DB ALLOW + egress BLOCK) instead of "
                        "the four single-rail effects; writes session.combined.json and does NOT "
                        "inline (so index.html stays byte-identical — load it via the viewer's "
                        "“Load session JSON…”)")
    args = p.parse_args(argv)

    if args.combined:
        out = args.out if args.out != SESSION_JSON else COMBINED_JSON
        session = build_combined_session()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(session, indent=2) + "\n")
        print(f"wrote {out}  ({len(session['effects'])} effects, tier={session['tier']})")
        for e in session["effects"]:
            print(f"  #{e['seq']} {e['rail']}:{e['proposed']['action']} {e['proposed']['target']}"
                  f"  -> {e['decision']}  ({e['reason']})")
        print("inlined into index.html: False (load via “Load session JSON…”)")
        return 0

    session = build_session(tier=args.tier)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(session, indent=2) + "\n")
    inlined = (not args.no_inline) and _inline_into_index(session)

    verdicts = " ".join(f"{e['label'].split(' ')[0] if e['seq'] else ''}"
                        for e in session["effects"])
    print(f"wrote {args.out}  ({len(session['effects'])} effects, tier={session['tier']})")
    for e in session["effects"]:
        print(f"  #{e['seq']} {e['rail']}:{e['proposed']['action']} {e['proposed']['target']}"
              f"  -> {e['decision']}  ({e['reason']})")
    print(f"inlined into index.html: {inlined}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
