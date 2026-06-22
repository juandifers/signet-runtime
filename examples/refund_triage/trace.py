"""One trace panel per run (spec §5) — a non-author reads the decision in five seconds.

Thin layer over the seam `Decision` carried on the RunResult; it authors no verdict, only renders
the one the supabase door produced. The contrast between the clean panel (ALLOW / token / 1 row)
and an injected panel (BLOCK / no token / 0 rows) IS the demo.
"""
from __future__ import annotations

from integrations.effect_gateway.seam import Outcome

from . import effects
from .agent import RunResult

BAR = "=" * 78


def _tier_label(r: RunResult) -> str:
    """Honest label (spec §0.4): `structural` ONLY under a runtime-verified OS boundary; otherwise
    `advisory`. Tier 0 is always advisory; Tier 1 is structural iff detect_separation confirmed it."""
    sep = r.separation
    if sep is None:
        return "0 (advisory)"
    return sep.label + (f"  [{sep.reason}]" if not sep.structural else "")


def _gate_line(r: RunResult) -> str:
    """Map the admission verdict onto the spec's owned/allow-list/fence triad."""
    src = r.state["guard"]["escalation_source"]
    owned = "✓" if src != "no_binding" else "✗"
    well_formed = "✓" if src != "gate_contained" else "✗"
    if r.outcome == Outcome.ALLOW.value:
        fence = "✓"
    else:
        fence = f"✗ ({r.cause})"
    return f"owned {owned}  allow-list {well_formed}  fence {fence}"


def _proposed_line(case: effects.RefundCase) -> str:
    a = case.proposed_effect().args
    extra = []
    for k in ("order_id", "amount", "currency", "set", "predicate"):
        if k in a:
            extra.append(f"{k}={a[k]}")
    return f"{a['op']} {a['schema']}.{a['table']}" + (("  " + "  ".join(extra)) if extra else "")


def panel(r: RunResult) -> str:
    allow = r.outcome == Outcome.ALLOW.value
    grants = ", ".join(r.state["mandate_summary"]["grants"])
    lines = [
        BAR,
        f"SCENARIO       : {r.scenario} / {r.case.key} {r.case.label} / "
        f"resolver={r.resolver} / tier={_tier_label(r)}",
        f"BOUND CONTEXT  : frozen task {r.state['mandate_summary']['task_id']} -> {grants}",
        f"PROPOSED EFFECT: {_proposed_line(r.case)}",
        f"GATE           : {_gate_line(r)}",
        f"KERNEL/DOOR    : {'ALLOW' if allow else 'BLOCK'}  ({r.cause})",
        f"TOKEN MINTED   : {'YES (scoped ES256 JWT)' if r.token_minted else 'NO'}",
        f"DB WRITE       : {(str(r.rows_written) + ' row(s)') if r.rows_written else 'NONE'}",
        f"RECEIPT        : {r.receipt_id}  ({_receipt_verify(r)})",
    ]
    if r.case.note:
        lines.append(f"NOTE           : {r.case.note}")
    lines.append(BAR)
    return "\n".join(lines)


def _receipt_verify(r: RunResult) -> str:
    """The receipt is signed + hash-chained; verify it here (in-memory log, this run)."""
    dec = r.decision
    if dec is None or dec.receipt is None:
        return "no receipt"
    ok, _msg = r.door.receipts.verify(dec.receipt)
    return f"signed; verify ok={ok}"
