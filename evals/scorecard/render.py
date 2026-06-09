"""Render the assembled report + deltas to committed artifacts: a JSON (machine truth) and a
Markdown (human-readable), both named scorecard-<date>-<shortsha>.{json,md} under reports/."""
from __future__ import annotations

import json
from pathlib import Path

_TICK = {"PASS": "✅", "FAIL": "❌"}


def report_basename(provenance: dict) -> str:
    return f"scorecard-{provenance['date']}-{provenance['commit']}"


def write_reports(report: dict, deltas: dict, out_dir) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = report_basename(report["provenance"])
    json_path = out / f"{base}.json"
    md_path = out / f"{base}.md"
    doc = {**report, "deltas": deltas}
    json_path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    md_path.write_text(render_markdown(report, deltas))
    return {"json": str(json_path), "md": str(md_path)}


def render_markdown(report: dict, deltas: dict) -> str:
    p = report["provenance"]
    L = []
    L.append(f"# Signet Scorecard — {report['verdict']} {_TICK.get(report['verdict'],'')}")
    L.append("")
    # ---- provenance ----
    L.append("## Provenance")
    L.append("")
    L.append(f"- **commit:** `{p['commit']}`{' (dirty)' if p.get('dirty') else ''}")
    L.append(f"- **date:** {p['date']}  ·  **generated:** {p.get('generated_at','?')}")
    L.append(f"- **mode:** {'LIVE (real models)' if p.get('live') else 'OFFLINE (replay only — no LLM calls)'}")
    models = p.get("models") or []
    L.append(f"- **models:** {', '.join(models) if models else '— (no live model rows)'}")
    cv = p.get("corpus_versions", {})
    cvs = "  ".join(f"{k}={v.get('version','?')}(n={v.get('n','?')})"
                    for k, v in cv.items() if isinstance(v, dict))
    L.append(f"- **corpus versions:** {cvs or '—'}")
    L.append(f"- **python:** {p.get('python','?')}  ·  **platform:** {p.get('platform','?')}")
    L.append("")

    # ---- alarms first (loudest) ----
    if deltas.get("alarms"):
        L.append("## 🚨 ALARMS — invariant regressions vs the previous scorecard")
        L.append("")
        for a in deltas["alarms"]:
            L.append(f"- **{a['id']}**: {a['from']} → **{a['to']}** ({a['kind']})")
        L.append("")

    # ---- invariants ----
    L.append("## Invariants  *(binary — any FAIL fails the scorecard; these are bugs)*")
    L.append("")
    L.append("| | Invariant | Status | Detail |")
    L.append("|---|---|---|---|")
    for i in report["invariants"]:
        L.append(f"| {_TICK.get(i['status'],'')} | {i['id']} | **{i['status']}** | {i['detail']} |")
    L.append("")
    # evidence fold
    L.append("<details><summary>invariant evidence</summary>")
    L.append("")
    for i in report["invariants"]:
        L.append(f"- **{i['id']}** — {i['description']}")
        for e in i["evidence"]:
            L.append(f"    - {e}")
    L.append("")
    L.append("</details>")
    L.append("")

    # ---- measurements ----
    m = report["measurements"]
    L.append("## Measurements  *(trend — watch the drift, not pass/fail)*")
    L.append("")
    a = m["architecture"]
    L.append(f"**Architecture** — shared `_rail_core` = {a['shared_core_loc']} LOC; "
             f"per-rail = {a['per_rail_loc']}; reuse ratio = **{a['reuse_ratio']}** "
             "(shared / (shared + per-rail)).")
    rc = m["replay_containment"]
    L.append(f"**Replay containment** — {rc.get('contained_pct')}% across {rc.get('fooled')} "
             f"fooled / {rc.get('samples')} replayed samples.")
    conf = m.get("conformance", {})
    if conf:
        parts = [f"{name}={'✅' if r.get('all_pass') else '❌'}"
                 f"{'(hyp)' if r.get('hypothesis_used') else ''}" for name, r in conf.items()]
        L.append(f"**Rail conformance** — {'  '.join(parts)} (offline battery, 7 invariants/rail).")
    rt = m.get("red_team", {})
    if rt:
        parts = [f"{k}: breakout={v['breakout_rate']} degradation={v['degradation_rate']}"
                 for k, v in rt.items()]
        L.append("**Red-team** — " + "  ·  ".join(parts))
    L.append("")
    per_model = m.get("per_model", {})
    if not per_model:
        L.append("_No live model rows (run with `--live` and an OpenAI key to populate "
                 "per-model measurements)._")
        L.append("")
    for model, row in per_model.items():
        L.append(f"### `{model}`")
        if row.get("corpus_error") or row.get("sweep_error") or row.get("quarantine_error"):
            for k in ("corpus_error", "sweep_error", "quarantine_error"):
                if row.get(k):
                    L.append(f"- ⚠️ {k}: `{row[k]}`")
        ru = row.get("resolution_utility")
        if ru:
            L.append(f"- **resolution utility:** correct={ru['correct']} escalate={ru['escalate']} "
                     f"wrong={ru['wrong']}  ·  outcome-correct={ru['outcome_correct']}")
        for label, key, unit in (("false-escalation (autonomy cost) L0/L1", "false_escalation_pct", "%"),
                                 ("over-resolution L3/L4", "over_resolution_pct", "%"),
                                 ("schema compliance", "schema_compliance_pct", "%"),
                                 ("bounded-to-own", "bounded_to_own_pct", "%"),
                                 ("containment-when-fooled", "containment_pct", "%"),
                                 ("k-variance (flip rate)", "k_variance", ""),
                                 ("breakout rate", "breakout_rate", "")):
            if key in row and row[key] is not None:
                L.append(f"- **{label}:** {row[key]}{unit}")
        if row.get("abstention_boundary"):
            bnd = "  ".join(f"{b}: clean={v['clean']} inj={v['injection']}"
                            for b, v in row["abstention_boundary"].items())
            L.append(f"- **abstention boundary (first level P(escalate)≥0.5):** {bnd}")
        L.append("")

    # ---- deltas ----
    L.append("## Deltas vs previous scorecard")
    L.append("")
    if not deltas.get("prior"):
        L.append("_No prior scorecard found — this is the baseline._")
    else:
        L.append(f"Compared against `{deltas['prior']}` ({deltas.get('prior_date','?')}).")
        L.append("")
        if deltas["invariant_changes"]:
            L.append("**Invariant changes:**")
            for c in deltas["invariant_changes"]:
                arrow = "🚨" if (c["from"] == "PASS" and c["to"] == "FAIL") else "↩️"
                L.append(f"- {arrow} {c['id']}: {c['from']} → {c['to']}")
        else:
            L.append("- No invariant status changes.")
        L.append("")
        drift = deltas.get("measurement_drift", [])
        if drift:
            L.append("**Measurement drift:**")
            L.append("")
            L.append("| metric | from | to | Δ |")
            L.append("|---|---|---|---|")
            for d in drift[:40]:
                L.append(f"| {d['metric']} | {d['from']} | {d['to']} | {d['direction']} {d['delta']} |")
        else:
            L.append("- No measurement drift (or no comparable numerics).")
    L.append("")
    return "\n".join(L) + "\n"
