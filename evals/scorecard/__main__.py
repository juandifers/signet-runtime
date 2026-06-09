"""`python -m evals.scorecard` — one command that runs the full test surface and writes a
committed, provenance-stamped scorecard (markdown + json) split into INVARIANTS and MEASUREMENTS,
with run-over-run deltas.

Default is OFFLINE: the deterministic pytest suite, recorded-cassette replay containment, and
static architecture metrics — NO LLM calls. Every INVARIANT is decided offline. Add `--live` (with
OPENAI_API_KEY) to also run the role_b corpus, the borderline sweep, and the empirical breakout
ONCE PER MODEL, which adds the per-model MEASUREMENT rows and live invariant evidence.

  python -m evals.scorecard                         # offline scorecard
  python -m evals.scorecard --live                  # + per-model live rows (default MODELS)
  python -m evals.scorecard --live --models gpt-4o  # one model
  python -m evals.scorecard --update-kernel-baseline   # repin the kernel baseline (deliberate)
"""
from __future__ import annotations

import argparse
import datetime
import json
import platform
import subprocess
import sys
from pathlib import Path

from . import architecture, collect, grade, render

# OpenAI-only. The third is a GPT-5 reasoning variant (resolver auto-branches: developer role,
# no temperature, max_completion_tokens).
DEFAULT_MODELS = ["gpt-4o-mini", "gpt-4o", "gpt-5-mini"]


def _git(*args, default=""):
    try:
        return subprocess.run(["git", *args], cwd=architecture.ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:
        return default


def _provenance(models, live) -> dict:
    now = datetime.datetime.now()
    return {
        "commit": _git("rev-parse", "--short", "HEAD", default="nogit"),
        "commit_full": _git("rev-parse", "HEAD", default="nogit"),
        "dirty": bool(_git("status", "--porcelain")),
        "date": now.date().isoformat(),
        "generated_at": now.isoformat(timespec="seconds"),
        "live": live,
        "models": models if live else [],
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }


def _find_prior(out_dir: Path, current_base: str):
    cands = sorted((p for p in out_dir.glob("scorecard-*.json") if p.stem != current_base),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    for p in cands:
        try:
            return json.loads(p.read_text())
        except Exception:
            continue
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals.scorecard",
                                 description="Run the full test surface; emit a committed scorecard.")
    ap.add_argument("--live", action="store_true",
                    help="also run per-model live rows (needs OPENAI_API_KEY)")
    ap.add_argument("--models", default=None,
                    help="comma-separated OpenAI models (default: %s)" % ",".join(DEFAULT_MODELS))
    ap.add_argument("--k", type=int, default=5, help="samples/case for the live borderline sweep")
    ap.add_argument("--redteam-rounds", type=int, default=6,
                    help="adaptive red-team rounds per rail x model (live)")
    ap.add_argument("--out", default=str(architecture.ROOT / "reports"), help="output directory")
    ap.add_argument("--no-pytest", action="store_true", help="skip the pytest run (debug only)")
    ap.add_argument("--update-kernel-baseline", action="store_true",
                    help="repin the kernel baseline to current bytes, then exit (deliberate action)")
    args = ap.parse_args(argv)

    if args.update_kernel_baseline:
        h = architecture.write_baseline()
        print(f"Pinned kernel baseline ({len(h)} files) -> {architecture.BASELINE_PATH}")
        return 0

    models = [m.strip() for m in (args.models.split(",") if args.models else DEFAULT_MODELS) if m.strip()]

    # ---- OFFLINE collectors (always) ----
    print("[scorecard] pytest suite ...", file=sys.stderr)
    pytest_res = ({"available": False, "skipped_by_flag": True} if args.no_pytest
                  else collect.pytest_buckets())
    print("[scorecard] replay containment ...", file=sys.stderr)
    replay = collect.replay_containment()
    print("[scorecard] rail conformance battery ...", file=sys.stderr)
    conformance = collect.conformance()
    arch = {"kernel_edit": architecture.kernel_edit_check(), "loc": architecture.loc_metrics()}
    cvers = collect.corpus_versions()

    # ---- LIVE collectors (opt-in, per model) ----
    live = {"models": [], "corpus": {}, "sweep": {}, "quarantine": {}, "red_team": {}}
    if args.live:
        if not collect.have_openai_key():
            print("ERROR: --live needs OPENAI_API_KEY (checked env and .env).", file=sys.stderr)
            return 2
        live["models"] = models
        for model in models:
            print(f"[scorecard] live: {model} corpus ...", file=sys.stderr)
            live["corpus"][model] = collect.live_corpus(model)
            print(f"[scorecard] live: {model} borderline sweep (k={args.k}) ...", file=sys.stderr)
            live["sweep"][model] = collect.live_sweep(model, k=args.k)
            print(f"[scorecard] live: {model} breakout battery ...", file=sys.stderr)
            live["quarantine"][model] = collect.live_quarantine(model)
            print(f"[scorecard] live: {model} adaptive red-team ...", file=sys.stderr)
            live["red_team"][model] = collect.red_team(model, rounds=args.redteam_rounds)

    prov = _provenance(models, args.live)
    report = grade.assemble(provenance=prov, pytest_res=pytest_res, replay=replay,
                            architecture=arch, live=live, corpus_versions=cvers,
                            conformance=conformance)

    out_dir = Path(args.out)
    prior = _find_prior(out_dir, render.report_basename(prov))
    deltas = grade.diff_against_prior(report, prior)
    paths = render.write_reports(report, deltas, out_dir)

    # ---- console summary ----
    print(f"\n=== Signet Scorecard: {report['verdict']} ===")
    for i in report["invariants"]:
        mark = "PASS" if i["status"] == "PASS" else "**FAIL**"
        print(f"  [{mark:8s}] {i['id']}: {i['detail']}")
    if deltas.get("alarms"):
        print("\n  ALARMS:")
        for a in deltas["alarms"]:
            print(f"    !! {a['id']}: {a['from']} -> {a['to']}")
    elif deltas.get("prior"):
        nchg = len(deltas["invariant_changes"])
        ndrift = len(deltas["measurement_drift"])
        print(f"\n  deltas vs {deltas['prior']}: {nchg} invariant change(s), {ndrift} measurement drift(s)")
    print(f"\n  wrote {paths['md']}\n        {paths['json']}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
