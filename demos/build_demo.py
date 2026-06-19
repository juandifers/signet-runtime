"""Build the static demo page from a LIVE run of the unmodified kernel.

This is the bridge between the truth layer (`demos/trace_pipeline.py`) and the story layer
(`demos/demo_template.html`). It runs the verifier + real authorizers, captures the trace, injects
it into the template, and writes the result to `docs/` so GitHub Pages can serve it.

Because the page is rebuilt from `build_trace()` every time, the published demo is always a
projection of the current kernel — it cannot silently drift from the code. Wire this into CI
(see .github/workflows/deploy-demo.yml) and the live URL is, by construction, "generated from the
unmodified kernel on commit <sha>."

Run:  python -m demos.build_demo          # writes docs/index.html
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from demos.trace_pipeline import build_trace
from demos.trace_resolution import build_resolution_trace
# build_attack_trace is imported lazily inside main(): it (and the `signet` CLI it shells out
# to) is a best-effort enrichment — the slim `demo` branch / minimal Pages build env does not
# carry signet/cli, so the import must not be load-bearing for the whole build.

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "demos" / "demo_template.html"
OUT_DIR = ROOT / "docs"
OUT_FILE = OUT_DIR / "index.html"


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "local"


def main() -> int:
    trace = build_trace()
    trace["resolution"] = build_resolution_trace()
    # GENERATED at build time by running the REAL local gate (`signet attack-me --json`) —
    # the Stage 2 local-gate tab is a projection of the shipped gate, not hand-authored.
    # Best-effort, like the recorded panels below: it needs signet/cli (absent on the slim demo
    # branch / minimal Pages env). On any failure the page omits the attack-me tab rather than
    # failing the whole build — the gauntlet (build_trace) stays mandatory.
    try:
        from demos.build_attack_trace import build_attack_trace
        trace["attack_me"] = build_attack_trace()
    except Exception as exc:
        print(f"  (attack-me panel omitted: {type(exc).__name__}: {exc})")
    # A RECORDED eval result (not regenerated here — needs a live model). Optional: if the file is
    # absent the page simply omits the evidence panel.
    ad_path = ROOT / "demos" / "agentdojo_result.json"
    if ad_path.exists():
        trace["agentdojo"] = json.loads(ad_path.read_text())
    # A RECORDED egress-containment result (AgentDojo slack, attack-success 60%->0%). Same as
    # agentdojo above: NOT regenerated here (needs a live model). Optional — panel omits itself
    # if the file is absent.
    eg_path = ROOT / "demos" / "egress_result.json"
    if eg_path.exists():
        trace["egress"] = json.loads(eg_path.read_text())
    # A RECORDED live-GitHub result (real Check Runs from a run of evals.github_railbridge.l3_run
    # against the installed GitHub App). Like agentdojo, it is NOT regenerated here — it needs live
    # credentials. Optional: if the file is absent the page simply omits the panel.
    lg_path = ROOT / "demos" / "live_github_result.json"
    if lg_path.exists():
        trace["live_github"] = json.loads(lg_path.read_text())
    # GENERATED at build time by running the REAL hermetic LangGraph injected-agent demo through
    # the unmodified kernel/interceptor path — a contained orchestrator story + signed receipt +
    # RFC-6962 inclusion proof. Gated on `langgraph` being installed (mirror A8): if absent the
    # page simply omits the Orchestrator tab's data. The proof bundle is also written next to the
    # page so the "verify it yourself" command works on a fresh clone.
    try:
        from demos.langgraph_merge_demo import build_trace as build_langgraph_trace
        lg = build_langgraph_trace()
        trace["langgraph"] = lg
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "langgraph_receipt.json").write_text(
            json.dumps(lg["bundle"], indent=2, default=str))
    except ImportError as e:
        print(f"  (langgraph trace skipped: {e} — install `langgraph` to include the "
              "Orchestrator tab)")
    # Stamp the build so the page can show its own provenance.
    trace["built_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    trace["built_from"] = _git_sha()

    compact = json.dumps(trace, separators=(",", ":"), default=str)
    assert "</script" not in compact.lower(), "trace contains a script close tag"

    template = TEMPLATE.read_text()
    assert "__TRACE_JSON__" in template, "template is missing the __TRACE_JSON__ placeholder"
    html = template.replace("__TRACE_JSON__", compact)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(html)
    # A .nojekyll file tells Pages to serve files as-is (no Jekyll processing).
    (OUT_DIR / ".nojekyll").write_text("")

    print(f"built {OUT_FILE.relative_to(ROOT)}  ({len(html):,} bytes)  "
          f"from {trace['built_from']} at {trace['built_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())