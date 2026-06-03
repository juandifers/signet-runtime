"""Locate and import the pinned tau-bench source by composition (no fork).

tau-bench is NOT vendored into this repo and NOT pip-installed (the editable
install of the cloned repo executes lifecycle code; we avoid that). Instead the
upstream clone is placed on ``sys.path`` so we import its real ``Env`` / retail
tools / tasks / reward and drive them unchanged. The signet kernel and the
agentdojo harness are untouched; this adapter is new code only.

Pinned version
---------------
    repo:   github.com/sierra-research/tau-bench
    commit: 59a200c6d575d595120f1cb70fea53cef0632f6b  (2026-03-18)
    domain: retail  (canonical; clear irreversible actions; no banking domain
            exists in tau-bench or tau2-bench, and tau2-bench requires Py>=3.12
            which would split us off from the signet kernel's 3.11 env)

Set ``TAU_BENCH_SRC`` to override the location of the clone.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

TAU_BENCH_COMMIT = "59a200c6d575d595120f1cb70fea53cef0632f6b"

_CANDIDATES = (
    os.environ.get("TAU_BENCH_SRC"),
    str(Path.home() / "Documents" / "tau-bench-src"),
    "/tmp/tau-bench-src",
)


def ensure_on_path() -> str:
    """Put the pinned tau-bench clone on sys.path; return the resolved root.

    Raises a clear error (rather than a bare ImportError later) if the clone is
    missing, so the failure points at the setup step, not at an import deep in
    the run.
    """
    for cand in _CANDIDATES:
        if not cand:
            continue
        root = Path(cand)
        if (root / "tau_bench" / "envs" / "retail").is_dir():
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            return str(root)
    raise RuntimeError(
        "tau-bench source not found. Clone it and point TAU_BENCH_SRC at it:\n"
        "  git clone https://github.com/sierra-research/tau-bench "
        "~/Documents/tau-bench-src\n"
        f"  (cd ~/Documents/tau-bench-src && git checkout {TAU_BENCH_COMMIT})\n"
        "Then re-run. (litellm must also be installed: pip install 'litellm>=1.41.0')."
    )
