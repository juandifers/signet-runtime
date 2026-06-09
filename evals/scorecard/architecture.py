"""Static architecture metrics for the scorecard:

  * kernel-edit check — the 10 core-kernel files MUST be byte-identical to a pinned baseline
    (`_kernel_baseline.json`). Any drift is an INVARIANT failure: rail work is forbidden from
    touching the kernel. The baseline stores a content hash per file; regenerate it ONLY with
    `python -m evals.scorecard --update-kernel-baseline` after a deliberate, reviewed kernel change.
  * LOC metrics — shared `_rail_core` LOC vs per-rail LOC, the reuse signal for "is the machinery
    actually rail-agnostic". Counted as non-blank, non-comment source lines.

No git dependency: hashing is over file BYTES so the check works in any checkout (or a tarball).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = Path(__file__).resolve().parent / "_kernel_baseline.json"

# The frozen kernel — CLAUDE.md invariant: rails add an authorizer, they never edit these.
KERNEL_FILES = (
    "signet/verifier.py", "signet/chain.py", "signet/models.py", "signet/policy.py",
    "signet/nonce.py", "signet/revocation.py", "signet/receipts.py", "signet/builder.py",
    "signet/crypto.py", "signet/canonical.py",
)

SHARED_CORE_DIR = "evals/_rail_core"
RAIL_DIRS = ("evals/github_railbridge", "evals/deploy_railbridge", "evals/infra_railbridge")


def _hash_file(rel: str) -> str:
    p = ROOT / rel
    return hashlib.sha256(p.read_bytes()).hexdigest()


def current_kernel_hashes() -> dict:
    return {rel: _hash_file(rel) for rel in KERNEL_FILES}


def write_baseline() -> dict:
    """Pin the current kernel bytes as the baseline. Deliberate action only."""
    hashes = current_kernel_hashes()
    BASELINE_PATH.write_text(json.dumps({"files": hashes}, indent=2, sort_keys=True) + "\n")
    return hashes


def load_baseline() -> dict:
    if not BASELINE_PATH.is_file():
        return {}
    return json.loads(BASELINE_PATH.read_text()).get("files", {})


def kernel_edit_check() -> dict:
    """Compare the 10 kernel files to the pinned baseline.

    Returns {edits, n, changed: [..], missing_baseline: bool, files: {rel: ok|changed|unpinned}}.
    `edits` is the count of files that differ from (or are absent in) the baseline. The INVARIANT
    is edits == 0."""
    baseline = load_baseline()
    cur = current_kernel_hashes()
    files, changed = {}, []
    for rel, h in cur.items():
        if rel not in baseline:
            files[rel] = "unpinned"
            changed.append(rel)
        elif baseline[rel] != h:
            files[rel] = "changed"
            changed.append(rel)
        else:
            files[rel] = "ok"
    return {
        "edits": len(changed), "n": len(cur), "changed": sorted(changed),
        "missing_baseline": not baseline, "files": files,
    }


def _source_loc(rel_dir: str) -> int:
    """Non-blank, non-comment Python source lines under a directory (excludes __pycache__)."""
    total = 0
    for p in sorted((ROOT / rel_dir).rglob("*.py")):
        for line in p.read_text().splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                total += 1
    return total


def loc_metrics() -> dict:
    shared = _source_loc(SHARED_CORE_DIR)
    per_rail = {d.split("/")[-1]: _source_loc(d) for d in RAIL_DIRS}
    rail_total = sum(per_rail.values())
    denom = shared + rail_total
    return {
        "shared_core_loc": shared,
        "per_rail_loc": per_rail,
        "rail_total_loc": rail_total,
        "reuse_ratio": round(shared / denom, 3) if denom else 0.0,
    }
