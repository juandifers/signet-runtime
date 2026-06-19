"""Stage 3 — publish the post-run Merkle root as the anchor.

This runs AFTER a run, never on the egress path. The egress decision + leaf commitment (Stage 1/2)
are already final before this is called; anchoring cannot block, delay, or fail an egress.

v1 mechanism: write the root to `anchor/root.txt` and emit the exact public-commit command. The
anchor is the commit + its timestamp in a public repo: forging a receipt's membership after the
fact would require rewriting already-pushed history. The actual `git push` is a human last-mile
(an outward-facing action), so this module writes the file and PRINTS the command rather than
pushing. An `opentimestamps_hook` marks the trustless (Bitcoin) upgrade, intentionally unimplemented.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ANCHOR_DIR = _REPO_ROOT / "anchor"


def publish_root(root_hex: str, *, anchor_dir: Path = _ANCHOR_DIR) -> Path:
    """Write the root to anchor/root.txt and print the exact command to anchor it publicly. Returns
    the path written. Does NOT push (human last-mile)."""
    anchor_dir.mkdir(parents=True, exist_ok=True)
    path = anchor_dir / "root.txt"
    path.write_text(root_hex.strip() + "\n", encoding="utf-8")
    for line in commit_commands(path, root_hex):
        print(line)
    return path


def commit_commands(path: Path, root_hex: str) -> List[str]:
    """The exact commands a human runs to anchor the root in a public repo."""
    return [
        "# anchor the egress-log root publicly (human last-mile — outward-facing, not auto-run):",
        f"git add {path}",
        f"git commit -m 'anchor egress log root {root_hex[:12]} @ run'",
        "git push   # the pushed commit + its timestamp ARE the anchor",
    ]


def opentimestamps_hook(root_hex: str) -> None:
    """UNIMPLEMENTED upgrade: anchor the root in Bitcoin via OpenTimestamps for a trustless
    timestamp, replacing 'committed to a public git repo' with a chain-backed proof.

    Implementation sketch (human last-mile): write `root_hex` to a file, run `ots stamp <file>` to
    obtain a `.ots` receipt from a calendar server, store the `.ots` alongside `anchor/root.txt`,
    and later `ots upgrade`/`ots verify` it once the Bitcoin attestation confirms. No code path in
    this repo depends on this — it is a documented future swap (see anchor/README.md)."""
    raise NotImplementedError(
        "OpenTimestamps (Bitcoin) anchoring is a documented upgrade hook — see anchor/README.md")
