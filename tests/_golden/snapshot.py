"""Write the §0.3 golden corpus to tests/_golden/rail_verdicts.json.

Run BEFORE the rail-algebra refactor to capture current behavior, then NEVER again unless behavior
is intentionally changed (it must not be — BEHAVIOR-PRESERVED). The acceptance test reproduces this
file verdict-for-verdict.

    python3 tests/_golden/snapshot.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # put tests/ on the path
from _golden.corpus import build_corpus

OUT = Path(__file__).resolve().parent / "rail_verdicts.json"


def main() -> None:
    corpus = build_corpus()
    OUT.write_text(json.dumps(corpus, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT} ({len(corpus['merge']['policy'])} merge-policy, "
          f"{len(corpus['merge']['resolve'])} merge-resolve, {len(corpus['egress'])} egress)")


if __name__ == "__main__":
    main()
