"""Offline proof of Spec 04 Part 1 — operator-driven scope control (no LLM, no browser).

Exercises the operator intake + the deterministic select_scope activation it feeds:

  1. operator request -> select_scope flips tour -> learn_more (scope_switch ALLOW receipt),
     and the previously-BLOCKED YC click is now ALLOWED under the new active scope;
  2. an operator request that maps to nothing -> REFUSE, active scope unchanged (still blocked);
  3. an out-of-ceiling target (google.com) stays BLOCKED regardless of operator input;
  4. read_operator_request reads one stdin line off the event loop; bare ENTER -> "" (deny).

Run: `python -m examples.browser_demo.selfcheck_operator`   (exit 0 = PASS)
"""
from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path

from .gate import decide
from .operator import read_operator_request
from .scopes import select_scope
from .session import Session
from .web_mandate import WebMandate

YC_CLICK = "https://en.wikipedia.org/wiki/Y_Combinator"
YC_DEST = "https://www.ycombinator.com/"
GOOGLE = "https://www.google.com"


def _mandate():
    return (
        WebMandate("demo-agent", task_id="op-selfcheck")
        .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "click", "extract"])
        .scope("tour",       domains=["wikipedia.org"],                    actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .scope("learn_more", domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .default_scope("tour")
        .build()
    )


def _check(name: str, cond: bool) -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        raise SystemExit(1)


def main() -> int:
    out = Path(__file__).resolve().parent / "_selfcheck_operator.session.json"
    m = _mandate()
    s = Session(m, out_path=out, session_id="op-selfcheck")
    print("SPEC-04 PART-1 SELF-CHECK")

    # Baseline: under `tour`, the YC click is blocked at the click (off-scope destination).
    d0 = decide(m, "click", YC_CLICK, provenance="page", click_destination=YC_DEST)
    _check("under tour: YC click BLOCKED", not d0.allowed)

    # (1) operator grants a pre-authorized scope -> deterministic activation + receipt.
    before = len(s.to_dict()["effects"])
    d = select_scope(m, "show me Y Combinator's official website", session=s, use_llm=False)
    _check("operator request -> select_scope ALLOW", d.allowed)
    _check("active flipped to learn_more", m.active == "learn_more")
    _check("scope_switch receipt written", len(s.to_dict()["effects"]) == before + 1)
    _check("switch receipt verifies", s.to_dict()["effects"][-1]["receipt_verified"])
    d1 = decide(m, "click", YC_CLICK, provenance="page", click_destination=YC_DEST)
    _check("under learn_more: same YC click now ALLOWED", d1.allowed)

    # (3) out-of-ceiling target stays blocked under the granted scope.
    dg = decide(m, "navigate", GOOGLE, provenance="agent")
    _check("google navigate BLOCKED under learn_more (ceiling wall)", not dg.allowed)

    # (2) an operator request that maps to nothing -> REFUSE, active unchanged.
    m2 = _mandate()
    s2 = Session(m2, out_path=out, session_id="op-selfcheck-2")
    d2 = select_scope(m2, "please open my online banking dashboard", session=s2, use_llm=False)
    _check("unmappable request -> REFUSE", not d2.allowed)
    _check("active unchanged (still tour)", m2.active == "tour")
    db = decide(m2, "click", YC_CLICK, provenance="page", click_destination=YC_DEST)
    _check("YC click still BLOCKED after refuse", not db.allowed)

    # (4) read_operator_request: reads one line; bare ENTER -> "".
    real = sys.stdin
    try:
        sys.stdin = io.StringIO("learn more about YC\n")
        got = asyncio.run(read_operator_request(""))
        _check("read_operator_request returns the typed line", got == "learn more about YC")
        sys.stdin = io.StringIO("\n")
        empty = asyncio.run(read_operator_request(""))
        _check("bare ENTER -> empty string (deny)", empty == "")
    finally:
        sys.stdin = real

    out.unlink(missing_ok=True)
    print("SPEC-04 PART-1 SELF-CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
