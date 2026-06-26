"""Offline acceptance harness for Spec 02: `python -m examples.browser_demo.selfcheck_scopes`.

Proves acceptance #1–#4 deterministically (no browser, no LLM — `select_scope(use_llm=False)`):
  1. element click policy — under `tour`, a click whose resolved destination is off-domain
     (ycombinator.com) is BLOCKED at the click;
  2. switch unlocks — after `select_scope` flips to `learn_more`, the SAME click is ALLOWED;
  3. the wall — an out-of-ceiling target (google.com) is BLOCKED under every scope;
  4. planner containment — a request mapping to nothing -> REFUSE, active unchanged; both
     scope-switch paths write verified receipts.
Also unit-checks `resolve_click_destination` against stub DOM nodes, and the hash chain.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from . import gate
from .guarded_tools import resolve_click_destination
from .scopes import select_scope
from .session import Session
from .web_mandate import WebMandate


class StubNode:
    """Minimal stand-in for a browser-use EnhancedDOMTreeNode (tag_name/attributes/parent_node)."""

    def __init__(self, tag: str, attributes: dict, parent: "StubNode | None" = None):
        self.node_name = tag.upper()
        self.attributes = attributes
        self.parent_node = parent

    @property
    def tag_name(self) -> str:
        return self.node_name.lower()


def build_mandate() -> object:
    return (
        WebMandate("demo-agent", task_id="scopes-selfcheck")
        .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "click", "extract"])
        .scope("tour",       domains=["wikipedia.org"],                   actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .scope("learn_more", domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .default_scope("tour")
        .build()
    )


def main() -> int:
    ok = True
    WIKI = "https://en.wikipedia.org/wiki/Y_Combinator"
    YC = "https://www.ycombinator.com/"

    # --- unit: destination resolution from stub nodes -------------------------------------
    print("== resolve_click_destination ==")
    anchor_yc = StubNode("a", {"href": YC})
    anchor_rel = StubNode("a", {"href": "/wiki/Startup"})
    span_in_yc = StubNode("span", {}, parent=anchor_yc)
    button = StubNode("button", {"onclick": "x()"})
    js_anchor = StubNode("a", {"href": "javascript:void(0)"})
    res = {
        "abs anchor":      resolve_click_destination(anchor_yc, WIKI),
        "relative anchor": resolve_click_destination(anchor_rel, WIKI),
        "span in anchor":  resolve_click_destination(span_in_yc, WIKI),
        "button (no href)": resolve_click_destination(button, WIKI),
        "javascript: href": resolve_click_destination(js_anchor, WIKI),
    }
    expect_dom = {"abs anchor": "www.ycombinator.com", "relative anchor": "en.wikipedia.org",
                  "span in anchor": "www.ycombinator.com", "button (no href)": None,
                  "javascript: href": None}
    for k, v in res.items():
        dom = gate.resolve_domain(v) if v else None
        good = dom == expect_dom[k]
        ok = ok and good
        print(f"  [{'OK ' if good else 'FAIL'}] {k:18} -> {v!r}  (domain={dom})")

    # --- acceptance 1–4 with receipts -----------------------------------------------------
    out = Path(tempfile.mkdtemp()) / "session.json"
    m = build_mandate()
    s = Session(m, out_path=out, session_id="scopes-selfcheck")

    def emit(label, action, target, expected, *, click_destination=None, provenance="agent"):
        nonlocal ok
        d = gate.decide(m, action, target, provenance=provenance, click_destination=click_destination)
        r = s.mint_receipt(action=action, target=gate.resolve_domain(target) or target,
                           outcome=d.outcome, active_scope=m.active)
        s.record(None, action, {"url": target}, d, r,
                 target=(gate.resolve_domain(click_destination) if click_destination else gate.resolve_domain(target)) or target,
                 performed={"browser": d.outcome}, label=label, active_scope=m.active)
        good = d.outcome == expected and s.receipts.verify(r)[0]
        ok = ok and good
        print(f"  [{'OK ' if good else 'FAIL'}] active={m.active:11} {label:34} -> {d.outcome.upper():5} | {d.reason}")

    print("\n== acceptance 1: off-domain click BLOCKED at the click (scope=tour) ==")
    emit("click YC link", "click", WIKI, "block", click_destination=YC, provenance="page")

    print("\n== in-scope clicks still ALLOW under tour ==")
    emit("click in-wiki link", "click", WIKI, "allow",
         click_destination="https://en.wikipedia.org/wiki/Startup", provenance="page")

    print("\n== acceptance 4 (refuse path): planner maps to nothing -> active unchanged ==")
    before = m.active
    dsw = select_scope(m, "open google for me please", session=s, use_llm=False)
    refuse_ok = (dsw.outcome == "block" and m.active == before)
    ok = ok and refuse_ok
    print(f"  [{'OK ' if refuse_ok else 'FAIL'}] select_scope('open google') -> {dsw.outcome.upper()}, active still {m.active!r}")

    print("\n== acceptance 2: select_scope flips to learn_more, SAME YC click now ALLOWS ==")
    dsw2 = select_scope(m, "show me YC's official site (ycombinator)", session=s, use_llm=False)
    flip_ok = (dsw2.outcome == "allow" and m.active == "learn_more")
    ok = ok and flip_ok
    print(f"  [{'OK ' if flip_ok else 'FAIL'}] select_scope(...) -> {dsw2.outcome.upper()}, active now {m.active!r}")
    emit("retry click YC link", "click", YC, "allow", click_destination=YC, provenance="page")

    print("\n== acceptance 3: out-of-ceiling target BLOCKED under EVERY scope ==")
    for scope_name in ("tour", "learn_more"):
        m.active = scope_name
        emit("navigate google.com (out of ceiling)", "navigate", "https://www.google.com/", "block",
             provenance="page")

    # planner cannot widen past the ceiling: there is no menu key granting google.com
    no_widen = all("google" not in d for sc in m.menu.values() for d in sc.allowed_domains)
    ok = ok and no_widen
    print(f"  [{'OK ' if no_widen else 'FAIL'}] no menu scope grants google.com (planner cannot widen past ceiling)")

    # --- hash chain over all receipts -----------------------------------------------------
    log = s.receipts.all()
    chain_ok = all(
        (r.prev_receipt_hash == (log[i - 1].receipt_hash if i > 0 else None))
        and s.receipts.verify(r)[0]
        for i, r in enumerate(log))
    ok = ok and chain_ok
    print(f"\nhash-chain over {len(log)} receipts valid: {chain_ok}")
    print(f"session.json: {s.out_path}")
    print("\nSPEC-02 SELF-CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
