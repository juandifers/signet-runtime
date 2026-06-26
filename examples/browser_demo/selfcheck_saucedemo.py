"""Offline acceptance harness for Spec 06 — PATH-level scoping.

`python -m examples.browser_demo.selfcheck_saucedemo`   (exit 0 = PASS)

No browser, no LLM (`select_scope(use_llm=False)`). Proves the dual-check (ceiling AND active
scope) and the ceiling-deny vs scope-deny distinction on the real saucedemo mandate, and emits a
sample `session.json` for the full arc (shopping ALLOWs → checkout-path BLOCK under shopping →
scope_switch to checkout → checkout-path ALLOWs → /checkout-complete BLOCK as a ceiling-deny).

  1. under `shopping`, navigate/click whose path is /checkout-step-one.html -> BLOCK (scope-deny);
     under `checkout` the same -> ALLOW.
  2. /checkout-complete.html -> BLOCK under EVERY scope (ceiling-deny); no menu scope's path_allow
     can reach it, so select_scope cannot grant it.
  3. path globs: /inventory.html and /inventory-item.html?id=4 are allowed by /inventory*; query
     strings / fragments don't break path extraction.
  4. ceiling-deny ("not allowed in ceiling") is surfaced distinctly from scope-deny ("not in
     scope 'shopping'") in the reason.
  5. the current-page backstop: a JS click lands the agent on an off-scope path, and the NEXT
     action there is BLOCKED even though the click itself was allow_unresolved.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from . import gate
from .run_saucedemo import build_mandate
from .scopes import select_scope
from .session import Session

BASE = "https://www.saucedemo.com"
LOGIN = BASE + "/"
INVENTORY = BASE + "/inventory.html"
ITEM = BASE + "/inventory-item.html?id=4"
CART = BASE + "/cart.html"
STEP1 = BASE + "/checkout-step-one.html"
STEP2 = BASE + "/checkout-step-two.html"
COMPLETE = BASE + "/checkout-complete.html"

_ok = True


def _check(name: str, cond: bool, detail: str = "") -> None:
    global _ok
    _ok = _ok and cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  | {detail}" if detail else ""))


def main() -> int:
    print("SPEC-06 SELF-CHECK — path-level scoping")
    m = build_mandate()                                  # active = shopping

    # --- (3) path extraction: query/fragment dropped, '' -> '/' ---------------------------
    print("\n== path extraction ==")
    _check("/inventory.html", gate.resolve_path(INVENTORY) == "/inventory.html")
    _check("/inventory-item.html?id=4 -> path drops query",
           gate.resolve_path(ITEM) == "/inventory-item.html")
    _check("bare host -> '/'", gate.resolve_path(BASE) == "/")
    _check("fragment dropped", gate.resolve_path(CART + "#summary") == "/cart.html")

    # --- (3) /inventory* glob matches catalog + item pages under shopping ------------------
    print("\n== /inventory* glob (scope=shopping) ==")
    for label, url in (("/inventory.html", INVENTORY), ("/inventory-item.html?id=4", ITEM)):
        d = gate.decide(m, "navigate", url, provenance="page")
        _check(f"navigate {label} ALLOW", d.allowed, d.reason)

    # --- (1) checkout path: BLOCK under shopping, ALLOW under checkout ---------------------
    print("\n== acceptance 1: /checkout-step-one.html — scope-gated ==")
    m.active = "shopping"
    d_sh = gate.decide(m, "navigate", STEP1, provenance="page")
    _check("navigate /checkout-step-one under shopping -> BLOCK", not d_sh.allowed, d_sh.reason)
    _check("reason is SCOPE-deny (operator can grant)", "not in scope 'shopping'" in d_sh.reason)
    m.active = "checkout"
    d_co = gate.decide(m, "navigate", STEP1, provenance="page")
    _check("navigate /checkout-step-one under checkout -> ALLOW", d_co.allowed, d_co.reason)
    m.active = "shopping"

    # --- (5) current-page backstop: a JS click lands off-path; next action there is blocked
    print("\n== acceptance 5: current-page backstop (JS nav lands off-scope) ==")
    # the click itself, on /cart.html with an unresolved (button) destination, is allowed:
    d_click = gate.decide(m, "click", CART, provenance="page", click_destination=None)
    _check("click 'Checkout' button on /cart.html (unresolved) -> ALLOW", d_click.allowed, d_click.reason)
    # but the browser JS-navigated to /checkout-step-one.html; the next action THERE is blocked:
    for act, tgt in (("type", STEP1), ("extract", STEP1), ("click", STEP1)):
        d = gate.decide(m, act, tgt, provenance="agent" if act != "click" else "page")
        _check(f"{act} on /checkout-step-one under shopping -> BLOCK", not d.allowed, d.reason)

    # --- (2) /checkout-complete.html: ceiling-deny under EVERY scope -----------------------
    print("\n== acceptance 2: /checkout-complete.html — ceiling wall ==")
    for scope_name in m.menu:
        m.active = scope_name
        d = gate.decide(m, "navigate", COMPLETE, provenance="page")
        _check(f"navigate /checkout-complete under {scope_name} -> BLOCK", not d.allowed)
        _check(f"  reason is CEILING-deny under {scope_name}", "not allowed in ceiling" in d.reason)
    # no menu scope's path_allow can even name the complete path -> select_scope can't grant it
    reachable = any(gate._path_allowed("/checkout-complete.html", sc.path_allow)
                    for sc in m.menu.values())
    _check("no scope's path_allow reaches /checkout-complete (operator cannot grant)", not reachable)
    m.active = "shopping"

    # --- the sample arc, with receipts, written to a session.json --------------------------
    print("\n== sample arc (-> session.json) ==")
    out = Path(tempfile.mkdtemp()) / "session.json"
    s = Session(m, out_path=out, session_id="saucedemo-paths-demo")
    seq = {"n": 0}

    def emit(action, page_or_dest, *, current=None, dest=None, provenance="agent", label=None):
        """Record one gated action. For navigate, page_or_dest is the destination URL; for
        click/type/extract, `current` is the page URL and `dest` the click destination (if any)."""
        seq["n"] += 1
        target = current if action != "navigate" else page_or_dest
        d = gate.decide(m, action, target, provenance=provenance, click_destination=dest)
        shown = (dest or target)
        r = s.mint_receipt(action=action, target=shown, outcome=d.outcome, active_scope=m.active)
        s.record(seq["n"], action, {"url": shown}, d, r, target=shown,
                 performed={"browser": d.outcome}, label=label, active_scope=m.active)
        tag = "ceiling" if "ceiling" in d.reason else ("scope" if "not in scope" in d.reason else "")
        print(f"  #{seq['n']:>2} [{m.active:>8}] {d.outcome.upper():5} {action:8} "
              f"{gate.resolve_path(shown):28} {('('+tag+'-deny)') if tag else ''}")
        return d

    # shopping: log in, browse, add to cart, view cart — all ALLOW
    emit("navigate", LOGIN, label="open login")
    emit("type", None, current=LOGIN, label="type username")
    emit("click", None, current=LOGIN, dest=None, provenance="page", label="click LOGIN (JS)")
    emit("extract", None, current=INVENTORY, label="read inventory")
    emit("click", None, current=INVENTORY, dest=None, provenance="page", label="add backpack (JS)")
    emit("navigate", CART, label="open cart")
    emit("extract", None, current=CART, label="read cart")
    # checkout path under shopping -> BLOCK (scope-deny)
    emit("navigate", STEP1, provenance="page", label="proceed to checkout (blocked)")
    # operator steers shopping -> checkout (Spec 05), recorded as a scope_switch ALLOW receipt
    dsw = select_scope(m, "proceed to checkout", session=s, use_llm=False)
    print(f"  ↳ select_scope('proceed to checkout') -> {dsw.outcome.upper()}, active now {m.active!r}")
    _check("operator switch to checkout ALLOWED", dsw.allowed and m.active == "checkout")
    # checkout: form + overview -> ALLOW
    emit("navigate", STEP1, provenance="page", label="checkout form")
    emit("type", None, current=STEP1, label="type name/zip")
    emit("navigate", STEP2, provenance="page", label="checkout overview")
    # place the order -> ceiling wall, under the MOST permissive scope
    emit("navigate", COMPLETE, provenance="page", label="FINISH / place order (ceiling-blocked)")

    # receipts verify + hash chain intact
    effects = s.to_dict()["effects"]
    _check("every effect carries a verifying receipt", all(e["receipt_verified"] for e in effects))
    log = s.receipts.all()
    chain_ok = all((r.prev_receipt_hash == (log[i - 1].receipt_hash if i > 0 else None))
                   and s.receipts.verify(r)[0] for i, r in enumerate(log))
    _check("hash-chain over all receipts valid", chain_ok)
    # the arc shape the spec asked for
    decisions = [(e["active_scope"], e["decision"], gate.resolve_path(str(e["proposed"]["target"])))
                 for e in effects]
    _check("shopping has ALLOWs + a checkout-path BLOCK",
           any(sc == "shopping" and dec == "ALLOW" for sc, dec, _ in decisions)
           and any(sc == "shopping" and dec == "BLOCK" and p == "/checkout-step-one.html"
                   for sc, dec, p in decisions))
    _check("checkout has ALLOWs for the form path",
           any(sc == "checkout" and dec == "ALLOW" and p == "/checkout-step-one.html"
               for sc, dec, p in decisions))
    _check("/checkout-complete is BLOCKED (ceiling)",
           any(dec == "BLOCK" and p == "/checkout-complete.html" for _, dec, p in decisions))
    print(f"\n  sample session.json: {s.out_path}")

    print("\nSPEC-06 SELF-CHECK:", "PASS" if _ok else "FAIL")
    return 0 if _ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
