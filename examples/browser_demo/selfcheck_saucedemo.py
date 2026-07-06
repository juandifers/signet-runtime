"""Offline acceptance harness for Spec 06 — PATH-level scoping.

`python -m examples.browser_demo.selfcheck_saucedemo`   (exit 0 = PASS)

No browser, no LLM (`select_scope(use_llm=False)`). Proves the dual-check (ceiling AND active
scope) and the ceiling-deny vs scope-deny distinction on the real saucedemo mandate, and emits a
sample `session.json` for the full arc (shop ALLOWs → checkout-path BLOCK under shop →
scope_switch to checkout → checkout-path ALLOWs → /checkout-complete BLOCK as a ceiling-deny).

  1. under `shop`, navigate/click whose path is /checkout-step-one.html -> BLOCK (scope-deny);
     under `checkout` the same -> ALLOW.
  2. /checkout-complete.html -> BLOCK under EVERY scope (ceiling-deny); no menu scope's path_allow
     can reach it, so select_scope cannot grant it.
  3. path globs: /inventory.html and /inventory-item.html?id=4 are allowed by /inventory*; query
     strings / fragments don't break path extraction.
  4. ceiling-deny ("not allowed in ceiling") is surfaced distinctly from scope-deny ("not in
     scope 'shop'") in the reason.
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
    m = build_mandate()                                  # active = shop

    # --- (3) path extraction: query/fragment dropped, '' -> '/' ---------------------------
    print("\n== path extraction ==")
    _check("/inventory.html", gate.resolve_path(INVENTORY) == "/inventory.html")
    _check("/inventory-item.html?id=4 -> path drops query",
           gate.resolve_path(ITEM) == "/inventory-item.html")
    _check("bare host -> '/'", gate.resolve_path(BASE) == "/")
    _check("fragment dropped", gate.resolve_path(CART + "#summary") == "/cart.html")

    # --- (3) /inventory* glob matches catalog + item pages under shop ------------------
    print("\n== /inventory* glob (scope=shop) ==")
    for label, url in (("/inventory.html", INVENTORY), ("/inventory-item.html?id=4", ITEM)):
        d = gate.decide(m, "navigate", url, provenance="page")
        _check(f"navigate {label} ALLOW", d.allowed, d.reason)

    # --- (1) checkout path: BLOCK under shop, ALLOW under checkout ---------------------
    print("\n== acceptance 1: /checkout-step-one.html — scope-gated ==")
    m.active = "shop"
    d_sh = gate.decide(m, "navigate", STEP1, provenance="page")
    _check("navigate /checkout-step-one under shop -> BLOCK", not d_sh.allowed, d_sh.reason)
    _check("reason is SCOPE-deny (operator can grant)", "not in scope 'shop'" in d_sh.reason)
    m.active = "checkout"
    d_co = gate.decide(m, "navigate", STEP1, provenance="page")
    _check("navigate /checkout-step-one under checkout -> ALLOW", d_co.allowed, d_co.reason)
    m.active = "shop"

    # look = presentation mode: navigate/extract are allowed on its paths (it can READ the cart),
    # but click/type are not in the lane's actions at all — it can't touch anything, login included.
    print("\n== look is read-only (action-gated) ==")
    m.active = "look"
    _check("navigate /cart.html under look -> ALLOW (look can read the cart)",
           gate.decide(m, "navigate", CART, provenance="page").allowed)
    _check("extract /cart.html under look -> ALLOW",
           gate.decide(m, "extract", CART, provenance="agent").allowed)
    d_type = gate.decide(m, "type", LOGIN, provenance="agent")
    _check("type under look -> BLOCK (no type action — can't even log in)", not d_type.allowed, d_type.reason)
    _check("reason is ACTION-deny under look", "not in scope 'look' actions" in d_type.reason)
    _check("click under look -> BLOCK (no click action)",
           not gate.decide(m, "click", INVENTORY, provenance="page", click_destination=None).allowed)
    m.active = "shop"
    _check("type under shop -> ALLOW (login works in the default lane)",
           gate.decide(m, "type", LOGIN, provenance="agent").allowed)

    # --- (5) current-page backstop: a JS click lands off-path; next action there is blocked
    print("\n== acceptance 5: current-page backstop (JS nav lands off-scope) ==")
    # the click itself, on /cart.html with an unresolved (button) destination, is allowed:
    d_click = gate.decide(m, "click", CART, provenance="page", click_destination=None)
    _check("click 'Checkout' button on /cart.html (unresolved) -> ALLOW", d_click.allowed, d_click.reason)
    # but the browser JS-navigated to /checkout-step-one.html; the next action THERE is blocked:
    for act, tgt in (("type", STEP1), ("extract", STEP1), ("click", STEP1)):
        d = gate.decide(m, act, tgt, provenance="agent" if act != "click" else "page")
        _check(f"{act} on /checkout-step-one under shop -> BLOCK", not d.allowed, d.reason)

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
    m.active = "shop"

    # --- the demo cheat sheet: each spoken row maps cleanly through the planner ------------
    # Deterministic (keyword planner, use_llm=False) — the LIVE demo uses the LLM, but this is
    # the safety net and proves the menu names ARE the trigger words. The fourth row is the
    # money shot: an order/purchase phrase maps to NOTHING -> REFUSED, never a fake ALLOW.
    print("\n== cheat sheet (planner mapping) ==")
    cm = build_mandate()                                 # fresh mandate; active = shop
    GRANTS = {
        "look":     ["i'm just looking", "let me look around", "just browsing, look only"],
        "shop":     ["let's shop", "i want to shop", "back to shopping"],
        "checkout": ["go to checkout", "checkout now", "proceed to checkout"],
    }
    for want, phrases in GRANTS.items():
        for p in phrases:
            cm.active = "shop"                           # reset so each row is judged from default
            d = select_scope(cm, p, session=None, use_llm=False)
            _check(f"{p!r} -> {want}", d.allowed and cm.active == want,
                   f"got {cm.active!r} ({d.outcome})")
    REFUSE = ["place the order", "pay now", "buy it", "finish the order",
              "complete my purchase", "submit the order"]
    for p in REFUSE:
        cm.active = "shop"
        d = select_scope(cm, p, session=None, use_llm=False)
        _check(f"{p!r} -> REFUSED (no scope), active unchanged",
               (not d.allowed) and cm.active == "shop", f"got {cm.active!r} ({d.outcome})")

    # --- item steering: cart verbs are TASK steers (intent), not authority ----------------
    # "add the bike light" / "remove the backpack" route to the agent's goal (gated); scope words
    # and order/pay phrasing do NOT — order phrasing still falls through to the REFUSED beat. The
    # authority to add/remove already exists: it's a click the shop lane grants on inventory + cart.
    print("\n== item steering (task-steer routing) ==")
    import os
    from . import task_steer
    _saved = os.environ.get("SIGNET_TASK_STEER")
    os.environ["SIGNET_TASK_STEER"] = "1"
    try:
        _check("'add the bike light' -> task goal (whole phrase)",
               task_steer.parse_task_request("add the bike light") == "add the bike light")
        _check("'remove the backpack' -> task goal",
               task_steer.parse_task_request("remove the backpack") == "remove the backpack")
        _check("'take the onesie out of the cart' -> task goal",
               task_steer.parse_task_request("take the onesie out of the cart") == "take the onesie out of the cart")
        _check("'go to checkout' is NOT a task steer (-> scope steer)",
               task_steer.parse_task_request("go to checkout") is None)
        _check("'place the order' is NOT a task steer (-> REFUSED beat survives)",
               task_steer.parse_task_request("place the order") is None)
    finally:
        if _saved is None:
            os.environ.pop("SIGNET_TASK_STEER", None)
        else:
            os.environ["SIGNET_TASK_STEER"] = _saved
    # authority already present: add/remove is a click the shop lane grants on inventory + cart.
    cm.active = "shop"
    _check("click 'Add to cart' on /inventory.html under shop -> ALLOW",
           gate.decide(cm, "click", INVENTORY, provenance="page", click_destination=None).allowed)
    _check("click 'Remove' in /cart.html under shop -> ALLOW",
           gate.decide(cm, "click", CART, provenance="page", click_destination=None).allowed)

    # scope-switch nudge: 'go to checkout' unlocks the lane AND directs the agent to SHOW THE CART.
    print("\n== scope nudge (switch -> use the lane) ==")
    from .run_saucedemo import config as _saucedemo_config
    goals = _saucedemo_config().scope_goals or {}
    _check("checkout switch carries a nudge", "checkout" in goals)
    _check("the checkout nudge opens the cart", "cart" in goals.get("checkout", "").lower())
    _check("shop switch returns to the inventory", "inventory" in goals.get("shop", "").lower())

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

    # shop: log in, browse, add to cart, view cart — all ALLOW
    emit("navigate", LOGIN, label="open login")
    emit("type", None, current=LOGIN, label="type username")
    emit("click", None, current=LOGIN, dest=None, provenance="page", label="click LOGIN (JS)")
    emit("extract", None, current=INVENTORY, label="read inventory")
    emit("click", None, current=INVENTORY, dest=None, provenance="page", label="add backpack (JS)")
    emit("navigate", CART, label="open cart")
    emit("extract", None, current=CART, label="read cart")
    # checkout path under shop -> BLOCK (scope-deny)
    emit("navigate", STEP1, provenance="page", label="proceed to checkout (blocked)")
    # operator steers shop -> checkout (Spec 05), recorded as a scope_switch ALLOW receipt
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
    _check("shop has ALLOWs + a checkout-path BLOCK",
           any(sc == "shop" and dec == "ALLOW" for sc, dec, _ in decisions)
           and any(sc == "shop" and dec == "BLOCK" and p == "/checkout-step-one.html"
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
