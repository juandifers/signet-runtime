"""Spec 06 demo — PATH-level scoping on a single-domain app (saucedemo.com).

`python -m examples.browser_demo.run_saucedemo`

Saucedemo is one domain, so meaningful policy is about URL **paths**, not domains. This reuses the
ENTIRE Spec 02-05 run loop (live steering, panels, voice, task steer) via `run_interactive`'s
`RunConfig` — only the mandate, task, and allowlist change. The new enforcement is the gate's
path dual-check (ceiling AND active scope), exercised here:

  * scope **look** — presentation mode: navigate + extract ONLY (no click/type). It can browse and
    read the catalog and the cart, but cannot touch anything — not even log in. A read-only lane
    the operator can switch DOWN to ("just looking").
  * scope **shop** (default) — full interaction: log in, add to cart, view `/cart.html`; the
    checkout paths are out of the lane.
  * scope **checkout** — shop + `/checkout-step-one.html` + `/checkout-step-two.html` (the form +
    overview). The operator switches UP to it LIVE (Spec 05) when the agent is blocked at checkout.
  * the **ceiling** omits `/checkout-complete.html` entirely — so PLACING the order is outside the
    ceiling and NO scope (and no operator) can grant it. That is the structural wall this spec adds.

HONESTY (the saucedemo reality, see README): the "Checkout"/"Finish" controls are JS `<button>`s,
not links, so their click destination is not statically resolvable — `allow_unresolved` lets the
click happen and the browser performs a CLIENT-SIDE navigation our `navigate` tool never sees. The
backstop is the gate's CURRENT-PAGE path check (gate.py): you may LAND on an off-scope path, but
you cannot ACT there (type/extract/click are all blocked until you're on an allowed path). So under
`shop` the agent reaches the checkout form and then stalls (every action blocked); the operator
steers to `checkout`; and `/checkout-complete.html` stays blocked under every scope.

Credentials: saucedemo's `standard_user` / `secret_sauce` are PUBLIC, documented test credentials
for a throwaway demo site. In a real deployment a human establishes the authenticated session and
the agent does NOT enter credentials (see README) — Signet gates the agent's actions, it is not a
credential manager.
"""
from __future__ import annotations

import asyncio
import os

from . import run_interactive
from .web_mandate import WebMandate

LOGIN_URL = "https://www.saucedemo.com/"

# Paths (saucedemo): "/" login, "/inventory.html" catalog, "/inventory-item.html?id=N" item,
# "/cart.html" cart, "/checkout-step-one.html" form, "/checkout-step-two.html" overview,
# "/checkout-complete.html" ORDER PLACED (deliberately outside the ceiling).
_CEILING_PATHS = ["/", "/inventory*", "/cart.html",
                  "/checkout-step-one.html", "/checkout-step-two.html"]   # THE WALL — no complete
_LOOK_PATHS = ["/", "/inventory*", "/cart.html"]                          # browse + read the cart
_SHOP_PATHS = ["/", "/inventory*", "/cart.html"]                          # log in, add, view cart
_CHECKOUT_PATHS = ["/", "/inventory*", "/cart.html",
                   "/checkout-step-one.html", "/checkout-step-two.html"]  # + the checkout form


def build_mandate() -> "WebMandate":
    return (
        WebMandate("demo-agent", task_id="saucedemo-001")
        # THE WALL — the max authority that can ever apply. NO /checkout-complete: placing the
        # order is outside the ceiling, so no scope (and no operator) can ever grant it.
        .ceiling(domains=["saucedemo.com"], actions=["navigate", "click", "type", "extract"],
                 path_allow=_CEILING_PATHS)
        # LOOK — presentation mode: navigate + extract ONLY (no click/type). It can browse and
        # read (incl. the cart) but cannot touch anything — not even log in.
        .scope("look",     domains=["saucedemo.com"], actions=["navigate", "extract"],
               click_policy="in_domain_only", path_allow=_LOOK_PATHS)
        # SHOP (default) — log in, add to cart, view cart; checkout paths are out of the lane.
        # click_policy is allow_unresolved (NOT in_domain_only as one might write): saucedemo's
        # login / add-to-cart / checkout are JS buttons with no static href, and in_domain_only
        # would block them — login included. The PATH dual-check + the current-page backstop is
        # the real containment here, not the click_policy.
        .scope("shop",     domains=["saucedemo.com"], actions=["navigate", "click", "type", "extract"],
               click_policy="allow_unresolved", path_allow=_SHOP_PATHS)
        # CHECKOUT — walk the checkout form + overview; still cannot place the order (ceiling wall).
        .scope("checkout", domains=["saucedemo.com"], actions=["navigate", "click", "type", "extract"],
               click_policy="allow_unresolved", path_allow=_CHECKOUT_PATHS)
        .default_scope("shop")   # default allows login (type + click)
        .build()
    )


TASK = (
    f"You are a shopping assistant on the Sauce Labs demo store, taking LIVE direction from a "
    f"human operator. Use `navigate` to open {LOGIN_URL} and log in with username `standard_user` "
    f"and password `secret_sauce` (public demo credentials): `type` them into the username and "
    f"password fields, then `click` the LOGIN button. You land on the inventory page. To begin, "
    f"`click` the 'Sauce Labs Backpack' 'Add to cart' button, then await the operator's direction. "
    f"FOLLOW THE OPERATOR'S ITEM INSTRUCTIONS: when told to ADD an item (e.g. 'add the bike "
    f"light'), `click` that product's 'Add to cart' button; when told to REMOVE one (e.g. 'remove "
    f"the backpack'), `click` its 'Remove' button — on the inventory page or inside the cart. You "
    f"can `click` the cart icon to open the cart (/cart.html) and `extract` to read its contents. "
    f"Do NOT proceed to checkout on your own — only when the operator tells you to; then `click` "
    f"'Checkout', `type` a first name, last name, and zip, and `click` 'Continue'. IMPORTANT: if "
    f"any action is BLOCKED, do NOT give up — report exactly what was blocked and why, then retry "
    f"the SAME action on a later step (the operator may change the active scope between your "
    f"steps). When the operator says you are finished, `extract` the cart, report it, and call "
    f"`done`."
)

# browser-use's own belt; a superset of the gate's single domain (gate is the enforcer of record).
BROWSER_ALLOWED_DOMAINS = ["*.saucedemo.com", "https://*.saucedemo.com"]

# When the operator steers INTO a lane, also tell the agent to USE it — a scope switch unlocks
# authority but is silent to the agent, so without this it just sits and re-extracts. "go to
# checkout" should SHOW THE CART and walk the form; "let's shop" should return to the catalog.
_SCOPE_GOALS = {
    "checkout": ("The operator has opened the CHECKOUT lane. First SHOW THE CART: click the cart "
                 "icon to go to /cart.html and `extract` to report what's in it. Then proceed to "
                 "checkout — click 'Checkout', and on the form `type` a first name, last name, and "
                 "zip, then click 'Continue' to reach the overview. Do NOT click 'Finish'."),
    "shop":     ("The operator is back in the SHOP lane. Return to the inventory page "
                 "(/inventory.html) and continue adding or removing items as directed."),
}


def config() -> "run_interactive.RunConfig":
    return run_interactive.RunConfig(
        build_mandate=build_mandate, task=TASK, allowed_domains=BROWSER_ALLOWED_DOMAINS,
        start_url=LOGIN_URL, session_id="saucedemo-paths-demo",
        title="path-scoped WebMandate (saucedemo)", scope_goals=_SCOPE_GOALS)


def main() -> int:
    # Item shopping IS this demo, so default task steering ON (so "add the bike light" works
    # without a flag). Set SIGNET_TASK_STEER=0 to turn item steering off and keep only lane steering.
    os.environ.setdefault("SIGNET_TASK_STEER", "1")
    return asyncio.run(run_interactive._run(config()))


if __name__ == "__main__":
    raise SystemExit(main())
