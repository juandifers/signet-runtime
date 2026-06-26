"""Spec 06 demo — PATH-level scoping on a single-domain app (saucedemo.com).

`python -m examples.browser_demo.run_saucedemo`

Saucedemo is one domain, so meaningful policy is about URL **paths**, not domains. This reuses the
ENTIRE Spec 02-05 run loop (live steering, panels, voice, task steer) via `run_interactive`'s
`RunConfig` — only the mandate, task, and allowlist change. The new enforcement is the gate's
path dual-check (ceiling AND active scope), exercised here:

  * scope **shopping** (default) — log in, browse `/inventory*`, add to cart, view `/cart.html`.
  * scope **checkout** — adds `/checkout-step-one.html` + `/checkout-step-two.html` (the form +
    overview). The operator switches to it LIVE (Spec 05) when the agent is blocked at checkout.
  * the **ceiling** omits `/checkout-complete.html` entirely — so PLACING the order is outside the
    ceiling and NO scope (and no operator) can grant it. That is the structural wall this spec adds.

HONESTY (the saucedemo reality, see README): the "Checkout"/"Finish" controls are JS `<button>`s,
not links, so their click destination is not statically resolvable — `allow_unresolved` lets the
click happen and the browser performs a CLIENT-SIDE navigation our `navigate` tool never sees. The
backstop is the gate's CURRENT-PAGE path check (gate.py): you may LAND on an off-scope path, but
you cannot ACT there (type/extract/click are all blocked until you're on an allowed path). So under
`shopping` the agent reaches the checkout form and then stalls (every action blocked); the operator
steers to `checkout`; and `/checkout-complete.html` stays blocked under every scope.

Credentials: saucedemo's `standard_user` / `secret_sauce` are PUBLIC, documented test credentials
for a throwaway demo site. In a real deployment a human establishes the authenticated session and
the agent does NOT enter credentials (see README) — Signet gates the agent's actions, it is not a
credential manager.
"""
from __future__ import annotations

import asyncio

from . import run_interactive
from .web_mandate import WebMandate

LOGIN_URL = "https://www.saucedemo.com/"

# Paths (saucedemo): "/" login, "/inventory.html" catalog, "/inventory-item.html?id=N" item,
# "/cart.html" cart, "/checkout-step-one.html" form, "/checkout-step-two.html" overview,
# "/checkout-complete.html" ORDER PLACED (deliberately outside the ceiling).
_CEILING_PATHS = ["/", "/inventory*", "/cart.html",
                  "/checkout-step-one.html", "/checkout-step-two.html"]   # NO complete
_SHOPPING_PATHS = ["/", "/inventory*", "/cart.html"]
_CHECKOUT_PATHS = ["/", "/inventory*", "/cart.html",
                   "/checkout-step-one.html", "/checkout-step-two.html"]


def build_mandate() -> "WebMandate":
    return (
        WebMandate("demo-agent", task_id="saucedemo-paths-001")
        .ceiling(domains=["saucedemo.com"], actions=["navigate", "click", "type", "extract"],
                 click_policy="allow_unresolved", path_allow=_CEILING_PATHS)
        # scopes use allow_unresolved too: saucedemo's add-to-cart / checkout / finish are JS
        # buttons (no static href). The path dual-check (incl. the current-page backstop) is what
        # actually contains them — not the click_policy.
        .scope("shopping", domains=["saucedemo.com"], actions=["navigate", "click", "type", "extract"],
               click_policy="allow_unresolved", path_allow=_SHOPPING_PATHS)
        .scope("checkout", domains=["saucedemo.com"], actions=["navigate", "click", "type", "extract"],
               click_policy="allow_unresolved", path_allow=_CHECKOUT_PATHS)
        .default_scope("shopping")
        .build()
    )


TASK = (
    f"You are shopping under a security mandate on the Sauce Labs demo store. Use `navigate` to "
    f"open {LOGIN_URL} . Log in with username `standard_user` and password `secret_sauce` (public "
    f"demo credentials): `type` them into the username and password fields, then `click` the LOGIN "
    f"button. You should land on the inventory page. Find the 'Sauce Labs Backpack' and `click` its "
    f"'Add to cart' button. Then `click` the shopping-cart icon to open the cart (/cart.html) and "
    f"`extract` what's in it. Next `click` 'Checkout' and `type` a first name, last name, and zip "
    f"into the form, then `click` 'Continue' to reach the overview. Finally `click` 'Finish' to "
    f"PLACE the order. IMPORTANT: if any action is BLOCKED, do NOT give up — report exactly what "
    f"was blocked and why, then try the SAME action again on your next step (a human operator may "
    f"change the active scope between your steps). When you can make no further progress, report "
    f"everything you did and everything that was blocked, then call `done`."
)

# browser-use's own belt; a superset of the gate's single domain (gate is the enforcer of record).
BROWSER_ALLOWED_DOMAINS = ["*.saucedemo.com", "https://*.saucedemo.com"]


def config() -> "run_interactive.RunConfig":
    return run_interactive.RunConfig(
        build_mandate=build_mandate, task=TASK, allowed_domains=BROWSER_ALLOWED_DOMAINS,
        start_url=LOGIN_URL, session_id="saucedemo-paths-demo",
        title="path-scoped WebMandate (saucedemo)")


def main() -> int:
    return asyncio.run(run_interactive._run(config()))


if __name__ == "__main__":
    raise SystemExit(main())
