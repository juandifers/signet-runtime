# Runbook — Acme Shop (guarded browser agent)

> One agent, a frozen ceiling, a live-steerable menu of lanes. The operator changes **which lane**
> is active (authority, clamped to the ceiling); the agent decides **what to attempt** (intent,
> always gated). The irreversible step — placing the order — is **outside the ceiling**, so no lane,
> no operator, and no injected goal can reach it.

> *Illustrative:* `shop.example.com` is the docs-reserved domain; `/products`, `/cart`, `/checkout`
> are conventional **assumed** paths. Verify them against the real site before presenting.

## Lanes (one ceiling, default-deny menu)

The ceiling allows `/`, `/products*`, `/cart`, `/checkout` — **omitting `/order-complete`**, so
*placing the order* is structurally impossible.

| lane | actions · paths | what it unlocks |
|------|-----------------|-----------------|
| `browse` | navigate/extract · `/`, `/products*`, `/cart` | **read-only** — browse + read the cart; can't click/type |
| `shop` *(default)* | + click/type · `/`, `/products*`, `/cart` | add/remove items, view the cart |
| `checkout` | + `/checkout` | the shipping form (still can't place the order) |

`shop` is the default (so the first steps — browse + add to cart — are possible). `browse` is gated
by **actions** (read-only); the step up to `checkout` is gated by **paths**.

## Voice / type cheat-sheet

The menu names *are* the trigger words (an LLM planner maps free text to one menu key; a
deterministic keyword matcher is the offline net). Say it in this terminal (or the operator console
with `SIGNET_STEER_IPC=1`).

| say | → | result |
|-----|---|--------|
| "just looking" / "browse around" | `browse` | read-only — can't click/type |
| "let's shop" / "back to shopping" | `shop` | interaction restored; returns to the catalog |
| "go to checkout" / "proceed to checkout" | `checkout` | shipping form unlocked; agent opens cart + fills the form |
| "place the order" / "pay" / "confirm" / "finish" | **REFUSED** | matched no lane — outside the menu/ceiling (loud banner + signed refusal receipt) |

### Item steering — tell it which items (intent, not authority)

While in `shop` you direct the cart by voice. **Not a policy change:** `shop` already authorizes
add/remove (a `click` on `/products*` or `/cart`). Choosing *which* items is **intent**, so it
routes through task steering (`SIGNET_TASK_STEER=1`, defaulted on) — natural cart verbs (`add` /
`remove` / `put` / `take` / `drop` / `delete`) become the agent's goal; every resulting click is
still gated by `shop`. "place the order" carries no cart verb, so it can't be injected as a task and
stays REFUSED.

## Run of show (beat by beat)

```bash
SIGNET_VOICE=1 python -m examples.browser_demo.run_acmeshop   # voice + item steering (default on)
python -m examples.browser_demo.run_acmeshop                  # typed steering
python -m examples.browser_demo.selfcheck_acmeshop            # offline proof (no LLM/browser)
```

1. **Boot.** Sidebar opens showing the frozen ceiling + lane menu (the wall is visible: no
   `/order-complete`). Agent starts in `shop` and reads the catalog.
2. **Work the default lane.** "add the blue mug" / "remove the kettle" — the agent clicks the item's
   add/remove control; each click is gated and receipted.
3. **The wall (refuse the agent).** If the agent ever tries `/order-complete`, it's blocked under
   every lane (ceiling-deny) with a receipt. This is the "no operator can grant it" beat.
4. **Grant a lane (steer up).** Say "go to checkout" → switches to `checkout`; `/checkout` (path-
   blocked under `shop`) now passes (no restart — the gate re-reads the active lane) and the agent
   opens the cart + fills the shipping form.
5. **Refuse the operator.** Say "place the order" → ⛔ REFUSED banner + receipt; active lane
   unchanged. Selecting a lane can never authorize placing the order.
6. **Receipts.** Every decision (allow / block / scope-switch / refusal) prints with a signed,
   verified receipt id and is written to `session.json` (rendered live in the sidebar).

> **Credentials:** the agent does **not** enter real credentials. In production a **human
> establishes the authenticated session**; Signet gates the agent's *actions*, it is not a
> credential manager.

## Honesty (what fought the library)

- The browser gate is **tier-0 / advisory** — in-process, not the kernel/broker enforcement
  boundary. Right shape (default-deny, frozen ceiling, signed receipts); a determined in-process
  bypass is out of scope for this layer.
- `shop`/`checkout` use `click_policy=allow_unresolved` because store buttons are JS `<button>`s
  with no static href — the click *lands*, and the **current-page path check** is the backstop (you
  may land off-path but can't **act** there). `browse` uses `in_domain_only`.
- The live page-loads need network DNS; `selfcheck_acmeshop.py` proves the structural arc offline —
  eyeball the live run on a networked machine.
