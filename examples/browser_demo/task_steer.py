"""Task steering (Spec 05 Part 2, OPTIONAL) — the operator redirects the agent's GOAL mid-run.

Flag-gated (`SIGNET_TASK_STEER=1`), OFF by default. This is the riskier, library-dependent
half, kept strictly separate from policy steering (Part 1):

  POLICY steering changes WHICH pre-authorized lane is active — clamped to the ceiling, safe no
  matter what is said. TASK steering changes WHAT the agent is trying to do — it is UNTRUSTED
  INSTRUCTION. The agent may attempt the new goal, but every resulting action is still gated by
  `mandate.active`. Task steering changes INTENT, never AUTHORITY. That is the whole point: an
  operator who says "go to the admin panel and delete the account" only changes what the agent
  *attempts* — the gate BLOCKS the off-ceiling action on screen, with a receipt, regardless.

MECHANISM: browser-use 0.13.1's intended follow-up hook, `Agent.add_new_task(goal)`, which
appends the new instruction to the agent's message context (and keeps the same task_id). We
call it ONLY at a step boundary (from `on_step_start`), never mid-step, and read the source
confirmed `run()` re-reads `self.eventbus` each use so the hook's eventbus refresh is tolerable
mid-run. Every call is guarded — a failure prints and is skipped; it can never crash the run.

A request routes to a TASK steer in two ways: an explicit prefix (`task:` / `goal:` / `do:` /
`now `), OR a natural cart-management verb (`add` / `remove` / `put` / `take` / …) — the latter so
an operator can shop by voice ("add the bike light", "remove the backpack") without a clunky
prefix. Everything else is a POLICY steer through `select_scope`. This keeps the channels
unambiguous over one input — and crucially, completion phrasing (place / order / pay / buy /
finish) carries NO cart verb, so it falls through to `select_scope` and is REFUSED: choosing
items is intent the operator may inject, but *completing a purchase* is never a task — the
authority to do it does not exist in the menu/ceiling.
"""
from __future__ import annotations

import os
from typing import Optional

_PREFIXES = ("task:", "goal:", "do:", "now ")
# Natural cart-management verbs for item shopping (saucedemo). A spoken "add the bike light" /
# "take the onesie out of the cart" is INTENT (which items), not new authority — the shop lane
# already grants add/remove (a click on /inventory* or /cart.html), and the gate still decides
# every resulting action. We deliberately omit place/order/pay/buy/finish: they carry no cart
# verb, so they stay POLICY steers and get REFUSED (completing a purchase is not an injectable task).
_CART_VERBS = ("add ", "remove ", "put ", "take ", "drop ", "delete ")


def enabled() -> bool:
    return bool(os.environ.get("SIGNET_TASK_STEER"))


def parse_task_request(request: str) -> Optional[str]:
    """Return the goal text if `request` is a task steer, else None (-> policy steer).

    Two routes: an explicit prefix (the goal is what FOLLOWS it) or a natural cart verb (the WHOLE
    phrase is the goal, e.g. "add the bike light"). An ordinary scope phrase ("go to checkout") and
    completion phrasing ("place the order") match neither, so they fall through to `select_scope`.
    Returns None when task steering is disabled."""
    if not enabled():
        return None
    text = request.strip()
    low = text.lower()
    for p in _PREFIXES:                  # explicit prefix -> the goal is what follows it
        if low.startswith(p):
            return text[len(p):].strip() or None
    for v in _CART_VERBS:                # natural cart instruction -> the whole phrase IS the goal
        if low.startswith(v):
            return text or None
    return None


def inject_task(agent, goal: str) -> bool:
    """Append a new goal to a live agent via the library's follow-up hook. Returns True on
    success. Fully guarded: any failure returns False without raising, so an unsupported library
    version or a transient error degrades to 'goal not injected' rather than crashing the run."""
    try:
        agent.add_new_task(goal)
        return True
    except Exception as e:
        print(f"[task-steer] could not inject goal ({e}); agent continues its current task.")
        return False
