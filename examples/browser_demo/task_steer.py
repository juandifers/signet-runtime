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

A request is a TASK steer only if it carries an explicit prefix (`task:` / `goal:` / `do:`);
everything else is a POLICY steer through `select_scope`. This keeps the two channels
unambiguous over one input.
"""
from __future__ import annotations

import os
from typing import Optional

_PREFIXES = ("task:", "goal:", "do:", "now ")


def enabled() -> bool:
    return bool(os.environ.get("SIGNET_TASK_STEER"))


def parse_task_request(request: str) -> Optional[str]:
    """Return the goal text if `request` is an explicit task steer, else None (-> policy steer).

    Only an explicit prefix routes to task steering, so an ordinary scope phrase like "show me
    YC" is never mistaken for a goal injection. Returns None when task steering is disabled."""
    if not enabled():
        return None
    low = request.strip().lower()
    for p in _PREFIXES:
        if low.startswith(p):
            goal = request.strip()[len(p):].strip()
            return goal or None
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
