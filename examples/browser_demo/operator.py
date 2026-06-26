"""Operator intake — the human channel into `select_scope` (Spec 04 Part 1).

Spec 02 fired the scope switch from an `on_step_start` hook (hands-free). Part 1
replaces that with a REAL operator: when the agent is blocked, the run halts
between steps and a person types a scope request, which is fed to the unchanged
`select_scope`. Voice (Part 3) is a SECOND front-end that lands on this same
intake — never a separate path.

WHY THIS IS SAFE: nothing here can exceed the ceiling. The operator only supplies
free-text *request*; `select_scope` still maps it (untrusted planner) to a frozen
menu key and the validated `mandate.active` setter clamps the result ⊆ ceiling.
The operator cannot author or widen a scope — only pick a pre-authorized one.

WHY THE AWAITED HOOK (not `agent.pause()`): browser-use checks `state.paused` at
the TOP of the step loop, BEFORE `on_step_start` runs, so a `pause()` issued from
a hook only takes effect one step late. `await on_step_start(self)` is itself the
between-steps barrier — blocking on stdin inside it halts the loop exactly where
we want, with no flag-timing race. We read stdin via `run_in_executor` so the
asyncio loop (browser event bus) stays alive while we wait for the human.
"""
from __future__ import annotations

import asyncio
import sys


async def read_operator_request(prompt: str) -> str:
    """Print `prompt`, read ONE line from stdin off the event loop, return it stripped.

    A bare ENTER (empty line) returns "" — the caller treats that as an explicit
    deny (the agent stays blocked). EOF (stdin closed, e.g. non-interactive) also
    returns "" so the run degrades to "blocked" rather than hanging forever.
    """
    print(prompt, end="", flush=True)
    loop = asyncio.get_event_loop()
    try:
        line = await loop.run_in_executor(None, sys.stdin.readline)
    except Exception:
        return ""
    return (line or "").strip()
