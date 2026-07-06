"""Offline proof of Spec 05 Part 2 — task steering changes INTENT, never AUTHORITY.

No LLM, no browser. The live agent arc (a real injected goal changing what the agent attempts)
needs a network page-load and is eyeballed on the user's Mac; what is PROVABLE offline — and is
the actual safety claim — is verified here:

  1. parse_task_request: OFF -> None; ON -> only an explicit prefix routes to a task steer,
     an ordinary scope phrase does not (so the two channels never collide);
  2. THE INVARIANT: whatever goal is injected, every resulting action is still gated by the
     active scope — an out-of-ceiling action is BLOCKED with a verifying receipt, an in-ceiling
     action is ALLOWED with one. The gate is unchanged, so authority cannot widen;
  3. inject_task uses the library hook and is fully guarded — a raising/unsupported agent
     yields False, never an exception (flag-off / failure can't crash the run).

Run: `python -m examples.browser_demo.selfcheck_task_steer`   (exit 0 = PASS)
"""
from __future__ import annotations

import os
from pathlib import Path

from . import task_steer
from .gate import decide
from .session import Session
from .web_mandate import WebMandate

GOOGLE = "https://www.google.com"                       # out of ceiling
YC = "https://www.ycombinator.com/"                     # in ceiling under learn_more


def _mandate():
    return (
        WebMandate("demo-agent", task_id="task-steer-selfcheck")
        .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "click", "extract"])
        .scope("tour",       domains=["wikipedia.org"],                    actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .scope("learn_more", domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .default_scope("learn_more")
        .build()
    )


def _check(name: str, cond: bool) -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        raise SystemExit(1)


class _FakeAgent:
    def __init__(self): self.added = []
    def add_new_task(self, g): self.added.append(g)


class _BoomAgent:
    def add_new_task(self, g): raise RuntimeError("unsupported")


def main() -> int:
    print("SPEC-05 PART-2 SELF-CHECK")
    out = Path(__file__).resolve().parent / "_selfcheck_task_steer.session.json"
    saved = os.environ.get("SIGNET_TASK_STEER")
    try:
        # (1) routing
        os.environ.pop("SIGNET_TASK_STEER", None)
        _check("disabled -> parse returns None", task_steer.parse_task_request("task: do x") is None)
        os.environ["SIGNET_TASK_STEER"] = "1"
        _check("enabled + 'task:' prefix -> goal extracted",
               task_steer.parse_task_request("task: go to the admin panel") == "go to the admin panel")
        _check("enabled + 'goal:' prefix -> goal extracted",
               task_steer.parse_task_request("goal: open pricing") == "open pricing")
        _check("ordinary scope phrase is NOT a task steer (-> policy steer)",
               task_steer.parse_task_request("show me Y Combinator's site") is None)

        # (2) THE INVARIANT — gate unchanged, so any injected goal stays clamped to active scope.
        m = _mandate()                                 # active = learn_more
        s = Session(m, out_path=out, session_id="task-steer-selfcheck")

        # Operator injects "go to google and delete the account" — the agent would attempt these:
        d_evil = decide(m, "navigate", GOOGLE, provenance="agent")
        r_evil = s.mint_receipt(action="navigate", target=GOOGLE, outcome=d_evil.outcome, active_scope=m.active)
        s.record(1, "navigate", {"url": GOOGLE}, d_evil, r_evil, target=GOOGLE,
                 performed={"blocked": True}, active_scope=m.active)
        _check("injected out-of-ceiling action BLOCKED", not d_evil.allowed)
        _check("BLOCK receipt verifies", s.to_dict()["effects"][-1]["receipt_verified"])

        d_ok = decide(m, "navigate", YC, provenance="agent")
        r_ok = s.mint_receipt(action="navigate", target=YC, outcome=d_ok.outcome, active_scope=m.active)
        s.record(2, "navigate", {"url": YC}, d_ok, r_ok, target=YC,
                 performed={"ok": True}, active_scope=m.active)
        _check("injected in-ceiling action ALLOWED (gated, proceeds)", d_ok.allowed)
        _check("ALLOW receipt verifies", s.to_dict()["effects"][-1]["receipt_verified"])
        _check("authority unchanged: active scope still learn_more", m.active == "learn_more")

        # (3) inject_task uses the library hook and is fully guarded.
        fake = _FakeAgent()
        _check("inject_task success -> True + hook called",
               task_steer.inject_task(fake, "open pricing") and fake.added == ["open pricing"])
        _check("inject_task on raising agent -> False, no exception",
               task_steer.inject_task(_BoomAgent(), "x") is False)
    finally:
        if saved is None:
            os.environ.pop("SIGNET_TASK_STEER", None)
        else:
            os.environ["SIGNET_TASK_STEER"] = saved
        out.unlink(missing_ok=True)

    print("SPEC-05 PART-2 SELF-CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
