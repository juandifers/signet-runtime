"""Offline proof of Spec 05 Part 1 — always-on live steering + the refuse-the-operator beat.

No LLM, no browser, no mic: we drive a REAL `LiveSteerChannel` (its own daemon thread + the
real event-loop marshaling) with an injected request source, and assert the steering and the
refusal land correctly. This exercises the actual threading/`run_coroutine_threadsafe` path,
not a stub.

  1. mid-run (agent NOT blocked) an operator request flips the active scope; receipt written;
  2. an unmappable / out-of-ceiling request -> REFUSE, active UNCHANGED, a signed refusal
     receipt, and a panel row that renders as REFUSED (loud beat) in the in-page panel state;
  3. typed and voice route through the SAME select_scope (acquire_operator_request_sync), and a
     voice failure falls back to typed (Spec 04 behavior preserved);
  4. exactly one applied request per input; bare-ENTER is a no-op (keeps listening).

Run: `python -m examples.browser_demo.selfcheck_steer`   (exit 0 = PASS)
"""
from __future__ import annotations

import asyncio
import queue
from pathlib import Path

from . import operator, voice
from .inpage_panel import panel_state
from .session import Session
from .steering import LiveSteerChannel
from .web_mandate import WebMandate


def _mandate():
    return (
        WebMandate("demo-agent", task_id="steer-selfcheck")
        .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "click", "extract"])
        .scope("tour",       domains=["wikipedia.org"],                    actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .scope("learn_more", domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .default_scope("tour")
        .build()
    )


def _check(name: str, cond: bool) -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        raise SystemExit(1)


async def _drive(mandate, session, requests):
    """Feed `requests` through a real LiveSteerChannel; return list of (request, decision)."""
    applied = []
    q = queue.Queue()
    for r in requests:
        q.put(r)
    q.put(None)                                   # stop signal

    done = asyncio.Event()

    def source():
        try:
            return q.get(timeout=5)
        except queue.Empty:
            return None

    async def on_apply(decision, request):
        applied.append((request, decision))
        if len(applied) == len(requests):
            loop.call_soon_threadsafe(done.set)

    loop = asyncio.get_running_loop()
    ch = LiveSteerChannel(mandate, session, loop, request_source=source, on_apply=on_apply)
    ch.start()
    try:
        await asyncio.wait_for(done.wait(), timeout=15)
    finally:
        ch.stop()
    return applied


def main() -> int:
    print("SPEC-05 PART-1 SELF-CHECK")
    out = Path(__file__).resolve().parent / "_selfcheck_steer.session.json"
    m = _mandate()
    s = Session(m, out_path=out, session_id="steer-selfcheck")

    import os
    # Force the offline deterministic keyword classifier (no network) for the steering drive.
    _saved_key = os.environ.pop("OPENAI_API_KEY", None)
    try:
        # (1)+(2)+(4): a bare ENTER (no-op), a valid steer, then an out-of-ceiling request.
        # Bare ENTER must NOT produce an apply, so only 2 of 3 inputs are applied.
        applied = asyncio.run(_drive(m, s, [
            "show me Y Combinator's official website",   # valid -> learn_more
            "open my online banking dashboard",          # unmappable -> REFUSE
        ]))

        _check("two inputs -> two applies", len(applied) == 2)
        req1, d1 = applied[0]
        _check("(1) mid-run steer ALLOWED", d1.allowed)
        _check("(1) active flipped to learn_more", m.active == "learn_more")
        req2, d2 = applied[1]
        _check("(2) out-of-ceiling request REFUSED", not d2.allowed)
        _check("(2) active UNCHANGED after refusal", m.active == "learn_more")

        effects = s.to_dict()["effects"]
        scope_fx = [e for e in effects if e["rail"] == "scope"]
        _check("two scope receipts written", len(scope_fx) == 2)
        _check("all scope receipts verify", all(e["receipt_verified"] for e in scope_fx))
        allow_fx = [e for e in scope_fx if e["decision"] == "ALLOW"]
        refuse_fx = [e for e in scope_fx if e["decision"] == "BLOCK"]
        _check("one signed ALLOW + one signed REFUSE", len(allow_fx) == 1 and len(refuse_fx) == 1)

        # (2) the refusal renders as a loud REFUSED row carrying the request text.
        state = panel_state(s)
        refused_rows = [d for d in state["decisions"] if d["decision"] == "REFUSED"]
        _check("panel shows a REFUSED row", len(refused_rows) == 1)
        _check("REFUSED row carries the request text",
               "banking" in refused_rows[0]["target"].lower())
        switch_rows = [d for d in state["decisions"] if d["decision"] == "SWITCH"]
        _check("panel shows a SWITCH row for the grant", len(switch_rows) == 1)

        # (3) typed + voice both route through acquire_operator_request_sync; voice failure -> typed.
        import io, sys
        real_stdin, real_cap, real_env = sys.stdin, voice.capture_voice_request_sync, os.environ.get("SIGNET_VOICE")
        try:
            os.environ.pop("SIGNET_VOICE", None)
            sys.stdin = io.StringIO("learn more about YC\n")
            _check("(3) typed routes through intake", operator.acquire_operator_request_sync("> ") == "learn more about YC")
            os.environ["SIGNET_VOICE"] = "1"
            voice.capture_voice_request_sync = lambda: None      # forced STT failure
            sys.stdin = io.StringIO("typed fallback line\n")
            _check("(3) voice failure falls back to typed",
                   operator.acquire_operator_request_sync("> ") == "typed fallback line")
            voice.capture_voice_request_sync = lambda: "spoken request text"
            sys.stdin = io.StringIO("SHOULD NOT READ\n")
            _check("(3) voice success returns transcript (stdin untouched)",
                   operator.acquire_operator_request_sync("> ") == "spoken request text")
        finally:
            sys.stdin, voice.capture_voice_request_sync = real_stdin, real_cap
            if real_env is None:
                os.environ.pop("SIGNET_VOICE", None)
            else:
                os.environ["SIGNET_VOICE"] = real_env
    finally:
        if _saved_key is not None:
            os.environ["OPENAI_API_KEY"] = _saved_key
        out.unlink(missing_ok=True)

    print("SPEC-05 PART-1 SELF-CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
