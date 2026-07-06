"""Offline proof of Spec 04 Part 3 — voice intake routing + the mandatory typed fallback.

No real microphone, no network, no LLM: we monkeypatch `voice.capture_voice_request` to stand
in for the mic+STT, and feed stdin for the typed path. This proves the wiring Acceptance 3
hinges on — the same receipted `select_scope` path, and clean fallback on STT failure:

  1. flag OFF                -> acquire_operator_request reads the TYPED line (voice skipped);
  2. flag ON, STT fails(None)-> falls back to the typed line CLEANLY (no crash/hang);
  3. flag ON, transcript     -> returns the transcript WITHOUT touching stdin, and that text
                                drives the same select_scope flip (tour -> learn_more, receipt);
  4. _transcribe w/o API key -> returns None (degrades, doesn't raise).

Run: `python -m examples.browser_demo.selfcheck_voice`   (exit 0 = PASS)
"""
from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path

from . import operator, voice
from .scopes import select_scope
from .session import Session
from .web_mandate import WebMandate


def _mandate():
    return (
        WebMandate("demo-agent", task_id="voice-selfcheck")
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


def main() -> int:
    print("SPEC-04 PART-3 SELF-CHECK")
    real_stdin = sys.stdin
    real_capture = voice.capture_voice_request
    real_voice_env = sys.modules["os"].environ.get("SIGNET_VOICE")
    import os

    out = Path(__file__).resolve().parent / "_selfcheck_voice.session.json"

    async def _voice_returns(text):
        async def _f():
            return text
        return _f

    try:
        # (1) flag OFF -> typed line is read; voice never invoked.
        os.environ.pop("SIGNET_VOICE", None)
        called = {"n": 0}

        async def _spy():
            called["n"] += 1
            return None
        voice.capture_voice_request = _spy
        sys.stdin = io.StringIO("learn more about YC\n")
        got = asyncio.run(operator.acquire_operator_request("> "))
        _check("flag OFF: reads typed line", got == "learn more about YC")
        _check("flag OFF: voice capture NOT called", called["n"] == 0)

        # (2) flag ON, STT fails (None) -> clean fallback to typed.
        os.environ["SIGNET_VOICE"] = "1"

        async def _fail():
            return None
        voice.capture_voice_request = _fail
        sys.stdin = io.StringIO("show me Y Combinator's official website\n")
        got2 = asyncio.run(operator.acquire_operator_request("> "))
        _check("flag ON + STT fail: falls back to typed", got2 == "show me Y Combinator's official website")

        # (3) flag ON, transcript -> returned without consuming stdin; drives select_scope.
        async def _ok():
            return "show me Y Combinator's official website"
        voice.capture_voice_request = _ok
        sentinel = io.StringIO("THIS SHOULD NOT BE READ\n")
        sys.stdin = sentinel
        got3 = asyncio.run(operator.acquire_operator_request("> "))
        _check("flag ON + transcript: returns transcript", got3 == "show me Y Combinator's official website")
        _check("flag ON + transcript: stdin untouched", sentinel.tell() == 0)

        m = _mandate()
        s = Session(m, out_path=out, session_id="voice-selfcheck")
        before = len(s.to_dict()["effects"])
        d = select_scope(m, got3, session=s, use_llm=False)
        _check("transcript drives select_scope ALLOW", d.allowed and m.active == "learn_more")
        _check("scope_switch receipt written + verifies",
               len(s.to_dict()["effects"]) == before + 1 and s.to_dict()["effects"][-1]["receipt_verified"])

        # (4) _transcribe without API key -> None (graceful).
        had_key = os.environ.pop("ELEVENLABS_API_KEY", None)
        try:
            _check("_transcribe w/o API key -> None", voice._transcribe("/nonexistent.wav") is None)
        finally:
            if had_key is not None:
                os.environ["ELEVENLABS_API_KEY"] = had_key
    finally:
        sys.stdin = real_stdin
        voice.capture_voice_request = real_capture
        if real_voice_env is None:
            os.environ.pop("SIGNET_VOICE", None)
        else:
            os.environ["SIGNET_VOICE"] = real_voice_env
        out.unlink(missing_ok=True)

    print("SPEC-04 PART-3 SELF-CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
