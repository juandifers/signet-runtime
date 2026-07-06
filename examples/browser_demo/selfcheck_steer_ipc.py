"""Offline proof of the two-terminal steering transport (Spec 05 polish).

No browser, no LLM, no mic. We stand up the REAL `SteerServer` on a temp Unix socket and a REAL
`LiveSteerChannel` on a REAL event loop (run on its own thread), connect a client exactly as the
`steer_console` process does, and assert the end-to-end path holds:

  1. a line sent over the socket is delivered and APPLIED on the loop, flipping the active scope —
     proving SteerServer.request_source drops into the UNCHANGED channel (same threading /
     run_coroutine_threadsafe marshaling as the in-terminal source);
  2. a whitespace-only line is a NO-OP (bare-ENTER semantics preserved over the wire);
  3. an out-of-ceiling request is REFUSED, active UNCHANGED, with a signed refusal receipt — the
     refuse-the-operator beat is unchanged when the request arrives via IPC instead of stdin.

The transport moved the bytes' ORIGIN (stdin -> socket); it changed NO authority. Run:
`python -m examples.browser_demo.selfcheck_steer_ipc`   (exit 0 = PASS)
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import threading
from pathlib import Path
from queue import Queue

from . import steer_ipc
from .session import Session
from .steering import LiveSteerChannel
from .web_mandate import WebMandate


def _mandate():
    return (
        WebMandate("demo-agent", task_id="steer-ipc-selfcheck")
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
    print("SPEC-05 IPC SELF-CHECK")
    saved_key = os.environ.pop("OPENAI_API_KEY", None)   # force the offline keyword classifier
    tmp = tempfile.mkdtemp(prefix="signet-steer-ipc-")
    sock_path = os.path.join(tmp, "steer.sock")
    out = Path(__file__).resolve().parent / "_selfcheck_steer_ipc.session.json"

    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, name="ipc-selfcheck-loop", daemon=True).start()

    m = _mandate()
    s = Session(m, out_path=out, session_id="steer-ipc-selfcheck")

    applied: "Queue[tuple]" = Queue()

    async def on_apply(decision, request):
        applied.put((request, decision))

    server = steer_ipc.SteerServer(sock_path).start()
    channel = LiveSteerChannel(m, s, loop, request_source=server.request_source, on_apply=on_apply)
    channel.start()

    try:
        client = steer_ipc._connect(sock_path, retries=40, delay=0.25)   # exactly what the console does
        _check("console connects to the running agent over the socket", client is not None)

        # (1) a valid request, delivered over the socket, is applied on the loop and flips the scope.
        client.sendall(b"show me Y Combinator's official website\n")
        _req1, d1 = applied.get(timeout=10)
        _check("(1) request delivered over IPC and applied on the loop", d1.allowed)
        _check("(1) active flipped to learn_more", m.active == "learn_more")

        # (2) a whitespace-only line is a no-op (it must NOT surface as an apply); the next apply
        #     we observe is the out-of-ceiling refusal sent right after it.
        client.sendall(b"   \n")

        # (3) an out-of-ceiling request is REFUSED + receipted; active unchanged.
        client.sendall(b"open my online banking dashboard\n")
        req2, d2 = applied.get(timeout=10)
        _check("(2) whitespace-only line was a no-op (not applied)", "banking" in req2.lower())
        _check("(3) out-of-ceiling request REFUSED", not d2.allowed)
        _check("(3) active UNCHANGED after refusal", m.active == "learn_more")

        scope_fx = [e for e in s.to_dict()["effects"] if e["rail"] == "scope"]
        _check("two scope receipts (one ALLOW, one REFUSE), both verify",
               len(scope_fx) == 2 and all(e["receipt_verified"] for e in scope_fx)
               and {e["decision"] for e in scope_fx} == {"ALLOW", "BLOCK"})

        client.close()
    finally:
        channel.stop()
        server.stop()                                    # unblocks request_source -> channel thread exits
        loop.call_soon_threadsafe(loop.stop)
        if saved_key is not None:
            os.environ["OPENAI_API_KEY"] = saved_key
        out.unlink(missing_ok=True)
        for cleanup in (lambda: os.unlink(sock_path), lambda: os.rmdir(tmp)):
            try:
                cleanup()
            except OSError:
                pass

    print("SPEC-05 IPC SELF-CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
