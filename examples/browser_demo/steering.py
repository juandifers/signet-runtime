"""Always-on live policy steering (Spec 05 Part 1) — the operator changes the ACTIVE scope at
ANY step, not only when the agent is blocked.

OWNERSHIP / CONTENTION (the key design decision): steering is owned by the RUN PROCESS, never
the page (the in-page panel is `pointer-events:none` on purpose). There is exactly ONE reader
of stdin at a time. When this channel is active it is the SOLE owner; the on-block prompt from
Spec 04 degrades to a printed notice ("blocked … steer when ready"). The other modes
(SIGNET_AUTO_GRANT=1 hands-free, or SIGNET_LIVE_STEER=0 = the Spec 04 on-block prompt) do not
start this channel, so stdin still has a single owner in every mode.

THREAD MODEL: a single daemon thread blocks synchronously on the operator (voice or typed) —
keeping mic/stdin blocking OFF the event loop and letting the process exit cleanly at the end
(daemon). Each captured request is marshaled onto the event loop via
`run_coroutine_threadsafe`, so `select_scope` and the `mandate.active` swap run on the SAME
thread the gate reads from — single-writer-on-the-loop, which is a stronger guarantee than a
lock (there is no window where the gate could observe a half-applied swap). We still take a
lock around the apply to serialize back-to-back requests and to satisfy the spec's
"guard the swap" intent explicitly.

The gate reads `mandate.active` fresh on every tool call, so a swap lands on the agent's NEXT
action with no restart. Steering changes POLICY (which pre-authorized lane is live), never
authority — `select_scope` clamps every request to a frozen menu key ⊆ ceiling, and an
unmappable request is REFUSED + receipted (the refuse-the-operator beat).
"""
from __future__ import annotations

import asyncio
import threading
from typing import Awaitable, Callable, Optional

from .operator import acquire_operator_request_sync
from .scopes import select_scope


class LiveSteerChannel:
    """A daemon-thread operator channel feeding `select_scope` on the event loop.

    request_source: sync callable returning the next operator request string. "" -> ignored
      (no-op, keep listening); None -> stop the channel. Defaults to the real voice/typed
      intake; injectable for tests.
    on_apply: optional async callback(decision, request) run on the loop after each apply
      (used to refresh the in-page panel immediately on a steer / refusal).
    """

    def __init__(self, mandate, session, loop: asyncio.AbstractEventLoop, *,
                 prompt: str = "[steer] scope request (talk/type, ENTER alone = skip): ",
                 request_source: Optional[Callable[[], Optional[str]]] = None,
                 on_apply: Optional[Callable[[object, str], Awaitable[None]]] = None) -> None:
        self.mandate = mandate
        self.session = session
        self.loop = loop
        self.prompt = prompt
        self._request_source = request_source or (lambda: acquire_operator_request_sync(self.prompt))
        self._on_apply = on_apply
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="signet-live-steer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # -- daemon thread --------------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                req = self._request_source()
            except Exception:
                break
            if self._stop.is_set():
                break
            if req is None:                 # explicit stop signal from the source
                break
            if not req.strip():             # bare ENTER -> nothing to steer; keep listening
                continue
            # Marshal the apply onto the event loop and wait for it (serializes requests).
            try:
                fut = asyncio.run_coroutine_threadsafe(self._apply(req.strip()), self.loop)
                fut.result(timeout=60)
            except Exception:
                pass

    # -- runs on the event loop -----------------------------------------------------------
    async def _apply(self, request: str):
        with self._lock:
            decision = select_scope(self.mandate, request, session=self.session)
        if self._on_apply is not None:
            try:
                await self._on_apply(decision, request)
            except Exception:
                pass
        return decision
