"""Two-terminal steering transport (Spec 05 polish) — move the operator prompt OFF the agent's
terminal so it never interleaves with the agent's step logs.

WHY: in the single-terminal default the always-on steering prompt and the agent's per-step output
share one stdout/stdin, so the prompt scrolls. The fix is a small local IPC: the operator runs a
SEPARATE console process (`python -m examples.browser_demo.steer_console`) in its own terminal,
and each line it sends arrives here over a Unix-domain socket.

WHERE IT PLUGS IN (and what does NOT change): `SteerServer.request_source` satisfies the EXACT
same sync contract the in-terminal source did — "" / whitespace -> no-op (keep listening), a real
line -> one operator request, None -> stop. So it drops straight into the UNCHANGED
`LiveSteerChannel`: the daemon thread, the `run_coroutine_threadsafe` marshaling onto the event
loop, the single-writer-on-the-loop swap, and `select_scope`'s clamp-to-ceiling all stay exactly
as they were. Only the bytes' origin moved from a local stdin to a local socket.

WHAT THIS CARRIES (and does NOT): free-text scope *requests* only — never authority. A request is
still mapped to a frozen menu key ⊆ ceiling by `select_scope` on the loop side; an unmappable /
out-of-ceiling one is REFUSED + receipted (the refuse-the-operator beat). The socket is local-only
(AF_UNIX, 0600) and additive: with `SIGNET_STEER_IPC` unset the run uses the in-terminal source
exactly as before, so every Spec 01-05 flow is unchanged.

Flag: SIGNET_STEER_IPC=1   (both the run and the console read it / the same default socket path).
Path: SIGNET_STEER_SOCK    overrides the default `<tmp>/signet-steer.sock` (both processes agree).
Unix-only (AF_UNIX); the in-terminal source remains the portable default.
"""
from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from queue import Queue
from typing import Optional

from .operator import acquire_operator_request_sync

_STOP = object()                                  # sentinel pushed by stop() to unblock a parked get()


def socket_path() -> str:
    """The control socket both processes use. Default `<tmpdir>/signet-steer.sock`; override with
    SIGNET_STEER_SOCK so the run and the console always agree without passing arguments."""
    return os.environ.get("SIGNET_STEER_SOCK") or os.path.join(
        tempfile.gettempdir(), "signet-steer.sock")


def ipc_enabled() -> bool:
    return bool(os.environ.get("SIGNET_STEER_IPC"))


class SteerServer:
    """Listens on a Unix socket and turns each newline-delimited line from the operator console
    into one steering request, exposed via the sync `request_source` the channel already expects.

    Accepts ONE console at a time; a disconnect just returns to accept(), so the operator can
    close and reopen the console mid-run. Reading happens on a daemon thread, so it never touches
    the event loop — identical to the in-terminal source's threading posture."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or socket_path()
        self._q: "Queue[object]" = Queue()
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "SteerServer":
        try:                                       # clear a stale socket file from a prior run
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(self.path)
        try:
            os.chmod(self.path, 0o600)             # operator-only; this is a local control channel
        except OSError:
            pass
        s.listen(1)
        s.settimeout(0.5)                          # so the accept loop can observe stop()
        self._sock = s
        self._thread = threading.Thread(target=self._serve, name="signet-steer-ipc", daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(0.5)
                buf = b""
                while not self._stop.is_set():
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:                  # console disconnected; wait for a reconnect
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._q.put(line.decode("utf-8", "replace").rstrip("\r"))

    def request_source(self) -> Optional[str]:
        """Block for the next operator line (the channel's daemon thread parks here). A line —
        possibly ""/whitespace, which the channel treats as a no-op — or None once stopped."""
        item = self._q.get()
        if item is _STOP:
            return None
        return item                                # type: ignore[return-value]

    def stop(self) -> None:
        self._stop.set()
        self._q.put(_STOP)                         # unblock a request_source() parked on get()
        try:
            if self._sock is not None:
                self._sock.close()
        except OSError:
            pass
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass


# ---- client side (the separate operator console process) ----------------------------------
def _connect(path: str, retries: int, delay: float) -> Optional[socket.socket]:
    """Connect to the run's socket, retrying briefly so the console can be launched a moment
    before or after the run (the socket appears once the run binds it)."""
    for _ in range(max(1, retries)):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            return s
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            time.sleep(delay)
    return None


def send_loop(prompt: str = "[steer] scope request (talk/type, ENTER alone = skip): ",
              *, path: Optional[str] = None,
              connect_retries: int = 20, retry_delay: float = 0.5) -> int:
    """Operator-facing loop: read a request (voice or typed, via the SAME `acquire_operator_request_sync`
    the in-terminal source uses) and send it to the running agent. Lives in its own process/terminal,
    so its prompt never interleaves with the agent's logs. Ctrl-C / EOF quits the console only — the
    agent and its steering channel keep running, and the console can reconnect."""
    target = path or socket_path()
    sock = _connect(target, connect_retries, retry_delay)
    if sock is None:
        print(f"[steer-console] could not reach the agent at {target}.\n"
              f"  Start the run first:  SIGNET_STEER_IPC=1 python -m examples.browser_demo.run_interactive\n"
              f"  then launch this console in a second terminal.")
        return 1
    print(f"[steer-console] connected to {target}. Type a scope request and press ENTER "
          f"(Ctrl-C to quit).\n"
          f"  Requests are clamped to the ceiling on the agent side; an unmappable / out-of-ceiling "
          f"one is REFUSED + receipted and shown loud in both panels.")
    try:
        with sock:
            while True:
                try:
                    req = acquire_operator_request_sync(prompt)
                except (EOFError, KeyboardInterrupt):
                    break
                if not req:                        # bare ENTER / EOF -> nothing to send; keep going
                    continue
                try:
                    sock.sendall((req + "\n").encode("utf-8"))
                except OSError:
                    print("[steer-console] the agent closed the channel; exiting.")
                    return 0
                print(f"[steer-console] sent -> {req!r}")
    except KeyboardInterrupt:
        pass
    print("\n[steer-console] disconnected (the agent keeps running).")
    return 0
