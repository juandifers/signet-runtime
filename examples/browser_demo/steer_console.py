"""Operator steering console — the SECOND terminal (Spec 05 two-terminal polish).

Run this in a SEPARATE terminal from the agent so the steering prompt never interleaves with the
agent's per-step logs:

    # terminal 1 — the agent
    SIGNET_STEER_IPC=1 python -m examples.browser_demo.run_interactive
    # terminal 2 — the operator (this)
    SIGNET_STEER_IPC=1 python -m examples.browser_demo.steer_console
    #   add SIGNET_VOICE=1 to push-to-talk; both fall back to typed.

Each line you type (or speak) is one scope request, sent over a local Unix socket to the running
agent and fed to the UNCHANGED `select_scope` on the agent's event loop. The console carries
free-text requests only — never authority: every request is clamped to a frozen menu key ⊆
ceiling, and an unmappable / out-of-ceiling one is REFUSED + receipted by the agent (the
refuse-the-operator beat), shown loud in both panels. Ctrl-C quits the console only; the agent
keeps running.
"""
from __future__ import annotations

from . import steer_ipc


def main() -> int:
    return steer_ipc.send_loop()


if __name__ == "__main__":
    raise SystemExit(main())
