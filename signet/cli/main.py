"""`signet` console entrypoint.

The `hook` subcommand is dispatched BEFORE argparse is built — it sits on the
PreToolUse hot path (<100ms warm budget) and must not pay for help-text plumbing.
"""
from __future__ import annotations

import argparse
import sys

_BOUNDARY = (
    "The local gate (`signet hook`) is CONTAINMENT UX with tamper-EVIDENT, signed, "
    "hash-chained local receipts. It is NOT the enforcement boundary — an agent with "
    "raw shell access can bypass any client-side hook; the server-side rail (Stage 3) "
    "is the boundary. Bash gating is heuristic pattern containment over the command "
    "string, not effect binding; the file-edit path is the precisely gated one. "
    "The hook is deterministic and offline: no LLM call, no network call, ever. "
    "It never widens permissions (it cannot emit \"allow\") — it only narrows."
)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if argv and argv[0] == "hook":          # hot path: skip argparse entirely
        from .hook import main as hook_main
        return hook_main()

    parser = argparse.ArgumentParser(
        prog="signet",
        description="Signet local gate: contain coding-agent auto mode behind a "
                    "deterministic path/command fence, with a signed receipt for "
                    "every decision.",
        epilog=_BOUNDARY)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="propose + write .signet/policy.yaml, wire the "
                       "PreToolUse hook, create the local key (consent step)")
    p.add_argument("--yes", action="store_true", help="accept all defaults, no prompts")
    p.add_argument("--force", action="store_true", help="overwrite an existing policy")
    p.add_argument("--shared", action="store_true",
                   help="wire the bare `signet hook` into the shared settings.json "
                        "instead of an absolute command in settings.local.json (for "
                        "teams that manage PATH deliberately)")

    sub.add_parser("status", help="effective fence summary, policy_hash, hook wiring, "
                   "receipt count")

    p = sub.add_parser("receipts", help="list local decision receipts; --verify "
                       "recomputes the signed hash chain (tamper-evidence)")
    p.add_argument("--verify", action="store_true")
    p.add_argument("-n", type=int, default=20, help="show the last N records")

    p = sub.add_parser("explain", help="show the verdict + exact rule for a path or "
                       "bash command (same code path as the hook)")
    p.add_argument("path", nargs="?", help="a file path to evaluate")
    p.add_argument("--bash", metavar="CMD", help="evaluate a bash command string instead")

    sub.add_parser("hook", help="PreToolUse gate (reads the hook payload on stdin; "
                   "wired by `signet init` — not for interactive use). Deny/ask only; "
                   "never allows. Bash gating is heuristic pattern containment.")

    p = sub.add_parser("attack-me", help="drive hostile tool calls through the REAL gate "
                       "in a throwaway sandbox — watch each get DENIED with a signed, "
                       "verifiable receipt (the 30-second conversion demo)")
    p.add_argument("--keep", action="store_true",
                   help="keep the sandbox + print the `signet receipts --verify` command")
    p.add_argument("--json", action="store_true",
                   help="emit the structured trace (acts, payloads, verdicts, receipts)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress narration, keep per-act verdict lines (for CI)")

    args = parser.parse_args(argv)
    if args.cmd == "explain" and (args.path is None) == (args.bash is None):
        parser.error("explain needs exactly one of <path> or --bash \"<cmd>\"")

    from . import init_cmd
    if args.cmd == "attack-me":
        from .attack_me import cmd_attack_me
        return cmd_attack_me(args)
    return {"init": init_cmd.cmd_init, "status": init_cmd.cmd_status,
            "receipts": init_cmd.cmd_receipts, "explain": init_cmd.cmd_explain}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
