"""CLI for the refund-triage demo.

  python3 -m examples.refund_triage.run --scenario clean
  python3 -m examples.refund_triage.run --scenario injected --attack a1   # privilege escalation
  python3 -m examples.refund_triage.run --scenario injected --attack a2   # off-op DELETE
  python3 -m examples.refund_triage.run --scenario injected --attack a3   # amount tamper (ALLOW)

The clean run writes exactly one row and emits a receipt; the injected a1/a2 runs write ZERO rows
and emit a refusal receipt; a3 shows the door's granularity boundary as an HONEST ALLOW.
"""
from __future__ import annotations

import argparse
import sys

from . import effects
from .agent import run_scenario
from .trace import panel


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="examples.refund_triage.run", description=__doc__)
    p.add_argument("--scenario", choices=["clean", "injected"], default="clean")
    p.add_argument("--attack", choices=sorted(effects.ATTACKS), default=None,
                   help="which injected attack to run (required for --scenario injected)")
    p.add_argument("--resolver", choices=["deterministic", "adversarial", "llm"], default=None,
                   help="default: deterministic for clean, adversarial for injected")
    p.add_argument("--tier", choices=["0", "1", "auto"], default="auto",
                   help="0=in-proc (advisory); 1=OS-separated broker over SIGNET_BROKER_SOCK "
                        "(structural iff real uid separation); auto=1 when a broker socket is set")
    args = p.parse_args(argv)

    if args.scenario == "injected" and args.attack is None:
        args.attack = "a1"
    resolver = args.resolver or ("adversarial" if args.scenario == "injected" else "deterministic")

    r = run_scenario(scenario=args.scenario, attack=args.attack, resolver=resolver, tier=args.tier)
    print(panel(r))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
