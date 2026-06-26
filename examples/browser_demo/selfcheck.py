"""Offline self-check: `python -m examples.browser_demo.selfcheck`.

Exercises the gate + real signet receipts + session shape WITHOUT an LLM or a browser,
so the core architecture (Spec 01 acceptance #2–#5) is verifiable deterministically and
in CI. The live `run.py` proves #1 (the agent actually drives a real browser).

Checks:
  2. an in-scope action -> ALLOW
  3. an off-allowlist target -> BLOCK (structured reason)
  4. a disallowed action type -> BLOCK
  5. every decision writes a receipt that VERIFIES offline via the real
     `ReceiptLog.verify`, and the receipts form a valid hash chain.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from . import gate
from .session import Session
from .web_mandate import WebMandate


def main() -> int:
    mandate = (
        WebMandate("demo-agent", task_id="selfcheck-001")
        .allow_domains(["example.com"])
        .allow_actions(["navigate", "extract"])   # NOTE: click/type deliberately withheld
        .build()
    )

    # The mandate is frozen: provenance-monotonicity is structural (no mutator exists).
    try:
        mandate.allowed_domains.add("evil.com")            # frozenset -> AttributeError
        assert False, "frozenset should be immutable"
    except AttributeError:
        pass

    out = Path(tempfile.mkdtemp()) / "session.json"
    session = Session(mandate, out_path=out, session_id="selfcheck")

    cases = [
        # (label, action, target, provenance, expected_outcome)
        ("in-scope navigate",      "navigate", "https://example.com/",        "agent", "allow"),
        ("in-scope extract",       "extract",  "https://example.com/",        "agent", "allow"),
        ("off-allowlist navigate", "navigate", "https://www.iana.org/help",   "page",  "block"),
        ("disallowed action type", "click",    "https://example.com/",        "agent", "block"),
        ("unrecognized action",    "purchase", "https://example.com/",        "agent", "block"),
        ("subdomain allowed",      "navigate", "https://docs.example.com/x",  "page",  "allow"),
    ]

    ok = True
    for label, action, target, prov, expected in cases:
        d = gate.decide(mandate, action, target, provenance=prov)
        receipt = session.mint_receipt(action=action, target=target, outcome=d.outcome)
        domain = gate.resolve_domain(target) or target
        performed = {"browser": "performed" if d.allowed else "blocked"}
        rec = session.record(None, action, {"url": target}, d, receipt,
                             target=domain, performed=performed, label=label)
        verified, vmsg = session.receipts.verify(receipt)
        match = (d.outcome == expected)
        ok = ok and match and verified
        flag = "OK " if (match and verified) else "FAIL"
        print(f"[{flag}] {label:<24} -> {d.outcome.upper():<5} "
              f"receipt {rec['receipt_id'][:10]} verified={verified}  | {d.reason}")

    # Acceptance #5: the receipts form a valid hash chain (each commits to the previous).
    log = session.receipts.all()
    chain_ok = True
    for i, r in enumerate(log):
        expected_prev = log[i - 1].receipt_hash if i > 0 else None
        if r.prev_receipt_hash != expected_prev:
            chain_ok = False
        if not session.receipts.verify(r)[0]:
            chain_ok = False
    print(f"\nhash-chain over {len(log)} receipts valid: {chain_ok}")
    print(f"session.json written to: {session.out_path}")

    ok = ok and chain_ok
    print("\nSELF-CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
