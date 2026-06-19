"""The eval-layer egress chokepoint — the agent's ONLY egress path (single chokepoint by
construction). Every attempted outbound connection goes through `attempt`; there is no other way
out, so the decision is unavoidable.

The chokepoint is where the block and the receipt are the same act: `attempt` calls the Stage-1
in-path emitter (`EgressMerkleLog.emit`), which runs the real decision (`effective_admits` + the
standing/learned basis) AND commits the leaf in one call, then enforces the verdict:

  * ALLOW  -> perform the egress (the bytes leave)
  * DENY   -> do not perform; the receipt is the proof of the block
  * REVIEW -> HELD, recorded, NOT performed — with no human present a REVIEW is never an allow

Enforcement happens here, synchronously, before and independent of any anchoring (Stage 3). The
chokepoint never waits on, or fails because of, an anchor target.

Scope: this is the EVAL chokepoint used by the smoke run, NOT the production proxy
(`signet/broker/proxy.py`, fenced). The rail is destination-based — it binds host:port and commits
a hash of the attempted payload; it does not inspect payload contents.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .record import ALLOW, DENY, REVIEW, EgressMerkleLog, EgressReceipt


@dataclass(frozen=True)
class EgressOutcome:
    decision: str
    performed: bool
    receipt: EgressReceipt
    label: str


class EgressChokepoint:
    """Wraps an `EgressMerkleLog`. The agent is handed ONLY this object for egress."""

    def __init__(self, log: EgressMerkleLog) -> None:
        self._log = log
        self.events: List[EgressOutcome] = []     # every attempt, in order
        self.sent: List[bytes] = []               # payloads actually egressed (ALLOW only)
        self.held: List[EgressOutcome] = []        # DENY + REVIEW (not performed)

    def attempt(self, *, destination: str, host: str, port: int, payload: bytes,
                protocol: str = "http_connect", label: str = "") -> EgressOutcome:
        """The single egress operation. Decide + commit the leaf (in-path), then enforce."""
        decision, receipt = self._log.emit(destination=destination, host=host, port=port,
                                            payload=payload, protocol=protocol)
        performed = (decision == ALLOW)
        outcome = EgressOutcome(decision=decision, performed=performed, receipt=receipt,
                                label=label or destination)
        self.events.append(outcome)
        if performed:
            self.sent.append(payload)             # the bytes leave only on ALLOW
        else:
            self.held.append(outcome)             # DENY or REVIEW: held, recorded, not performed
        return outcome

    def finalize(self) -> Tuple[str, List[dict]]:
        """Delegate to the log: returns (root, wire_receipts). Anchoring (Stage 3) consumes the
        root afterward; it is never on the path above."""
        return self._log.finalize()
