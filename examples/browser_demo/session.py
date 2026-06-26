"""`Session` — wraps the REAL signet `ReceiptLog` and emits a viewer-shaped `session.json`.

Hybrid coupling (Spec 01): the gate itself is standalone and in-process, but the
evidence is real. Every decision mints exactly one signed, hash-chained
`signet.receipts.Receipt` via the unchanged kernel `ReceiptLog`, and is serialised
into the same per-effect contract the existing refund-triage viewer consumes
(examples/refund_triage/viewer/index.html), so our trace renders there with no
viewer change. `session.json` is rewritten after every recorded decision.

Field mapping into the kernel `ReceiptLog.append(...)` (signet/receipts.py:26):
  * execution_id  -> "<task_id>-<n>"            (per-decision id)
  * mandate_id    -> mandate.task_id
  * chain_hash    -> hash of the proposed effect {action, target, outcome} — the
                     "exact bound action" this receipt commits to (lets it verify offline)
  * policy_id     -> short hash of the frozen mandate scope (binds the receipt to the
                     policy that decided it, mirroring the kernel's policy_hash discipline)
  * decision      -> "allow" | "block"          (the gate outcome, verbatim)
  * payment_status-> "performed" | "refused"    (rail-agnostic: did the effect run?)
  * payment_ref   -> the target (URL / page)
  * rail          -> "browser"

HONESTY: crypto is research-grade (Ed25519, local in-process keypair, no anchor),
isolated to the kernel's `crypto`/`ReceiptLog` and production-swappable. The browser
rail mints NO capability token (`token_minted` is always False) — it is an
effect-performing door like egress, which holds nothing.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
from typing import Optional

from signet import crypto
from signet.canonical import hash_obj
from signet.receipts import ReceiptLog, Receipt

from .gate import Decision
from .web_mandate import FrozenWebMandate

DEFAULT_OUT = Path(__file__).resolve().parent / "session.json"


class Session:
    def __init__(self, mandate: FrozenWebMandate, *,
                 out_path: Path | str = DEFAULT_OUT,
                 session_id: str = "browser-demo") -> None:
        self.mandate = mandate
        self.out_path = Path(out_path)
        self.session_id = session_id
        # Research-grade enforcer keypair, minted in-process (honesty label in module docstring).
        sk, vk = crypto.generate_keypair()
        self._receipts = ReceiptLog(sk, vk)
        self._policy_id = "web-mandate-" + hash_obj({
            "domains": sorted(mandate.allowed_domains),
            "actions": sorted(mandate.allowed_actions),
        })[:12]
        self._effects: list[dict] = []
        self._snapshots: list[dict] = []

    # -- the ReceiptLog wrapper -------------------------------------------------------------
    @property
    def receipts(self) -> ReceiptLog:
        return self._receipts

    def mint_receipt(self, *, action: str, target: str, outcome: str,
                     active_scope: Optional[str] = None) -> Receipt:
        """One signed, hash-chained receipt per decision. `chain_hash` binds it to this exact
        proposed effect (incl. the active scope, Spec 02), so `ReceiptLog.verify(receipt)`
        confirms it offline. `active_scope=None` hashes identically to a Spec 01 receipt."""
        payload = {"action": action, "target": target, "outcome": outcome}
        if active_scope is not None:
            payload["active_scope"] = active_scope
        chain_hash = hash_obj(payload)
        return self._receipts.append(
            execution_id=f"{self.mandate.task_id}-{len(self._effects) + 1}",
            mandate_id=self.mandate.task_id,
            chain_hash=chain_hash,
            policy_id=self._policy_id,
            decision=outcome,
            payment_status="performed" if outcome == "allow" else "refused",
            payment_ref=target,
            rail="browser",
        )

    # -- the viewer-shaped record -----------------------------------------------------------
    def record(self, step: Optional[int], action: str, args: dict, decision: Decision,
               receipt: Receipt, *, target: str, performed: dict,
               label: Optional[str] = None, note: Optional[str] = None,
               rail: str = "browser", active_scope: Optional[str] = None) -> dict:
        """Append one effect record (refund-triage viewer §4 shape) and rewrite session.json."""
        seq = len(self._effects) + 1
        verified = bool(self._receipts.verify(receipt)[0])
        rec = {
            "seq": seq,
            "step": step,                       # the agent step that proposed it (informational)
            "rail": rail,
            "label": label or f"{action} {target}",
            "proposed": {
                "action": action,
                "target": target,
                "detail": _detail(args),
            },
            "decision": decision.outcome.upper(),                  # ALLOW | BLOCK
            "reason": decision.reason,
            "escalation_source": "resolved" if decision.allowed else "admission_denied",
            "token_minted": False,                                 # browser door holds nothing
            "performed": performed,
            "active_scope": active_scope if active_scope is not None else self.mandate.active,
            "receipt_id": receipt.receipt_hash,
            "receipt_verified": verified,
            "note": note,
        }
        self._effects.append(rec)
        self.write()
        return rec

    def record_scope_switch(self, request: str, selected: Optional[str], outcome: str, *,
                            reason: str, step: Optional[int] = None) -> dict:
        """Record a `select_scope` decision (Spec 02 Part C) as one signed receipt + effect.
        `selected` is the activated menu key on allow, or None on refuse (active unchanged)."""
        from .gate import Decision
        target = selected or "none"
        active_now = self.mandate.active
        receipt = self.mint_receipt(action="select_scope", target=target, outcome=outcome,
                                    active_scope=active_now)
        return self.record(
            step, "select_scope", {"query": request}, Decision(outcome, reason), receipt,
            target=target, rail="scope", active_scope=active_now,
            performed={"scope": active_now if outcome == "allow" else "unchanged"},
            label=f"select_scope: {request[:60]}",
            note="untrusted planner mapped request -> a frozen menu key; activation is deterministic")

    def snapshot(self, *, step: Optional[int], url: str, title: str) -> None:
        """on_step_start state snapshot ONLY — never enforcement (Spec 01 locked decision)."""
        self._snapshots.append({"step": step, "url": url, "title": title})

    # -- serialisation ----------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
            "tier": "0 (advisory)",                # in-process gate; not a structural boundary
            "tier_structural": False,
            "mandate": {
                "principal": self.mandate.principal,
                "task_id": self.mandate.task_id,
                "database": None,                  # n/a for the browser rail; viewer tolerates None
                "granted_scope": self.mandate.granted_scope(),     # the ACTIVE scope's grant
                # Spec 02/03 fields the live sidebar renders: frozen ceiling, the full scope
                # menu, and the current active scope name (per-effect active_scope is on effects[]).
                "ceiling": self.mandate.ceiling.summary(),
                "scopes": self.mandate.menu_summaries(),
                "active": self.mandate.active,
            },
            "effects": list(self._effects),
            "snapshots": list(self._snapshots),    # extra, ignored by the viewer
        }

    def write(self) -> Path:
        """ATOMIC write (temp + os.replace) so a live poll never reads a half-written file.
        The sidebar that polls this path always sees either the previous or the next complete
        JSON, never a torn one."""
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(self.to_dict(), indent=2) + "\n"
        tmp = self.out_path.with_name(self.out_path.name + f".{os.getpid()}.tmp")
        tmp.write_text(data)
        os.replace(tmp, self.out_path)             # atomic on POSIX + Windows
        return self.out_path


def _detail(args: dict) -> str:
    """Human-legible row detail (legibility only — the gate ignores it)."""
    parts = []
    for k in ("url", "index", "text", "query"):
        if k in args and args[k] not in (None, ""):
            v = str(args[k])
            if len(v) > 80:
                v = v[:77] + "..."
            parts.append(f"{k}={v}")
    return ", ".join(parts)
