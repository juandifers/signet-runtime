"""Signed, hash-chained receipts.

Each receipt commits to the previous receipt's hash, forming an append-only log.
The enforcer signs each receipt. Anchoring receipt_hash on a public ledger
(e.g. an XRPL memo) would additionally defeat equivocation -- the enforcer could
not show different histories to different parties -- without revealing any
payment detail.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from . import crypto
from .canonical import canonical_json, hash_obj
from .models import Receipt


class ReceiptLog:
    def __init__(self, enforcer_signing_key: str, enforcer_verify_key: str):
        self._sk = enforcer_signing_key
        self._vk = enforcer_verify_key
        self._log: List[Receipt] = []

    def append(self, *, execution_id: str, mandate_id: str, chain_hash: str,
               policy_id: str, decision: str, payment_status: str,
               payment_ref: Optional[str], rail: str) -> Receipt:
        prev = self._log[-1].receipt_hash if self._log else None
        receipt = Receipt(
            receipt_id="receipt_" + uuid.uuid4().hex[:12],
            execution_id=execution_id,
            mandate_id=mandate_id,
            chain_hash=chain_hash,
            policy_id=policy_id,
            decision=decision,
            payment_status=payment_status,
            payment_ref=payment_ref,
            rail=rail,
            timestamp=datetime.now(timezone.utc),
            prev_receipt_hash=prev,
        )
        receipt.receipt_hash = hash_obj(receipt.hashing_payload())
        receipt.signature = crypto.sign(self._sk, receipt.receipt_hash.encode())
        self._log.append(receipt)
        return receipt

    def verify(self, receipt: Receipt) -> tuple[bool, str]:
        recomputed = hash_obj(receipt.hashing_payload())
        if recomputed != receipt.receipt_hash:
            return False, "Receipt hash does not match its contents (tampered)."
        if receipt.signature is None or not crypto.verify(
            self._vk, receipt.receipt_hash.encode(), receipt.signature
        ):
            return False, "Receipt signature invalid."
        return True, "Receipt verified."

    def all(self) -> List[Receipt]:
        return list(self._log)
