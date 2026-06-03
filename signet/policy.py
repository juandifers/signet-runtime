"""Enterprise policy engine.

This is the control-plane layer that sits on top of the ZTRV security kernel.
v0 supports: per-transaction cap, recipient allowlist, currency check, allowed
actions, daily velocity (defends structuring/split attacks), and a simulated
human-approval threshold.
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import CartMandate, IntentMandate, RuntimeContext


@dataclass
class Policy:
    policy_id: str
    max_amount_per_transaction: int
    max_amount_per_day: int
    allowed_recipients: List[str]
    allowed_currencies: List[str]
    allowed_actions: List[str]
    require_human_approval_above: Optional[int] = None


@dataclass
class PolicyResult:
    ok: bool
    reason: str
    requires_review: bool = False


class SpendLedger:
    """Tracks per-subject (principal), per-day cumulative spend for velocity."""

    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS spend "
            "(subject TEXT, day TEXT, amount INTEGER)"
        )
        self._conn.commit()

    def day_total(self, subject: str, now: datetime) -> int:
        day = now.date().isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM spend "
                "WHERE subject = ? AND day = ?",
                (subject, day),
            ).fetchone()
            return int(row[0])

    def record(self, subject: str, amount: int, now: datetime) -> None:
        day = now.date().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO spend (subject, day, amount) VALUES (?, ?, ?)",
                (subject, day, amount),
            )
            self._conn.commit()


@dataclass
class PolicyEngine:
    policies: Dict[str, Policy] = field(default_factory=dict)
    spend: SpendLedger = field(default_factory=SpendLedger)

    def add(self, policy: Policy) -> None:
        self.policies[policy.policy_id] = policy

    def evaluate(self, intent: IntentMandate, cart: CartMandate,
                 ctx: RuntimeContext, now: datetime | None = None) -> PolicyResult:
        now = now or datetime.now(timezone.utc)
        policy = self.policies.get(intent.policy_id)
        if policy is None:
            return PolicyResult(False, f"Unknown policy_id '{intent.policy_id}'.")

        if cart.action not in policy.allowed_actions:
            return PolicyResult(False, f"Action '{cart.action}' not permitted by policy.")
        if cart.currency not in policy.allowed_currencies:
            return PolicyResult(False, f"Currency '{cart.currency}' not permitted by policy.")
        if cart.recipient not in policy.allowed_recipients:
            return PolicyResult(False, f"Recipient '{cart.recipient}' not on policy allowlist.")
        if cart.amount > policy.max_amount_per_transaction:
            return PolicyResult(
                False,
                f"Amount {cart.amount} exceeds per-transaction cap "
                f"{policy.max_amount_per_transaction}.",
            )

        projected = self.spend.day_total(intent.principal_id, now) + cart.amount
        if projected > policy.max_amount_per_day:
            return PolicyResult(
                False,
                f"Amount {cart.amount} would bring the principal's daily spend to "
                f"{projected}, over the daily cap {policy.max_amount_per_day} "
                f"(structuring/velocity).",
            )

        if (policy.require_human_approval_above is not None
                and cart.amount > policy.require_human_approval_above):
            return PolicyResult(
                False,
                f"Amount {cart.amount} exceeds human-approval threshold "
                f"{policy.require_human_approval_above}.",
                requires_review=True,
            )

        return PolicyResult(True, "Policy satisfied.")

    def record_spend(self, subject: str, amount: int,
                     now: datetime | None = None) -> None:
        self.spend.record(subject, amount, now or datetime.now(timezone.utc))
