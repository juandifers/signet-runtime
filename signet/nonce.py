"""Consume-once nonce registry.

The DB's PRIMARY KEY uniqueness gives us an atomic check-and-set: the first
INSERT of a nonce succeeds, any concurrent/subsequent INSERT of the same nonce
fails. This is the property the ZTRV paper insists must be atomic so that
concurrent retries cannot race each other and both pass.

Required state is bounded by the validity window (sliding GC), not by
cumulative transaction history.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone


class NonceRegistry:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS nonces "
            "(nonce TEXT PRIMARY KEY, expires_at TEXT NOT NULL)"
        )
        self._conn.commit()

    def consume_once(self, nonce: str, ttl_seconds: int = 300,
                     now: datetime | None = None) -> bool:
        """Return True if this is the first use of `nonce`, False if replayed."""
        now = now or datetime.now(timezone.utc)
        expires = (now + timedelta(seconds=ttl_seconds)).isoformat()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)",
                    (nonce, expires),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def gc(self, now: datetime | None = None) -> int:
        """Delete expired nonces. Returns count removed."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM nonces WHERE expires_at < ?", (now.isoformat(),)
            )
            self._conn.commit()
            return cur.rowcount

    def size(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]
