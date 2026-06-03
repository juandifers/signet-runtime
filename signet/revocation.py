"""Revocation registry.

Revocation must be checked at *execution* time, not only at issuance, because a
mandate that was valid when minted can be revoked before it is used.
"""
from __future__ import annotations

from typing import Set


class RevocationRegistry:
    def __init__(self) -> None:
        self._revoked: Set[str] = set()

    def revoke(self, mandate_id: str) -> None:
        self._revoked.add(mandate_id)

    def is_revoked(self, mandate_id: str) -> bool:
        return mandate_id in self._revoked
