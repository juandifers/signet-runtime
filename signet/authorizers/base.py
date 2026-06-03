"""Authorizer interface.

The verifier decides; an Authorizer turns that decision into a rail-specific
*necessary input* for the irreversible action. The principle: the agent must
hold no standalone capability to reach the irreversible step -- every path is
either a co-signature the enforcer must contribute or a credential the enforcer
mints just-in-time. The verifier stays rail-agnostic; only the authorizer is
per-rail.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from ..models import ExecutionRequest, ExecutionToken


@dataclass
class AuthorizationResult:
    executed: bool
    reason: str
    payment_ref: Optional[str] = None
    rail: str = ""


class Authorizer(ABC):
    rail: str = "abstract"

    @abstractmethod
    def authorize(self, token: ExecutionToken,
                  req: ExecutionRequest) -> AuthorizationResult:
        ...
