"""Authorizer interface — now a CONCRETE TEMPLATE METHOD so containment is STRUCTURAL, not
convention.

The verifier decides; an Authorizer turns that decision into a rail-specific *necessary input* for
the irreversible action. The principle: the agent must hold no standalone capability to reach the
irreversible step — every path is either a co-signature the enforcer must contribute or a
credential the enforcer mints just-in-time. The verifier stays rail-agnostic; only the authorizer
is per-rail.

Previously every authorizer re-implemented the same opening: verify the enforcer token, then
independently re-check the runtime effect vs the signed Cart, then act. That was CONVENTION — a
rail that "forgot" `verify_token` still satisfied the old ABC (inventory GAP #6). Now `authorize`
is a FINAL template that OWNS that order:

    verify_token  ->  recheck_against_context  ->  produce_capability

A rail fills in only the two content hooks; it CANNOT skip the token check or run before the
re-check. `produce_capability` is reached ONLY when both guards pass. A rail whose
`produce_capability` would mint unconditionally still cannot execute on an invalid token or a
context mismatch — the template blocks it first.

Cosigners (xrpl/mpc) deliberately OVERRIDE `authorize` to `raise` (their real path is `cosign(...)`,
a different signature); they implement the hooks trivially. Bringing the cosign path under an
analogous template is a separate, flagged pass.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Tuple

from ..models import ExecutionRequest, ExecutionToken


@dataclass
class AuthorizationResult:
    executed: bool
    reason: str
    payment_ref: Optional[str] = None
    rail: str = ""


class Authorizer(ABC):
    rail: str = "abstract"

    def __init__(self, verifier, enforcer_vk: str):
        self._verifier = verifier
        self._enforcer_vk = enforcer_vk

    def authorize(self, token: ExecutionToken,
                  req: ExecutionRequest) -> AuthorizationResult:
        """FINAL containment flow — DO NOT override in a rail (override the hooks). The order +
        fail-closed live here, not in the rail:

          1. the enforcer token MUST be valid (verify_token) — else refuse;
          2. the runtime effect MUST match the signed Cart (recheck_against_context) — else refuse,
             after giving the rail a chance to record the rejection natively (on_rejected);
          3. ONLY THEN produce the rail capability (produce_capability).
        """
        if not self._verifier.verify_token(token, self._enforcer_vk):
            return AuthorizationResult(False, "Enforcer token invalid/expired.", rail=self.rail)
        ok, reason = self.recheck_against_context(token, req)
        if not ok:
            self.on_rejected(token, req, reason)
            return AuthorizationResult(False, reason, rail=self.rail)
        return self.produce_capability(token, req)

    @abstractmethod
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        """Independently re-check the runtime effect against the signed Cart + that the token is
        bound to THIS exact transaction. Return (ok, reason). MUST NOT have an irreversible side
        effect — it runs before the capability is produced and may be followed by `on_rejected`."""
        ...

    @abstractmethod
    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        """Mint/execute the rail's necessary input — reached ONLY when verify_token AND
        recheck_against_context both pass."""
        ...

    def on_rejected(self, token: ExecutionToken, req: ExecutionRequest, reason: str) -> None:
        """Optional rail-native record of a rejection (e.g. conclude a Check Run / deploy gate as
        failure). Default: no-op. Must not change the (False) verdict."""
        return None
