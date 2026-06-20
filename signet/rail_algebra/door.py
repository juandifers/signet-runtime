"""Door (the PEP): the mechanism that makes a verdict unbypassable, plus its HONEST soundness
(ONLY-DOOR-OR-DECLARE — a door declares `sole_path` only where the resource is truly unreachable
without it; elsewhere it is `advisory` and a negative test records the ambient path).

`enforce(cap)` runs ONLY after the policy ALLOWed and the bind re-checked; it returns Effect (the
door performed/admitted) or Blocked (the door refused, fail-closed). The door MECHANISM is injected
(the GitHub Check Run handle, the broker proxy admission) so this module wraps existing rails — it
NEVER reimplements netns, the sole-path, or the broker privilege drop (NETNS-UNTOUCHED).

Variants:
  * ExternalEnforcer (EXTERNAL) — an external system is the real PEP (a required Check Run gating a
    protected-branch ruleset; a PSP). The enforcer concludes the check; branch protection blocks the
    merge until it does.
  * KeyholderBroker (CUSTODY) — the enforcer is the sole holder of a scoped credential it mints
    just-in-time (the DB rail). STUB here for the payment composition.
  * NetworkSolePath (SOLE_PATH | ADVISORY) — WRAPS the egress broker proxy. `sole_path=True` only
    under the netns deployment (CAP_NET_ADMIN dropped); without it the door is ADVISORY and a direct
    connection bypasses the proxy (test_broker_egress #8). This variant does not edit netns.py.
  * AdvisoryInline (ADVISORY) — an inline observer with no hard boundary (logging/receipts only).
"""
from __future__ import annotations

from typing import Any, Callable, Optional, Tuple, Union

from .schedule import DOOR, mark
from .types import (ADVISORY, Blocked, CUSTODY, Effect, EXTERNAL, SOLE_PATH)

DoorResult = Union[Effect, Blocked]


class ExternalEnforcer:
    """An external PEP. `perform(cap) -> ref` concludes the required gate as success; a rail-native
    refusal (e.g. PermissionError from a consume-once Check Run) is caught -> Blocked. `decline(cap,
    reason)` concludes the gate as FAILURE for the rejected-effect path (on_rejected)."""

    soundness = EXTERNAL

    def __init__(self, perform: Callable[[Any], str],
                 decline: Optional[Callable[[Any, str], Optional[str]]] = None):
        self._perform = perform
        self._decline = decline

    def enforce(self, cap) -> DoorResult:
        mark(DOOR)                                          # phase from the rail's active phase_scope
        try:
            ref = self._perform(cap)
        except PermissionError as e:                        # rail refused (consume-once / unbound)
            return Blocked(str(e))
        return Effect(detail="external gate concluded success", ref=ref)

    def decline(self, cap, reason: str) -> Blocked:
        ref = None
        if self._decline is not None:
            ref = self._decline(cap, reason)
        return Blocked(reason=reason, ref=ref)


class KeyholderBroker:
    """The enforcer mints a short-lived, effect-bound credential it alone holds (CAP-BOUND). STUB:
    `mint(cap) -> ref` is injected; absent, construction succeeds but enforce raises (the DB rail's
    real broker is out of scope for this refactor)."""

    soundness = CUSTODY

    def __init__(self, mint: Optional[Callable[[Any], str]] = None):
        self._mint = mint

    def enforce(self, cap) -> DoorResult:
        if self._mint is None:                              # pragma: no cover - stub
            raise NotImplementedError(
                "KeyholderBroker.enforce needs an injected credential minter (out of scope here)")
        return Effect(detail="brokered capability minted", ref=self._mint(cap))


class NetworkSolePath:
    """Wraps the egress broker proxy's inline admission. `admit(cap) -> (admitted, reason, ref)` is
    the existing admission decision; this variant adds NOTHING to it but the honest soundness label.
    `sole_path` is False in v0 (no netns) -> ADVISORY (ONLY-DOOR-OR-DECLARE: a direct connection
    bypasses the proxy). It flips to SOLE_PATH only under the netns deployment — which this class
    does not touch."""

    def __init__(self, admit: Callable[[Any], Tuple[bool, str, Optional[str]]],
                 *, sole_path: bool = False):
        self._admit = admit
        self.sole_path = bool(sole_path)
        self.soundness = SOLE_PATH if sole_path else ADVISORY

    def enforce(self, cap) -> DoorResult:
        mark(DOOR)                                          # phase from the rail's active phase_scope
        admitted, reason, ref = self._admit(cap)
        return Effect(detail=reason, ref=ref) if admitted else Blocked(reason=reason, ref=ref)


class AdvisoryInline:
    """An inline observer: it records a verdict but enforces no hard boundary (an ambient path
    exists). Always permits structurally — its value is the receipt, not containment."""

    soundness = ADVISORY

    def __init__(self, observe: Optional[Callable[[Any], str]] = None):
        self._observe = observe

    def enforce(self, cap) -> DoorResult:
        detail = self._observe(cap) if self._observe is not None else "advisory: observed only"
        return Effect(detail=detail)
