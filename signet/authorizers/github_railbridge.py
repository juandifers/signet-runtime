"""GitHub rail-bridge authorizer (Role 2-style credential custody for an infra rail).

The irreversible step for "merge a PR to a protected branch" is the enforcer
concluding a required Check Run as `success` -- that is the gate the protected
branch's ruleset waits on. The agent holds no capability to conclude that check;
only this authorizer does, and only after the verifier approves and the effect
re-checks against `req.context`. This mirrors `mock_broker.py`: the enforcer is the
sole holder of the rail capability, and the rail (`GitHubRail`) refuses to conclude
any check not bound to this token's `chain_hash`.

Invariants (CLAUDE.md): base.py does NOT enforce verify_token -- so authorize()
calls it as its FIRST line. Then it independently re-checks the effect against
`req.context` (effect_class, recipient incl. head_sha, destination_account) and
that the token is bound to THIS exact transaction, refusing on any mismatch
(fail closed). No rail logic leaks into the kernel; the kernel stays rail-agnostic.

RAIL ALGEBRA (signet.rail_algebra): the two content hooks now DELEGATE to a Bind + Door pair —
recheck_against_context = EffectKeyOneShot.recheck (the kernel context-bind: the token bound to
THIS transaction + the runtime effect == the signed Cart), and produce_capability / on_rejected =
ExternalEnforcer.enforce / .decline (the required Check Run concluded success/failure; the
protected-branch ruleset is the EXTERNAL PEP). The merge rail's POLICY (the typed-data fence) is
enforced UPSTREAM at mandate resolution (the Role-B gate, see evals/github_railbridge) — so the
authorizer holds the Bind+Door half of the Composition; the full (Policy, Bind, Door) is assembled
at the rail's resolve seam. Binding-field content is the rail's (which fields bind), exactly as
role_b injects its gate predicates; the order + fail-closed stay in the algebra/template. This file
imports only signet-internal modules (no evals), keeping trusted code free of editable-rail deps.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

from .base import AuthorizationResult, Authorizer, ComponentOutcome, ScheduledComponent
from .. import chain
from ..models import ExecutionRequest, ExecutionToken
from ..rail_algebra import (Capability, Composition, Effect, EffectKeyOneShot, ExternalEnforcer,
                            MERGE_SCHEDULE, Phase, phase_scope)
from ..rail_algebra.schedule import BIND, DOOR


class GitHubRail(ABC):
    """The rail capability the enforcer holds: conclude a required Check Run."""

    @abstractmethod
    def open_check(self, chain_hash: str, head_sha: str) -> str:
        ...

    @abstractmethod
    def conclude(self, check_run_id: str, chain_hash: str, conclusion: str) -> str:
        ...


class MockGitHubRail(GitHubRail):
    """A stand-in for the GitHub Checks API. It trusts ONLY check runs the enforcer
    opened bound to a chain_hash, and refuses to conclude one not so bound or already
    concluded (consume-once) -- the analogue of MockPaymentAdapter."""

    def __init__(self) -> None:
        # check_run_id -> [chain_hash, head_sha, conclusion|None, used]
        self._issued: Dict[str, list] = {}
        self.conclusions: list = []   # (check_run_id, head_sha, conclusion) audit trail

    def open_check(self, chain_hash: str, head_sha: str) -> str:
        check_run_id = "check_" + uuid.uuid4().hex[:12]
        self._issued[check_run_id] = [chain_hash, head_sha, None, False]
        return check_run_id

    def conclude(self, check_run_id: str, chain_hash: str, conclusion: str) -> str:
        rec = self._issued.get(check_run_id)
        if rec is None:
            raise PermissionError("No such check run: rail refuses (agent has no capability).")
        bound_hash, head_sha, _, used = rec
        if used:
            raise PermissionError("Check run already concluded (consume-once).")
        if bound_hash != chain_hash:
            raise PermissionError("Check run not bound to this transaction.")
        rec[2], rec[3] = conclusion, True
        self.conclusions.append((check_run_id, head_sha, conclusion))
        return check_run_id


def _parse_head_sha(recipient: str) -> str:
    """Extract head_sha from a recipient `merge_pr:{repo}#{pr}->{base}@{head_sha}`."""
    return recipient.rsplit("@", 1)[-1] if "@" in recipient else ""


class GitHubRailBridge(Authorizer):
    rail = "github"
    # RESOLUTION rail: the Policy (the typed-data fence) fired UPSTREAM at mandate resolution
    # (RESOLVE); this authorizer holds the Bind + Door, both at AUTHORIZE. The full declared
    # schedule across the split Composition (verified faithful in tests/test_rail_schedule.py).
    SCHEDULE = MERGE_SCHEDULE

    def __init__(self, verifier, enforcer_verify_key: str,
                 github_rail: Optional[GitHubRail] = None):
        super().__init__(verifier, enforcer_verify_key)
        self._rail = github_rail or MockGitHubRail()
        self._last_check_ref: Optional[str] = None
        # ---- the rail algebra Bind + Door (the Policy half lives upstream at resolution) ----
        self.bind = EffectKeyOneShot(recheck_fn=self._chain_bound)
        self.door = ExternalEnforcer(perform=self._conclude_success,
                                     decline=self._conclude_failure)
        # COMPOSED rail: declaring a Composition with the MERGE_SCHEDULE routes authorize() through
        # the schedule-driven path (base.run_phase). Policy is None HERE because the merge Policy
        # fires UPSTREAM at RESOLVE (the resolver seam), not at this authorizer's AUTHORIZE phase
        # (PHASE-ISOLATION). The driven phase is AUTHORIZE = [Bind, Door] (PROMOTION.md).
        self.composition = Composition(policy=None, bind=self.bind, door=self.door,
                                       name="github", schedule=MERGE_SCHEDULE)

    @staticmethod
    def _context_matches_cart(req: ExecutionRequest) -> bool:
        """The runtime effect must equal the authorized (signed) Cart effect on the
        binding fields: recipient (effect_class + repo#pr->base@head_sha) and the
        diff_hash destination. Independent of the kernel's own step-7 check."""
        c, x = req.cart, req.context
        return (c.recipient == x.recipient
                and c.action == x.action
                and c.destination_account == x.destination_account)

    @staticmethod
    def _well_formed(req: ExecutionRequest) -> bool:
        x = req.context
        return (x.rail == "github"
                and isinstance(x.recipient, str)
                and x.recipient.startswith(x.action + ":")
                and "@" in x.recipient)

    # -- Bind content: which fields bind (the kernel context-bind / TOCTOU gate) --
    def _chain_bound(self, token: ExecutionToken, req: ExecutionRequest) -> bool:
        """The token is bound to THIS exact transaction AND the runtime effect matches the approved
        Cart (effect_class, recipient incl. head_sha, destination_account). Returns bool; the
        algebra's EffectKeyOneShot.recheck fails closed if this raises."""
        recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
        return (recomputed == token.chain_hash
                and self._well_formed(req)
                and self._context_matches_cart(req))

    # -- Door content: conclude the required Check Run (the EXTERNAL branch-protection gate) --
    def _conclude_success(self, cap: Capability) -> str:
        req, token = cap.effect, cap.handle
        head_sha = _parse_head_sha(req.context.recipient)
        recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
        self._last_check_ref = self._rail.open_check(token.chain_hash, head_sha)
        return self._rail.conclude(self._last_check_ref, recomputed, "success")

    def _conclude_failure(self, cap: Capability, reason: str) -> str:
        req, token = cap.effect, cap.handle
        head_sha = _parse_head_sha(req.context.recipient)
        check_run_id = self._rail.open_check(token.chain_hash, head_sha)
        self._rail.conclude(check_run_id, token.chain_hash, "failure")
        return check_run_id

    def _cap(self, token: ExecutionToken, req: ExecutionRequest) -> Capability:
        return Capability(effect=req, lifecycle=self.bind.lifecycle(), handle=token)

    # -- the Bind + Door invocations as schedule components (the single source of truth, shared by
    #    the driven path and the legacy hooks; the caller establishes the phase_scope) --
    def _bind_outcome(self, token: ExecutionToken, req: ExecutionRequest) -> ComponentOutcome:
        """Bind @ AUTHORIZE: EffectKeyOneShot.recheck (fail-closed on any mismatch)."""
        if self.bind.recheck(token, req):
            return ComponentOutcome(True, "bound to this transaction")
        return ComponentOutcome(False, "Effect/context mismatch vs the approved Cart "
                                       "(head_sha/base/path substitution or unbound token).")

    def _door_result(self, token: ExecutionToken,
                     req: ExecutionRequest) -> AuthorizationResult:
        """Door @ AUTHORIZE: conclude the required Check Run as success (the EXTERNAL branch-
        protection gate). Returns the final AuthorizationResult; never calls on_rejected."""
        self._last_check_ref = None
        outcome = self.door.enforce(self._cap(token, req))
        if isinstance(outcome, Effect):
            return AuthorizationResult(
                True, "Check Run concluded success; protected-branch merge gate satisfied.",
                payment_ref=outcome.ref, rail=self.rail)
        return AuthorizationResult(False, outcome.reason,
                                   payment_ref=self._last_check_ref, rail=self.rail)

    # -- COMPOSED path: the components base.run_phase drives at AUTHORIZE, in MERGE_SCHEDULE order
    #    (private plumbing — the public content surface stays the two hooks) --
    def _components_for(self, phase, token: ExecutionToken, req: ExecutionRequest):
        if phase is not Phase.AUTHORIZE:
            return []                                       # Policy is owned at RESOLVE, not here
        return [
            ScheduledComponent(BIND, lambda: self._bind_outcome(token, req)),
            ScheduledComponent(DOOR, lambda: self._door_result(token, req), is_door=True),
        ]

    def on_rejected(self, token: ExecutionToken, req: ExecutionRequest, reason: str) -> None:
        """Rail-native record of a rejection: conclude the required Check Run as FAILURE, bound to
        the token's chain_hash (so the protected merge demonstrably did NOT proceed)."""
        self.door.decline(self._cap(token, req), reason)

    # -- the two template hooks remain DEFINED (the ABC requires them; conformance asserts their
    #    presence). The composed rail no longer reaches them via authorize() — they delegate to the
    #    same components so there is ONE implementation of the Bind/Door content (no drift). --
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        with phase_scope(Phase.AUTHORIZE):                  # Bind @ AUTHORIZE (MERGE_SCHEDULE)
            out = self._bind_outcome(token, req)
        return out.ok, out.reason

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        with phase_scope(Phase.AUTHORIZE):                  # Door @ AUTHORIZE (MERGE_SCHEDULE)
            return self._door_result(token, req)
