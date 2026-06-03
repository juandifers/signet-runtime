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
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional

from .base import AuthorizationResult, Authorizer
from .. import chain
from ..models import ExecutionRequest, ExecutionToken


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

    def __init__(self, verifier, enforcer_verify_key: str,
                 github_rail: Optional[GitHubRail] = None):
        self._verifier = verifier
        self._enforcer_vk = enforcer_verify_key
        self._rail = github_rail or MockGitHubRail()

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

    def authorize(self, token: ExecutionToken,
                  req: ExecutionRequest) -> AuthorizationResult:
        # 1. The authorizer refuses to act unless the enforcer token is valid. FIRST.
        if not self._verifier.verify_token(token, self._enforcer_vk):
            return AuthorizationResult(False, "Enforcer token invalid/expired.", rail=self.rail)

        # 2. Independent re-check: the token is bound to THIS exact transaction, and
        #    the runtime effect matches the approved Cart (effect_class, recipient
        #    incl. head_sha, destination_account). Fail closed on any mismatch.
        head_sha = _parse_head_sha(req.context.recipient)
        recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
        bound = (recomputed == token.chain_hash
                 and self._well_formed(req)
                 and self._context_matches_cart(req))

        check_run_id = self._rail.open_check(token.chain_hash, head_sha)
        if not bound:
            # Record a hard failure conclusion bound to the token's chain_hash; the
            # protected merge does NOT proceed.
            self._rail.conclude(check_run_id, token.chain_hash, "failure")
            return AuthorizationResult(
                False,
                "Effect/context mismatch vs the approved Cart "
                "(head_sha/base/path substitution or unbound token).",
                payment_ref=check_run_id, rail=self.rail)

        # 3. Conclude the required Check Run as success -> the protected-branch merge
        #    gate is satisfied. Only the enforcer can do this.
        try:
            ref = self._rail.conclude(check_run_id, recomputed, "success")
        except PermissionError as e:
            return AuthorizationResult(False, str(e), payment_ref=check_run_id, rail=self.rail)
        return AuthorizationResult(
            True, "Check Run concluded success; protected-branch merge gate satisfied.",
            payment_ref=ref, rail=self.rail)
