"""Deploy/promote rail-bridge authorizer — Role 2-style credential custody for an infra rail, and
the SECOND authorizer (after GitHub) proving the kernel is rail-agnostic: it is a NEW file
implementing `base.py`, with ZERO edits to the verifier or any other kernel module.

The irreversible step for "promote an artifact to an environment" is the enforcer concluding a
required deploy gate as `success` -- the gate the environment's promotion ruleset waits on. The
agent holds no capability to conclude that gate; only this authorizer does, and only after the
verifier approves and the effect re-checks against `req.context`. This mirrors `mock_broker.py`
and `github_railbridge.py`: the enforcer is the sole holder of the rail capability, and the rail
(`DeployGate`) refuses to conclude any gate not bound to this token's `chain_hash`.

Invariants (CLAUDE.md): base.py does NOT enforce verify_token -- so authorize() calls it as its
FIRST line. Then it INDEPENDENTLY re-checks the effect against `req.context` (effect_class,
recipient incl. artifact_digest + environment, destination_account) and that the token is bound to
THIS exact transaction, refusing on any mismatch (fail closed). No rail logic leaks into the
kernel.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

from .base import AuthorizationResult, Authorizer
from .. import chain
from ..models import ExecutionRequest, ExecutionToken


class DeployGate(ABC):
    """The rail capability the enforcer holds: conclude a required deploy/promotion gate."""

    @abstractmethod
    def open_gate(self, chain_hash: str, artifact_digest: str) -> str:
        ...

    @abstractmethod
    def conclude(self, gate_id: str, chain_hash: str, conclusion: str) -> str:
        ...


class MockDeployGate(DeployGate):
    """A stand-in for a real promotion controller (Argo/Spinnaker/a signed-promotion service). It
    trusts ONLY gates the enforcer opened bound to a chain_hash, and refuses to conclude one not
    so bound or already concluded (consume-once) -- the analogue of MockPaymentAdapter /
    MockGitHubRail."""

    def __init__(self) -> None:
        # gate_id -> [chain_hash, artifact_digest, conclusion|None, used]
        self._issued: Dict[str, list] = {}
        self.conclusions: list = []   # (gate_id, artifact_digest, conclusion) audit trail

    def open_gate(self, chain_hash: str, artifact_digest: str) -> str:
        gate_id = "gate_" + uuid.uuid4().hex[:12]
        self._issued[gate_id] = [chain_hash, artifact_digest, None, False]
        return gate_id

    def conclude(self, gate_id: str, chain_hash: str, conclusion: str) -> str:
        rec = self._issued.get(gate_id)
        if rec is None:
            raise PermissionError("No such deploy gate: rail refuses (agent has no capability).")
        bound_hash, artifact_digest, _, used = rec
        if used:
            raise PermissionError("Deploy gate already concluded (consume-once).")
        if bound_hash != chain_hash:
            raise PermissionError("Deploy gate not bound to this transaction.")
        rec[2], rec[3] = conclusion, True
        self.conclusions.append((gate_id, artifact_digest, conclusion))
        return gate_id


def _parse_artifact_digest(recipient: str) -> str:
    """Extract the artifact digest from a recipient
    `deploy:{service}@{env}#{artifact_digest}/{config_hash}`."""
    if "#" not in recipient:
        return ""
    after = recipient.rsplit("#", 1)[-1]
    return after.split("/", 1)[0] if "/" in after else after


class DeployRailBridge(Authorizer):
    rail = "deploy"

    def __init__(self, verifier, enforcer_verify_key: str,
                 deploy_gate: Optional[DeployGate] = None):
        super().__init__(verifier, enforcer_verify_key)
        self._rail = deploy_gate or MockDeployGate()

    @staticmethod
    def _context_matches_cart(req: ExecutionRequest) -> bool:
        """The runtime effect must equal the authorized (signed) Cart effect on the binding
        fields: recipient (effect_class + service@env#digest/config) and the config-fingerprint
        destination. Independent of the kernel's own step-7 check."""
        c, x = req.cart, req.context
        return (c.recipient == x.recipient
                and c.action == x.action
                and c.destination_account == x.destination_account)

    @staticmethod
    def _well_formed(req: ExecutionRequest) -> bool:
        x = req.context
        return (x.rail == "deploy"
                and isinstance(x.recipient, str)
                and x.recipient.startswith(x.action + ":")
                and "@" in x.recipient
                and "#" in x.recipient)

    # -- the content hooks; base.Authorizer.authorize owns verify_token + the order --
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        """Independent re-check (no side effect): the token is bound to THIS exact transaction, and
        the runtime effect matches the approved Cart (effect_class, recipient incl. artifact_digest
        + environment, destination_account). Fail closed on any mismatch."""
        recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
        bound = (recomputed == token.chain_hash
                 and self._well_formed(req)
                 and self._context_matches_cart(req))
        if not bound:
            return (False, "Effect/context mismatch vs the approved Cart "
                           "(artifact-digest/environment/config substitution or unbound token).")
        return True, "bound to this transaction"

    def on_rejected(self, token: ExecutionToken, req: ExecutionRequest, reason: str) -> None:
        """Preserve the rail-native record: conclude the deploy gate as FAILURE, bound to the
        token's chain_hash (so the promotion demonstrably did NOT proceed)."""
        artifact_digest = _parse_artifact_digest(req.context.recipient)
        gate_id = self._rail.open_gate(token.chain_hash, artifact_digest)
        self._rail.conclude(gate_id, token.chain_hash, "failure")

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        """Conclude the required deploy gate as success -> the promotion gate is satisfied. Only the
        enforcer can do this. Reached ONLY after both guards pass."""
        artifact_digest = _parse_artifact_digest(req.context.recipient)
        recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
        gate_id = self._rail.open_gate(token.chain_hash, artifact_digest)
        try:
            ref = self._rail.conclude(gate_id, recomputed, "success")
        except PermissionError as e:
            return AuthorizationResult(False, str(e), payment_ref=gate_id, rail=self.rail)
        return AuthorizationResult(
            True, "Deploy gate concluded success; promotion gate satisfied.",
            payment_ref=ref, rail=self.rail)
