"""Infra-as-code rail-bridge authorizer — the THIRD authorizer (after GitHub and deploy) proving the
kernel is rail-agnostic: it is a NEW file implementing `base.py`, with ZERO edits to the verifier or
any other kernel module.

The irreversible step for "apply a change-set to a target account/cluster" is the enforcer
concluding a required InfraApplyGate as `success` -- the gate a real terraform/k8s controller would
wait on. The agent holds no capability to conclude that gate; only this authorizer does, and only
after the verifier approves and the effect re-checks against `req.context`. The real apply is NOT
implemented (offline-property discipline, like the DeployGate / the XRPL co-signer): the property we
prove is that the enforcer is the SOLE holder of the apply capability and that the gate refuses to
conclude any apply not bound to this token's `chain_hash` (consume-once).

Invariants (CLAUDE.md): base.py does NOT enforce verify_token -- so authorize() (the FINAL template
in base.py) calls it first. Then this authorizer INDEPENDENTLY re-checks the effect against
`req.context` (effect_class, recipient incl. the resource-SET hash + account/cluster, the plan
destination) and that the token is bound to THIS exact transaction, refusing on any mismatch (fail
closed). A post-auth ADD/REMOVE of one resource changes the recipient's set-hash and is refused. No
rail logic leaks into the kernel.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

from .base import AuthorizationResult, Authorizer
from .. import chain
from ..models import ExecutionRequest, ExecutionToken


class InfraApplyGate(ABC):
    """The rail capability the enforcer holds: conclude a required infra-apply gate."""

    @abstractmethod
    def open_gate(self, chain_hash: str, plan_hash: str) -> str:
        ...

    @abstractmethod
    def conclude(self, gate_id: str, chain_hash: str, conclusion: str) -> str:
        ...


class MockInfraApplyGate(InfraApplyGate):
    """A stand-in for a real apply controller (a terraform-cloud / Atlantis / a signed-apply service).
    It trusts ONLY gates the enforcer opened bound to a chain_hash, and refuses to conclude one not so
    bound or already concluded (consume-once) -- the analogue of MockDeployGate / MockGitHubRail. NO
    live terraform/k8s apply is performed; concluding the gate IS the (mock) irreversible step."""

    def __init__(self) -> None:
        # gate_id -> [chain_hash, plan_hash, conclusion|None, used]
        self._issued: Dict[str, list] = {}
        self.conclusions: list = []   # (gate_id, plan_hash, conclusion) audit trail

    def open_gate(self, chain_hash: str, plan_hash: str) -> str:
        gate_id = "gate_" + uuid.uuid4().hex[:12]
        self._issued[gate_id] = [chain_hash, plan_hash, None, False]
        return gate_id

    def conclude(self, gate_id: str, chain_hash: str, conclusion: str) -> str:
        rec = self._issued.get(gate_id)
        if rec is None:
            raise PermissionError("No such infra-apply gate: rail refuses (agent has no capability).")
        bound_hash, plan_hash, _, used = rec
        if used:
            raise PermissionError("Infra-apply gate already concluded (consume-once).")
        if bound_hash != chain_hash:
            raise PermissionError("Infra-apply gate not bound to this transaction.")
        rec[2], rec[3] = conclusion, True
        self.conclusions.append((gate_id, plan_hash, conclusion))
        return gate_id


def _parse_plan_hash(recipient: str) -> str:
    """Extract the plan hash from a recipient
    `infra_apply:{account}@{cluster}#{resource_set_hash}/{plan_hash}`."""
    if "/" not in recipient:
        return ""
    return recipient.rsplit("/", 1)[-1]


class InfraRailBridge(Authorizer):
    rail = "infra"

    def __init__(self, verifier, enforcer_verify_key: str,
                 apply_gate: Optional[InfraApplyGate] = None):
        super().__init__(verifier, enforcer_verify_key)
        self._rail = apply_gate or MockInfraApplyGate()

    @staticmethod
    def _context_matches_cart(req: ExecutionRequest) -> bool:
        """The runtime effect must equal the authorized (signed) Cart effect on the binding fields:
        recipient (effect_class + account@cluster#resource_set_hash/plan_hash) and the plan-fingerprint
        destination. Independent of the kernel's own step-7 check."""
        c, x = req.cart, req.context
        return (c.recipient == x.recipient
                and c.action == x.action
                and c.destination_account == x.destination_account)

    @staticmethod
    def _well_formed(req: ExecutionRequest) -> bool:
        x = req.context
        return (x.rail == "infra"
                and isinstance(x.recipient, str)
                and x.recipient.startswith(x.action + ":")
                and "@" in x.recipient
                and "#" in x.recipient
                and "/" in x.recipient)

    # -- the content hooks; base.Authorizer.authorize owns verify_token + the order --
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        """Independent re-check (no side effect): the token is bound to THIS exact transaction, and
        the runtime effect matches the approved Cart (effect_class, recipient incl. the resource-SET
        hash + account/cluster, plan destination). Fail closed on any mismatch -- including a single
        added/removed resource (it changes the set-hash inside the recipient)."""
        recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
        bound = (recomputed == token.chain_hash
                 and self._well_formed(req)
                 and self._context_matches_cart(req))
        if not bound:
            return (False, "Effect/context mismatch vs the approved Cart "
                           "(resource-set/account/cluster/plan substitution or unbound token).")
        return True, "bound to this transaction"

    def on_rejected(self, token: ExecutionToken, req: ExecutionRequest, reason: str) -> None:
        """Preserve the rail-native record: conclude the apply gate as FAILURE, bound to the token's
        chain_hash (so the apply demonstrably did NOT proceed)."""
        plan_hash = _parse_plan_hash(req.context.recipient)
        gate_id = self._rail.open_gate(token.chain_hash, plan_hash)
        self._rail.conclude(gate_id, token.chain_hash, "failure")

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        """Conclude the required infra-apply gate as success -> the apply gate is satisfied. Only the
        enforcer can do this. Reached ONLY after both guards pass."""
        plan_hash = _parse_plan_hash(req.context.recipient)
        recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
        gate_id = self._rail.open_gate(token.chain_hash, plan_hash)
        try:
            ref = self._rail.conclude(gate_id, recomputed, "success")
        except PermissionError as e:
            return AuthorizationResult(False, str(e), payment_ref=gate_id, rail=self.rail)
        return AuthorizationResult(
            True, "Infra-apply gate concluded success; apply gate satisfied.",
            payment_ref=ref, rail=self.rail)
