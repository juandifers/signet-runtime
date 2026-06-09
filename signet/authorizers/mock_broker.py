"""Role 2 -- the broader, rail-agnostic guardrail: credential custody.

For rails where you cannot be a cryptographic co-signer (cards, ACH, PSP APIs),
the enforcer becomes the *sole holder* of the funding credential. The agent
holds nothing capable of moving money -- only the right to request execution.
The broker mints a one-time, intent-bound credential ONLY after the verifier
approves, and the payment adapter refuses any call lacking a valid minted
credential. Bypass is impossible not by cryptography but because the agent has
no usable credential.
"""
from __future__ import annotations

import hmac
import uuid
from hashlib import sha256
from typing import Dict, Tuple

from .base import AuthorizationResult, Authorizer
from ..models import ExecutionRequest, ExecutionToken


class MockPaymentAdapter:
    """A stand-in PSP. It trusts ONLY minted credentials, never the agent."""

    def __init__(self) -> None:
        # credential_id -> (chain_hash, used)
        self._issued: Dict[str, list] = {}

    def _register(self, credential_id: str, chain_hash: str) -> None:
        self._issued[credential_id] = [chain_hash, False]

    def execute(self, credential_id: str, chain_hash: str) -> str:
        rec = self._issued.get(credential_id)
        if rec is None:
            raise PermissionError("No such credential: adapter refuses (agent has no capability).")
        bound_hash, used = rec
        if used:
            raise PermissionError("Credential already used (consume-once).")
        if bound_hash != chain_hash:
            raise PermissionError("Credential not bound to this transaction.")
        rec[1] = True
        return "mockpay_tx_" + uuid.uuid4().hex[:10]


class MockCredentialBroker(Authorizer):
    rail = "mock"

    def __init__(self, verifier, enforcer_verify_key: str,
                 adapter: MockPaymentAdapter | None = None,
                 broker_secret: bytes = b"enforcer-only-secret"):
        super().__init__(verifier, enforcer_verify_key)
        self.adapter = adapter or MockPaymentAdapter()
        self._secret = broker_secret  # the credential-minting key the agent never has

    def _mint(self, chain_hash: str) -> str:
        # A one-time credential, cryptographically bound to the chain hash.
        credential_id = "cred_" + uuid.uuid4().hex[:12]
        mac = hmac.new(self._secret, (credential_id + chain_hash).encode(),
                       sha256).hexdigest()
        self.adapter._register(credential_id, chain_hash)
        return credential_id + ":" + mac

    # -- the two content hooks; the base template owns verify_token + the order --
    def recheck_against_context(self, token: ExecutionToken,
                                req: ExecutionRequest) -> Tuple[bool, str]:
        # The mock credential broker is rail-agnostic credential custody: it has no per-rail
        # effect-vs-context binding to re-check (the kernel already context-bound the token). It
        # mints ONLY on a valid token, which the template guarantees before this returns.
        return True, "ok"

    def produce_capability(self, token: ExecutionToken,
                           req: ExecutionRequest) -> AuthorizationResult:
        credential = self._mint(token.chain_hash)
        credential_id = credential.split(":")[0]
        try:
            payment_ref = self.adapter.execute(credential_id, token.chain_hash)
        except PermissionError as e:
            return AuthorizationResult(False, str(e), rail=self.rail)
        return AuthorizationResult(True, "Executed via brokered one-time credential.",
                                   payment_ref=payment_ref, rail=self.rail)
