"""Thin FastAPI surface over the Signet runtime.

    uvicorn signet.api:app --reload
    # interactive docs at http://127.0.0.1:8000/docs

The proof of the system is in tests/ and demos/; this is the deployable seam.
Endpoints intentionally trust ONLY the verifier's decision -- the authorizer is
the only thing that turns a decision into a payment.
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from . import crypto
from .authorizers.mock_broker import MockCredentialBroker
from .builder import make_env
from .models import ExecutionRequest, Receipt
from .receipts import ReceiptLog

app = FastAPI(title="Signet Runtime", version="0.1.0")

# A single in-process environment for the PoC server.
_env = make_env()
_broker = MockCredentialBroker(_env.verifier, _env.enforcer_vk)
_receipts = ReceiptLog(_env.enforcer_sk, _env.enforcer_vk)


class RegisterKey(BaseModel):
    identity: str
    verify_key_hex: str


@app.get("/info")
def info():
    return {"service": "signet-runtime", "enforcer_verify_key": _env.enforcer_vk}


@app.post("/mandates/register-key")
def register_key(body: RegisterKey):
    _env.keystore.register(body.identity, body.verify_key_hex)
    return {"registered": body.identity}


@app.post("/mandates/{mandate_id}/revoke")
def revoke(mandate_id: str):
    _env.revocation.revoke(mandate_id)
    return {"revoked": mandate_id}


@app.post("/intents/evaluate")
def evaluate(req: ExecutionRequest):
    decision, token = _env.verifier.evaluate(req)
    return {"decision": decision.model_dump(mode="json"),
            "token": token.model_dump(mode="json") if token else None}


@app.post("/execute")
def execute(req: ExecutionRequest):
    decision, token = _env.verifier.evaluate(req)
    if not decision.approved:
        _receipts.append(execution_id="-", mandate_id=req.intent.mandate_id,
                         chain_hash=decision.chain_hash or "-",
                         policy_id=req.intent.policy_id, decision="blocked",
                         payment_status="not_executed", payment_ref=None,
                         rail=req.context.rail)
        return {"decision": decision.model_dump(mode="json"), "executed": False}
    result = _broker.authorize(token, req)
    receipt = _receipts.append(
        execution_id=token.execution_id, mandate_id=token.mandate_id,
        chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
        decision="approved",
        payment_status="executed" if result.executed else "failed",
        payment_ref=result.payment_ref, rail=result.rail)
    return {"decision": decision.model_dump(mode="json"),
            "executed": result.executed, "payment_ref": result.payment_ref,
            "receipt": receipt.model_dump(mode="json")}


@app.get("/receipts")
def list_receipts():
    return [r.model_dump(mode="json") for r in _receipts.all()]


@app.post("/receipts/verify")
def verify_receipt(receipt: Receipt):
    ok, reason = _receipts.verify(receipt)
    return {"valid": ok, "reason": reason}
