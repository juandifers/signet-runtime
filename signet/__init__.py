"""Signet Runtime -- runtime enforcement for AP2-style agent payment mandates.

Top-level names are LAZY (PEP 562): `import signet` stays light so the `signet hook`
CLI hot path (<100ms budget) and a core-only install (`pip install signet-runtime`,
no extras) never pay for — or require — pydantic-model construction, fastapi, or xrpl.
`from signet import Verifier` etc. behaves exactly as before.
"""
from importlib import import_module

_EXPORTS = {
    "Verifier": ".verifier",
    "PolicyEngine": ".policy", "Policy": ".policy",
    "NonceRegistry": ".nonce",
    "RevocationRegistry": ".revocation",
    "ReceiptLog": ".receipts",
    "IntentMandate": ".models", "CartMandate": ".models", "PaymentMandate": ".models",
    "RuntimeContext": ".models", "ExecutionRequest": ".models", "ExecutionToken": ".models",
    "Decision": ".models", "Receipt": ".models",
}

__all__ = list(_EXPORTS)


def __getattr__(name):
    mod = _EXPORTS.get(name)
    if mod is None:
        raise AttributeError(f"module 'signet' has no attribute {name!r}")
    value = getattr(import_module(mod, __name__), name)
    globals()[name] = value          # cache: next access skips __getattr__
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
