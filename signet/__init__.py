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
    # The on-ramp facade (the blessed DX surface, spec §5). ABSOLUTE module path: the implementation
    # lives with the demo rails it wires (examples/onramp). Lazy like everything here, so `import
    # signet` stays light and a core-only checkout pays nothing — `signet.guard` triggers the import
    # only on first access (and reports a teaching error if the examples tree / a rail extra is absent).
    "guard": "examples.onramp", "Mandate": "examples.onramp", "SignetConfig": "examples.onramp",
}

__all__ = list(_EXPORTS)


def __getattr__(name):
    mod = _EXPORTS.get(name)
    if mod is None:
        raise AttributeError(f"module 'signet' has no attribute {name!r}")
    # Relative paths (".verifier") resolve within `signet`; an absolute path ("examples.onramp") is
    # imported as-is (the on-ramp facade re-export — implementation kept out of the kernel package).
    pkg = __name__ if mod.startswith(".") else None
    value = getattr(import_module(mod, pkg), name)
    globals()[name] = value          # cache: next access skips __getattr__
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
