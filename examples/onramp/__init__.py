"""Signet on-ramp — the blessed public surface for guarding a LangGraph tool (spec §5).

A stranger with a LangGraph tool wires Signet in ~10 lines, without reading the kernel, the seam, the
brokers, or the rail modules:

    from signet import guard, Mandate, SignetConfig

    mandate = (Mandate("support-bot", task_id="refund-001")
                 .allow_db("public.credits", ops=("select", "insert"))
                 .allow_egress("payments.internal")
                 .build())

    safe_db     = guard(db_tool, mandate)        # Tier 0 advisory (local dev default)
    safe_egress = guard(egress_tool, mandate)    # same mandate -> ONE shared session

STABLE: exactly `guard`, `Mandate`, `SignetConfig` (re-exported at top level as `signet.*`). Everything
else — the kernel, the seam, the rails, the brokers — is INTERNAL and may change.

FACADE ONLY: this adds no enforcement and changes no behavior; it constructs and wires the existing
pieces (see guard.py). The default is Tier 0 **advisory** and says so (SignetConfig.label()); make the
DB rail structural with `SignetConfig(tier=1, broker_socket=..., jwks_path=...)`. The egress rail is
advisory on this build (structural egress needs a netns — out of scope).

NOTE: the on-ramp wires the repo's demo rails (examples/refund_triage), so it is available when that
tree is on the path (the dev checkout). `Mandate`/`SignetConfig` are import-light; `guard()` pulls the
demo builders lazily and raises a teaching error if a rail's extra is missing.
"""
from .config import SignetConfig
from .errors import (MalformedTargetError, MissingRailExtraError, SignetOnRampError,
                     UnknownRailError)
from .guard import build_onramp_door, guard, guarded_door
from .mandate import Mandate

__all__ = [
    "guard", "Mandate", "SignetConfig",            # the blessed surface
    "guarded_door", "build_onramp_door",           # door access (stop/inspect; faithfulness driver)
    "SignetOnRampError", "UnknownRailError", "MalformedTargetError", "MissingRailExtraError",
]
