"""signet.rail_algebra — the rail algebra: rails COMPOSE three explicit, reusable strategy
interfaces instead of being bespoke per-rail code.

    Composition = (policy: Policy, bind: Bind, door: Door)

  * Policy (PDP)  — project(world, candidate) -> Features ; decide(features) -> Verdict
  * Bind   ([D])  — commit(effect) -> Capability ; lifecycle() ; recheck(cap, ctx) -> bool
  * Door   (PEP)  — soundness ; enforce(cap) -> Effect | Blocked

The module is a dependency LEAF: it imports nothing from `signet.*` or `evals.*`. The general
variants are SHAPES; rails inject their field-level content (the evaluator, the host matchers, the
Check Run handle, the proxy admission). Trusted code therefore never depends on editable rail code
(IMPLEMENTATION.md §4.4). The 10 kernel files are untouched (K0).
"""
from __future__ import annotations

from .types import (ADVISORY, ALLOW, Blocked, Capability, Composition, CUSTODY, DENY, Effect,
                    ESCALATE, EXTERNAL, Features, METERED, ONE_SHOT, OWN, SOLE_PATH, TTL, UNTRUSTED,
                    Verdict, allow, deny, escalate, provenance_audit)
from .policy import (AllowOnUntrustedContent, BasePolicy, Content, DeclarativeMembership,
                     PatternAllowlist, Quantitative)
from .bind import EffectKeyOneShot, InlineCapability, MeteredLedger
from .door import AdvisoryInline, ExternalEnforcer, KeyholderBroker, NetworkSolePath
from .payment import payment_composition

__all__ = [
    # types
    "Features", "Verdict", "Capability", "Composition", "Effect", "Blocked",
    "allow", "deny", "escalate", "provenance_audit",
    "OWN", "UNTRUSTED", "ALLOW", "DENY", "ESCALATE",
    "ONE_SHOT", "TTL", "METERED", "ADVISORY", "CUSTODY", "SOLE_PATH", "EXTERNAL",
    # policy variants
    "BasePolicy", "DeclarativeMembership", "PatternAllowlist", "Quantitative",
    "Content", "AllowOnUntrustedContent",
    # bind variants
    "EffectKeyOneShot", "InlineCapability", "MeteredLedger",
    # door variants
    "ExternalEnforcer", "KeyholderBroker", "NetworkSolePath", "AdvisoryInline",
    # payment composition stub
    "payment_composition",
]
