"""The shared vocabulary of the rail algebra: Features, Verdict, Capability, the Lifecycle /
Soundness enums, the Door's Effect | Blocked, the Composition tuple, and the cross-cutting
PROVENANCE-MONOTONICITY audit.

This module is PURE — it imports nothing from `signet.*` or `evals.*`. The three strategy
interfaces (Policy / Bind / Door) and their variants live alongside it, but the *types* a rail
exchanges with the framework are defined here so the trust direction stays one-way: rails depend on
the algebra, never the reverse (see IMPLEMENTATION.md §4).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

# ---- provenance labels (kept identical to evals._rail_core.policy_spec's OWN/UNTRUSTED strings so a
#      DeclarativeMembership policy can reuse an AttrDecl's provenance verbatim, with NO import) ----
OWN = "own"
UNTRUSTED = "untrusted"


# ============================================================================
# Features — a typed, PROVENANCED projection of (world, candidate)
# ============================================================================
@dataclass(frozen=True)
class Features:
    """What `Policy.project` produces and `Policy.decide` consumes: a name->value map plus the
    provenance (OWN | UNTRUSTED) of each named feature. Provenance rides WITH the data so the
    framework's PROVENANCE-MONOTONICITY audit can reason about which features may permit."""
    values: Mapping[str, Any] = field(default_factory=dict)
    provenance: Mapping[str, str] = field(default_factory=dict)

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    def untrusted_names(self) -> Tuple[str, ...]:
        return tuple(n for n, p in self.provenance.items() if p == UNTRUSTED)

    def with_values(self, **overrides: Any) -> "Features":
        merged = dict(self.values)
        merged.update(overrides)
        return replace(self, values=merged)


# ============================================================================
# Verdict — the PDP outcome: ALLOW | DENY(reason) | ESCALATE(candidates)
# ============================================================================
ALLOW = "allow"
DENY = "deny"
ESCALATE = "escalate"


@dataclass(frozen=True)
class Verdict:
    kind: str                                  # ALLOW | DENY | ESCALATE
    reason: str = ""
    candidates: Tuple[Any, ...] = ()

    @property
    def is_allow(self) -> bool:
        return self.kind == ALLOW

    @property
    def is_deny(self) -> bool:
        return self.kind == DENY

    @property
    def is_escalate(self) -> bool:
        return self.kind == ESCALATE


def allow(reason: str = "") -> Verdict:
    return Verdict(ALLOW, reason)


def deny(reason: str) -> Verdict:
    return Verdict(DENY, reason)


def escalate(candidates=(), reason: str = "") -> Verdict:
    return Verdict(ESCALATE, reason, tuple(candidates))


# ============================================================================
# Bind — lifecycle of a capability + what it commits to
# ============================================================================
# Lifecycle
ONE_SHOT = "one_shot"        # consume-once (kernel consume-once on chain_hash)
TTL = "ttl"                  # valid until an expiry
METERED = "metered"          # debited against an aggregate ledger
LIFECYCLES = (ONE_SHOT, TTL, METERED)


@dataclass(frozen=True)
class Capability:
    """What a Bind commits to: a single effect, the lifecycle, an optional expiry, and an opaque
    handle (the kernel ExecutionToken, a scoped JWT, ...). `ok`/`reason` let `commit` fail closed
    without raising."""
    effect: Any = None
    lifecycle: str = ONE_SHOT
    handle: Any = None
    exp: Optional[str] = None
    ok: bool = True
    reason: str = ""


# ============================================================================
# Door — the PEP mechanism + its honest soundness
# ============================================================================
# Soundness — how unbypassable the door actually is (ONLY-DOOR-OR-DECLARE).
ADVISORY = "advisory"        # an ambient path exists; the door only observes/logs
CUSTODY = "custody"          # the enforcer is sole holder of a credential (broker/keyholder)
SOLE_PATH = "sole_path"      # OS interposition: the resource is unreachable except via the door
EXTERNAL = "external"        # an external system (branch protection, a PSP) is the real PEP
SOUNDNESS = (ADVISORY, CUSTODY, SOLE_PATH, EXTERNAL)


@dataclass(frozen=True)
class Effect:
    """A door PERMITTED and performed (or admitted) the effect."""
    detail: str = ""
    ref: Optional[str] = None


@dataclass(frozen=True)
class Blocked:
    """A door REFUSED the effect (fail-closed)."""
    reason: str = ""
    ref: Optional[str] = None


# ============================================================================
# Composition — (policy, bind, door)
# ============================================================================
@dataclass(frozen=True)
class Composition:
    policy: Any
    bind: Any
    door: Any
    name: str = ""

    def describe(self) -> dict:
        return {
            "name": self.name,
            "policy": getattr(self.policy, "name", type(self.policy).__name__),
            "bind": type(self.bind).__name__,
            "bind_lifecycle": self.bind.lifecycle(),
            "door": type(self.door).__name__,
            "door_soundness": getattr(self.door, "soundness", "?"),
        }


# ============================================================================
# PROVENANCE-MONOTONICITY — no UNTRUSTED feature may reach an ALLOW
# ============================================================================
def provenance_audit(policy) -> List[str]:
    """Assert the cross-cutting law: an ALLOW may depend ONLY on OWN features; an UNTRUSTED feature
    may push a verdict toward DENY/ESCALATE but never ENABLE an allow.

    Behavioral test (no static analysis of the policy body needed): take the policy's own
    `allow_witness()` (a Features vector it ALLOWs); NEUTRALIZE every untrusted feature (set it to
    the policy's most-restrictive 'no claim' value via `neutralize_untrusted`); re-decide. If the
    ALLOW survives, the allow did not rest on untrusted data (correct). If neutralizing untrusted
    features flips the verdict away from ALLOW, the ALLOW *depended* on attacker-controlled data — a
    violation. A policy that never allows (allow_witness is None) trivially holds.

    Returns the list of violation strings (empty == the policy is provenance-monotone).
    """
    violations: List[str] = []
    witness = policy.allow_witness()
    if witness is None:
        return violations                                  # never allows -> nothing can leak in
    v = policy.decide(witness)
    if not v.is_allow:
        return [f"policy {getattr(policy, 'name', '?')!r}: allow_witness() is not ALLOW "
                f"(got {v.kind}) — audit contract violated"]
    neutral = policy.neutralize_untrusted(witness)
    vn = policy.decide(neutral)
    if not vn.is_allow:
        untrusted = list(witness.untrusted_names()) or [
            n for n, p in policy.feature_provenance().items() if p == UNTRUSTED]
        violations.append(
            f"policy {getattr(policy, 'name', '?')!r}: ALLOW depends on UNTRUSTED feature(s) "
            f"{untrusted} — neutralizing them flips {v.kind}->{vn.kind} (untrusted reached an ALLOW)")
    return violations
