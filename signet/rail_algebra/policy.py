"""Policy (the PDP): "is this effect permitted?"

A Policy PROJECTS (world, candidate) -> Features (typed + provenanced) and DECIDES Features ->
Verdict (ALLOW | DENY(reason) | ESCALATE). The general variants here are SHAPES; the rail-specific
content (which membership table, which host patterns, which evaluator) is INJECTED, so this module
imports nothing from `signet.*` or `evals.*` — the algebra stays a leaf in the dependency graph and
trusted code never depends on editable rail code (IMPLEMENTATION.md §4.4). Injecting the backend is
the same discipline `evals._rail_core.role_b` already uses for its `within_allowlist`/`within_fence`
gate predicates: the framework owns the control flow; the rail supplies the field-level content.

Variants:
  * DeclarativeMembership — the typed-data fence: reuses an injected evaluate_allowlist /
    evaluate_fence over a PolicySpec (the merge/deploy/infra rails' shared evaluator). All features
    OWN, so it is provenance-monotone by construction.
  * PatternAllowlist — host/glob membership + a raw-literal resolution hook (the egress rail). The
    agent-supplied host string is UNTRUSTED and may only NARROW; the OWN ceiling/grant/trusted-
    resolution booleans are what PERMIT — the subtle provenance case (§4.3).
  * Quantitative — thresholds over an aggregate (STUB: a single cap comparison; the atomic ledger
    that would feed it is named, not built).
  * Content — scan payload, DENY-on-match (STUB: substring match, no TLS termination). Correct:
    untrusted payload may only deny. `AllowOnUntrustedContent` is the deliberately-WRONG twin the
    provenance audit must FLAG (it ALLOWs on an untrusted match).
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from .types import (Features, OWN, UNTRUSTED, Verdict, allow, deny)


# ============================================================================
# base — supplies the audit contract every variant shares
# ============================================================================
class BasePolicy:
    name: str = "policy"
    # subclasses declare each feature's provenance + a neutral ("no claim") value for untrusted ones.
    PROVENANCE: Dict[str, str] = {}
    NEUTRAL: Dict[str, Any] = {}

    def feature_provenance(self) -> Dict[str, str]:
        return dict(self.PROVENANCE)

    def neutralize_untrusted(self, features: Features) -> Features:
        """Set every UNTRUSTED feature to its most-restrictive 'no claim' value. OWN features are
        untouched — so a provenance-monotone policy's ALLOW (which rests only on OWN features)
        survives, while a policy that leaned on untrusted data loses its ALLOW (-> flagged)."""
        prov = self.feature_provenance()
        out = dict(features.values)
        for name, p in prov.items():
            if p == UNTRUSTED:
                out[name] = self.NEUTRAL.get(name, None)
        return Features(out, dict(features.provenance) or prov)

    def allow_witness(self) -> Optional[Features]:
        return None                                        # default: no example -> audit is vacuous

    # subclasses MUST implement:
    def project(self, world, candidate) -> Features:       # pragma: no cover - interface
        raise NotImplementedError

    def decide(self, features: Features) -> Verdict:       # pragma: no cover - interface
        raise NotImplementedError


# ============================================================================
# DeclarativeMembership — the typed-data fence (merge / deploy / infra)
# ============================================================================
class DeclarativeMembership(BasePolicy):
    """Decide over an injected PolicySpec using the rail's SHARED evaluator (evaluate_allowlist /
    evaluate_fence). `schema` is a tuple of AttrDecls (duck-typed: `.name`, `.provenance`) — every
    fence/allowlist attribute is OWN (the rail's own load gate already refuses an UNTRUSTED one), so
    this policy is provenance-monotone. The two layers stay distinct (`within_allowlist` /
    `within_fence`) so a rail's gate keeps its off-allowlist vs off-fence cause strings."""

    def __init__(self, *, name: str, schema, spec,
                 project_attrs: Callable[[Any, Any], Dict[str, Any]],
                 allowlist_fn: Callable[[Dict[str, Any], Any], bool],
                 fence_fn: Callable[[Dict[str, Any], Any], Tuple[bool, str]],
                 allow_witness_values: Optional[Dict[str, Any]] = None,
                 off_allowlist_reason: str = "off-allowlist",
                 off_fence_reason: str = "off-fence"):
        self.name = name
        self._schema = tuple(schema)
        self._spec = spec
        self._project_attrs = project_attrs
        self._allowlist_fn = allowlist_fn
        self._fence_fn = fence_fn
        self._witness_values = allow_witness_values
        self._off_allow = off_allowlist_reason
        self._off_fence = off_fence_reason

    @property
    def PROVENANCE(self) -> Dict[str, str]:                 # type: ignore[override]
        return {d.name: getattr(d, "provenance", OWN) for d in self._schema}

    def _features(self, attrs: Dict[str, Any]) -> Features:
        return Features(dict(attrs), self.PROVENANCE)

    def project(self, world, candidate) -> Features:
        return self._features(self._project_attrs(world, candidate))

    # the two fence layers, exposed so a rail's gate predicates delegate here verbatim.
    def within_allowlist(self, features: Features) -> bool:
        return bool(self._allowlist_fn(dict(features.values), self._spec))

    def within_fence(self, features: Features) -> bool:
        ok, _ = self._fence_fn(dict(features.values), self._spec)
        return bool(ok)

    def decide(self, features: Features) -> Verdict:
        if not self.within_allowlist(features):
            return deny(self._off_allow)
        ok, disposition = self._fence_fn(dict(features.values), self._spec)
        if not ok:
            return deny(f"{self._off_fence} ({disposition})" if disposition else self._off_fence)
        return allow("within allowlist ∩ fence")

    def allow_witness(self) -> Optional[Features]:
        if self._witness_values is None:
            return None
        return self._features(self._witness_values)


# ============================================================================
# PatternAllowlist — host/glob membership + raw-literal resolution (egress)
# ============================================================================
class PatternAllowlist(BasePolicy):
    """Decide an outbound destination over OWN ceiling/grant booleans + a trusted raw-literal
    resolution. The agent-supplied host STRING is UNTRUSTED and never permits — it only selects
    which OWN pattern is tested. `project_features` (injected by the rail) computes the booleans by
    running the host-pattern matchers + the proxy's TRUSTED resolver; `decide` is pure boolean logic
    here, so the rail keeps its exact cause strings."""

    # OWN booleans are the permitting surface; the raw agent host is carried UNTRUSTED for the audit.
    PROVENANCE = {"agent_host": UNTRUSTED, "port": OWN, "is_ip_literal": OWN,
                  "in_standing": OWN, "in_mandate": OWN, "raw_ip_resolved_match": OWN}
    NEUTRAL = {"agent_host": ""}

    def __init__(self, *, name: str,
                 project_features: Callable[[Any, Any], Dict[str, Any]],
                 deny_standing_reason: str = "out-of-standing-policy",
                 deny_grant_reason: str = "out-of-mandate-destination",
                 allow_reason: str = "within mandate ∩ policy",
                 allow_literal_reason: str = "raw-ip matches a resolved allowlisted host"):
        self.name = name
        self._project_features = project_features
        self._deny_standing = deny_standing_reason
        self._deny_grant = deny_grant_reason
        self._allow = allow_reason
        self._allow_literal = allow_literal_reason

    def project(self, world, candidate) -> Features:
        return Features(dict(self._project_features(world, candidate)), dict(self.PROVENANCE))

    def decide(self, features: Features) -> Verdict:
        if features.get("is_ip_literal"):
            return (allow(self._allow_literal) if features.get("raw_ip_resolved_match")
                    else deny(self._deny_grant))
        if not features.get("in_standing"):
            return deny(self._deny_standing)
        if not features.get("in_mandate"):
            return deny(self._deny_grant)
        return allow(self._allow)

    def allow_witness(self) -> Optional[Features]:
        return Features({"agent_host": "api.allowed.test", "port": 443, "is_ip_literal": False,
                         "in_standing": True, "in_mandate": True, "raw_ip_resolved_match": False},
                        dict(self.PROVENANCE))


# ============================================================================
# Quantitative — thresholds over an aggregate (STUB)
# ============================================================================
class Quantitative(BasePolicy):
    """A single cap comparison: ALLOW iff the OWN aggregate feature is <= cap. STUB — the atomic
    multi-instance ledger that would supply a live aggregate is named (MeteredLedger), not built."""

    PROVENANCE = {"aggregate": OWN, "cap": OWN}

    def __init__(self, *, name: str = "quantitative", feature: str = "aggregate", cap: int = 0):
        self.name = name
        self._feature = feature
        self._cap = cap

    def project(self, world, candidate) -> Features:
        return Features({self._feature: candidate, "cap": self._cap},
                        {self._feature: OWN, "cap": OWN})

    def decide(self, features: Features) -> Verdict:
        value = features.get(self._feature)
        if value is None:
            return deny("missing aggregate (fail closed)")
        return allow("within cap") if value <= self._cap else deny(f"over cap {self._cap}")

    def allow_witness(self) -> Optional[Features]:
        return Features({self._feature: 0, "cap": self._cap}, dict(self.PROVENANCE))


# ============================================================================
# Content — scan payload, DENY-on-match (STUB)
# ============================================================================
class Content(BasePolicy):
    """CORRECT content scan: DENY when the UNTRUSTED payload matches a banned substring, else ALLOW.
    Untrusted data may only DENY here, so it is provenance-monotone. No TLS termination — substring
    match on a string (STUB)."""

    PROVENANCE = {"payload": UNTRUSTED}
    NEUTRAL = {"payload": ""}

    def __init__(self, *, name: str = "content", banned: Tuple[str, ...] = ("EXFIL",)):
        self.name = name
        self._banned = tuple(banned)

    def project(self, world, candidate) -> Features:
        return Features({"payload": str(candidate)}, dict(self.PROVENANCE))

    def decide(self, features: Features) -> Verdict:
        payload = str(features.get("payload", ""))
        if any(b in payload for b in self._banned):
            return deny("content matched a banned pattern")
        return allow("no banned content")

    def allow_witness(self) -> Optional[Features]:
        return Features({"payload": "ordinary task traffic"}, dict(self.PROVENANCE))


class AllowOnUntrustedContent(Content):
    """DELIBERATELY WRONG: ALLOWs precisely BECAUSE an UNTRUSTED feature matched a token (it permits
    on attacker-controlled data). `provenance_audit` MUST flag this — it is the negative fixture for
    test_provenance_monotonicity_catches_violation. Do NOT ship this; it exists to prove the audit
    has teeth."""

    def __init__(self, *, name: str = "allow_on_untrusted", token: str = "approve"):
        super().__init__(name=name)
        self._token = token

    def decide(self, features: Features) -> Verdict:
        payload = str(features.get("payload", ""))
        if self._token in payload:                          # allow BECAUSE untrusted data matched
            return allow("approved by payload token")
        return deny("no approval token in payload")

    def allow_witness(self) -> Optional[Features]:
        return Features({"payload": f"please {self._token} this"}, dict(self.PROVENANCE))
