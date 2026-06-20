"""The §0.3 GOLDEN CORPUS harness — the regression gate for the rail-algebra refactor.

This module computes each rail's verdicts over a representative input corpus through the rail's
STABLE public entry points (the ones whose *internals* the refactor rewires, but whose signatures
and outputs must be byte-for-byte preserved):

  * merge  — `GitHubPlugin().within_allowlist/within_fence` (the Policy layer) over the configured
             world's owned ids {in-gate ×2, off-fence, off-allowlist} + a nonexistent id, AND
             `GitHubPlugin().resolve(...)` (the full Role-B gate) over the adversarial resolver
             outputs (the "six attacks" battery from evals.conformance.battery).
  * egress — `EgressBroker.admit(host, port)` (which drives the EgressAuthorizer template) over
             {allowed host, disallowed host, wildcard host, raw-IP-matching-allowed, raw-IP-evasion}.

Both the snapshot script (`python -m tests._golden.snapshot`) and the acceptance test
(`tests/test_rail_algebra.py`) call `build_corpus()` here, so equality is computed IDENTICALLY on
both sides — there is no second, drifting transcription of the corpus.

The egress fixture uses a StubResolver with FIXED ports (no live EchoServer) so the (admitted,
cause) verdicts are deterministic: `admit` resolves + mints + authorizes but never opens the
upstream socket, so no real server is needed.
"""
from __future__ import annotations

from typing import Dict, List

# ---- merge corpus deps (the conformance plugin + its battery) ----
from evals.conformance.battery import _RawResolver, _adversarial_outputs
from evals.conformance.rails import github_plugin
from evals.github_railbridge.domain import GitHubDomain

# ---- egress corpus deps ----
from signet.broker.mandate import MandateProvider
from signet.broker.proxy import EgressBroker
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.egress.mandate import EgressGrant, EgressMandate, EgressStandingPolicy
from signet.rails.egress.dest_sim import StubResolver
from signet.rails.egress.resolver import Resolution

import datetime as _dt

_NONEXISTENT_PR = 999


# ============================================================================
# merge
# ============================================================================
def merge_verdicts() -> Dict:
    """Policy-layer verdicts (within_allowlist/within_fence) over the owned ids + a nonexistent id,
    AND resolve-layer verdicts over the adversarial resolver outputs."""
    plugin = github_plugin()
    world = plugin.build_world()
    owned = sorted(plugin.owned_ids(world))
    effective = plugin._effective(world)
    domain = GitHubDomain(policy=effective)

    # -- Policy layer: each owned candidate, then a nonexistent id (off the books) --
    policy: List[Dict] = []
    for cid in owned:
        policy.append({
            "id": cid,
            "within_allowlist": bool(plugin.within_allowlist(world, cid)),
            "within_fence": bool(plugin.within_fence(world, cid)),
        })
    # nonexistent id: a fabricated target the domain cannot look up -> both predicates fail closed.
    nonexistent_target = f"{domain.configured_repo}#{_NONEXISTENT_PR}->main@shaNONE"
    policy.append({
        "id": _NONEXISTENT_PR,
        "within_allowlist": bool(domain.within_allowlist(nonexistent_target, world)),
        "within_fence": bool(domain.within_fence(nonexistent_target, world)),
    })

    # -- resolve layer: the full Role-B gate over the adversarial outputs ("the six attacks") --
    legit, legit2 = owned[0], owned[1]
    attacker = plugin.attacker_id(world)
    off_allow = next(c for c in owned if not plugin.within_allowlist(world, c))
    off_set = max(owned) + 1000
    crit = plugin.criterion(world)

    resolve: List[Dict] = []
    for label, raw, _kind in _adversarial_outputs(legit, legit2, attacker, off_allow, off_set):
        v = plugin.resolve(crit, world, _RawResolver(raw, set(owned)))
        resolve.append({
            "label": label,
            "resolved": bool(v.resolved),
            "target_id": v.target_id,
            "escalation_source": v.escalation_source,
            "cause": v.cause,
        })

    return {"policy": policy, "resolve": resolve}


# ============================================================================
# egress
# ============================================================================
def _egress_broker() -> EgressBroker:
    """A deterministic egress broker: a frozen mandate granting api.allowed.test:443 (concrete) and
    *.allowed.test:443 (wildcard); a broad standing ceiling; a StubResolver with FIXED ports so the
    raw-IP cases are stable. No live upstream — `admit` never connects."""
    resolver = StubResolver({
        "api.allowed.test": Resolution("127.0.0.1", 9101),   # concrete, allowlisted
        "sub.allowed.test": Resolution("127.0.0.1", 9102),   # matches the *.allowed.test wildcard
        "evil.test": Resolution("127.0.0.1", 9103),          # in the standing ceiling, NOT the mandate
    })
    mandates = MandateProvider()
    mandates.register(EgressMandate("task-golden", (EgressGrant("api.allowed.test", (443,)),
                                                    EgressGrant("*.allowed.test", (443,)))))
    standing = EgressStandingPolicy((
        EgressGrant("api.allowed.test", (80, 443, 22)),
        EgressGrant("*.allowed.test", (443,)),
        EgressGrant("evil.test", (443,)),
    ))
    clock = lambda: _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
    return EgressBroker.create(mandates=mandates, standing=standing,
                               receipts=LocalReceiptLog("golden:egress"),
                               task_id="task-golden", resolver=resolver, clock=clock,
                               ttl_seconds=60)


def _egress_broker_expired() -> EgressBroker:
    """A broker whose frozen mandate grants api.allowed.test:443 but EXPIRED before the clock
    (2026-06-11 11:00 < 12:00). TOCTOU binds and the destination IS policy-clean, so the ONLY thing
    that can block is the mandate-lifecycle guard -> this row characterizes 'mandate-expired'."""
    resolver = StubResolver({"api.allowed.test": Resolution("127.0.0.1", 9101)})
    mandates = MandateProvider()
    mandates.register(EgressMandate("task-expired", (EgressGrant("api.allowed.test", (443,)),),
                                    expires_at="2026-06-11T11:00:00+00:00"))
    standing = EgressStandingPolicy((EgressGrant("api.allowed.test", (80, 443, 22)),))
    clock = lambda: _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
    return EgressBroker.create(mandates=mandates, standing=standing,
                               receipts=LocalReceiptLog("golden:egress-expired"),
                               task_id="task-expired", resolver=resolver, clock=clock,
                               ttl_seconds=60)


def _egress_broker_no_mandate() -> EgressBroker:
    """A broker whose task_id has NO registered frozen mandate. TOCTOU binds, but no mandate exists
    -> this row characterizes 'no-frozen-mandate' (the missing-mandate lifecycle guard)."""
    resolver = StubResolver({"api.allowed.test": Resolution("127.0.0.1", 9101)})
    standing = EgressStandingPolicy((EgressGrant("api.allowed.test", (80, 443, 22)),))
    clock = lambda: _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
    return EgressBroker.create(mandates=MandateProvider(), standing=standing,
                               receipts=LocalReceiptLog("golden:egress-nomandate"),
                               task_id="task-missing", resolver=resolver, clock=clock,
                               ttl_seconds=60)


def egress_verdicts() -> List[Dict]:
    broker = _egress_broker()
    cases = [
        ("allowed_host", "api.allowed.test", 443),
        ("disallowed_host", "evil.test", 443),
        ("wildcard_host", "sub.allowed.test", 443),
        ("raw_ip_matching_allowed", "127.0.0.1", 9101),     # == trusted resolution of api.allowed.test
        ("raw_ip_evasion", "127.0.0.1", 9103),              # == evil's resolved port; dodges the host
    ]
    out: List[Dict] = []
    for label, host, port in cases:
        adm = broker.admit(host, port)
        out.append({"label": label, "host": host, "port": port,
                    "admitted": bool(adm.admitted), "cause": adm.cause})

    # ---- the mandate-LIFECYCLE rows (SCHEDULE.md PROMOTION §3.1) ----
    # These characterize the two egress Bind-class lifecycle guards (frozen-mandate exists + not
    # expired) on a destination that is otherwise policy-clean, so a verdict change can ONLY mean a
    # dropped guard. Committed BEFORE the schedule-driven promotion so BEHAVIOR-PRESERVED catches it.
    for label, broker_fn in (("mandate_expired", _egress_broker_expired),
                             ("no_frozen_mandate", _egress_broker_no_mandate)):
        adm = broker_fn().admit("api.allowed.test", 443)
        out.append({"label": label, "host": "api.allowed.test", "port": 443,
                    "admitted": bool(adm.admitted), "cause": adm.cause})
    return out


# ============================================================================
# top-level
# ============================================================================
def build_corpus() -> Dict:
    return {"merge": merge_verdicts(), "egress": egress_verdicts()}
