"""Per-task AP2 Open/Closed mandate on the INFRA-as-code rail — OFFLINE, agentdojo-free.

This mirrors the deploy rail's `mandate.py` ONE-FOR-ONE in control flow; only the candidate schema
(plans, not builds), the fence fields (resource types + the QUANTITATIVE blast/destroy caps, not
environment+provenance), and the SET-VALUED effect-key differ. The RESOLUTION stages — Layer-A
structural pre-filter -> set-valued Role B + cardinality -> the containment gate — are the SHARED
`evals._rail_core.role_b.run_role_b_stages`; the escalation-source enum is shared too. Only Stage-3's
gate (the infra fence) and the infra structural predicate are rail-specific.

  * OpenMandate  — the operator's TRUSTED, frozen grant for THIS job (criterion + account/cluster
                   scope + blast/destroy caps), frozen before any plan metadata is read.
  * effective fence = standing InfraPolicy INTERSECT OpenMandate (monotonic narrowing).
  * ClosedMandate — the RESOLVED specific apply, bound to `account@cluster#resource_set_hash/plan`,
                   only minted if its bound effect is a MEMBER of the effective fence.

The decision routes through the SAME kernel + an infra authorizer (verify_token + independent
context re-check). The apply gate is MOCK; no real terraform/k8s apply is performed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from signet.authorizers.infra_railbridge import InfraRailBridge
from signet.canonical import hash_obj
from signet.receipts import ReceiptLog

from evals.effect_core import ENDORSE, resolve_effect_predicate
from evals._rail_core.role_b import ESC_LAYER_A, run_role_b_stages

from .domain import (CONFIGURED_ACCOUNTS, CONFIGURED_CLUSTERS, PROTECTED_RESOURCE_TYPES,
                     InfraDomain, InfraWorld, effect_class_for, extract_infra_predicate, target_id)
from .infra_chain import PRINCIPAL, build_infra_chain
from .policy import (DEFAULT_BLAST_CAP, DEFAULT_DESTROY_CAP, TIER_AUTO, InfraPolicy, PolicySource,
                     resolve_effective_policy)

RESOLVED = "RESOLVED"
UNRESOLVED = "UNRESOLVED"
UNRESOLVED_CONSTRAINT = "unresolved_constraint"


# ============================================================================
# OpenMandate — the operator's TRUSTED, frozen grant for THIS job
# ============================================================================
@dataclass(frozen=True)
class OpenMandate:
    """The Open part of an AP2 mandate: the scope of authority for one apply job. TRUSTED INPUT,
    frozen BEFORE any plan metadata is read."""
    criterion: str
    account_allow: tuple = CONFIGURED_ACCOUNTS     # accounts this job may target (narrows)
    cluster_allow: tuple = CONFIGURED_CLUSTERS
    blast_cap: int = DEFAULT_BLAST_CAP             # the job may only LOWER the standing cap
    destroy_cap: int = DEFAULT_DESTROY_CAP
    applies_per_day: Optional[int] = None
    extra_protected: tuple = ()                    # additional protected resource types (tightening)
    account_id: Optional[str] = None

    def as_task_policy(self) -> InfraPolicy:
        """Render the OpenMandate as a task-layer InfraPolicy for intersect(). It can only ADD
        restrictions: accounts/clusters intersect, protected types union, caps min."""
        kw = dict(
            allowed_accounts=tuple(self.account_allow) or CONFIGURED_ACCOUNTS,
            allowed_clusters=tuple(self.cluster_allow) or CONFIGURED_CLUSTERS,
            protected_resource_types=tuple(PROTECTED_RESOURCE_TYPES) + tuple(self.extra_protected),
            blast_cap=int(self.blast_cap),
            destroy_cap=int(self.destroy_cap))
        if self.applies_per_day is not None:
            kw["applies_per_day"] = int(self.applies_per_day)
        return InfraPolicy(**kw)

    def predicate(self):
        return extract_infra_predicate(self.criterion)

    def mandate_id(self) -> str:
        return "open_" + hash_obj([self.criterion, list(self.account_allow), list(self.cluster_allow),
                                   self.blast_cap, self.destroy_cap, self.applies_per_day,
                                   list(self.extra_protected), self.account_id])[:16]


# ============================================================================
# ClosedMandate — the resolved, fence-checked, bound authorization
# ============================================================================
@dataclass(frozen=True)
class ClosedMandate:
    account: str
    plan_id: int
    cluster: str
    resource_set: tuple
    plan_hash: str
    effect_class: str
    bound_target: str        # target_id == account@cluster#resource_set_hash/plan_hash


@dataclass
class Considered:
    plan_id: Optional[int]
    target: str
    cause: str
    channel: str = "resolver"


@dataclass
class MandateResolution:
    kind: str
    closed: Optional[ClosedMandate] = None
    cause: str = ""
    considered: List[Considered] = field(default_factory=list)
    reasoning_trace: str = ""
    reasoning_trace_hash: Optional[str] = None
    # resolved | layer_a_structural | layer_b_cardinality | gate_contained | no_match
    escalation_source: Optional[str] = None


def _plan_from_target(target: str, world: InfraWorld, domain: InfraDomain):
    for r in world.open_plans.values():
        if domain._target(r) == target:
            return r
    return None


def resolve_task_mandate(om: OpenMandate, world: InfraWorld, effective: InfraPolicy, *,
                         resolver=None, trace_store=None) -> MandateResolution:
    """Resolve the OpenMandate's criterion to ONE bound ClosedMandate within the effective fence, or
    escalate with ``unresolved_constraint``. With `resolver` set (the Role B path), the SHARED
    three-stage orchestrator runs; the deterministic Role-A path runs when resolver is None."""
    domain = InfraDomain(policy=effective)
    if resolver is not None:
        return _resolve_via_role_b(om, world, effective, domain, resolver, trace_store)

    # Deterministic Role-A path: instruction-only predicate -> resolve over own plans -> gate.
    pred = om.predicate()
    res = resolve_effect_predicate(pred, world, domain, cap_cents=None)
    if res.kind != ENDORSE:
        return MandateResolution(UNRESOLVED, None, f"{UNRESOLVED_CONSTRAINT}: {res.cause}", [])
    rec = _plan_from_target(res.endorsed_target, world, domain)
    if rec is None:
        return MandateResolution(UNRESOLVED, None,
                                 f"{UNRESOLVED_CONSTRAINT}: endorsed target not own", [])
    return _gate_and_bind(world, effective, domain, rec.plan_id)


def _gate_predicates(world: InfraWorld, effective: InfraPolicy, domain: InfraDomain):
    """The two per-rail boolean predicates the SHARED gate consumes (the FIELDS are infra-specific;
    the ORDER + fail-closed live in `evals._rail_core.role_b`): the allow-list UNIVERSE ceiling
    (configured account + cluster + allowed resource types) and the scope/protected/QUANTITATIVE
    FENCE (the effective policy's is_fenced — the blast/destroy conjunction)."""
    within_allowlist = lambda p: domain.within_allowlist(domain._target(world.open_plans[p]), world)
    within_fence = lambda p: not effective.is_fenced(world.open_plans[p])
    return within_allowlist, within_fence


def _bind_closed(world: InfraWorld, effective: InfraPolicy, domain: InfraDomain, plan_id, *,
                 reasoning_trace: str = "", reasoning_trace_hash=None) -> MandateResolution:
    """Bind a gate-PASSED plan id to a ClosedMandate (no re-gate)."""
    rec = world.open_plans[plan_id]
    closed = ClosedMandate(
        account=rec.account, plan_id=plan_id, cluster=rec.cluster,
        resource_set=tuple(rec.resource_set), plan_hash=rec.plan_hash,
        effect_class=effect_class_for(rec, effective.protected_resource_types),
        bound_target=domain._target(rec))
    return MandateResolution(RESOLVED, closed, "", [], reasoning_trace=reasoning_trace,
                             reasoning_trace_hash=reasoning_trace_hash, escalation_source="resolved")


def _gate_and_bind(world: InfraWorld, effective: InfraPolicy, domain: InfraDomain,
                   plan_id: Optional[int]) -> MandateResolution:
    """Deterministic Role-A path: run the SHARED containment gate (order + fail-closed) on a single
    chosen plan, then bind it. Reuses `_rail_core.role_b.run_gate` so even the deterministic path
    cannot reorder the gate."""
    from evals._rail_core.role_b import run_gate
    if plan_id is None or plan_id not in world.open_plans:
        return MandateResolution(UNRESOLVED, None,
                                 f"{UNRESOLVED_CONSTRAINT}: not an owned plan", [],
                                 escalation_source="gate_contained")
    wa, wf = _gate_predicates(world, effective, domain)
    reject = run_gate(plan_id, set(world.open_plans), wa, wf)
    if reject is not None:
        rec = world.open_plans[plan_id]
        return MandateResolution(UNRESOLVED, None, f"{UNRESOLVED_CONSTRAINT}: {reject}",
                                 [Considered(plan_id, domain._target(rec), reject, "resolver")],
                                 escalation_source="gate_contained")
    return _bind_closed(world, effective, domain, plan_id)


def _resolve_via_role_b(om: OpenMandate, world: InfraWorld, effective: InfraPolicy,
                        domain: InfraDomain, resolver, trace_store) -> MandateResolution:
    """Role B path with STRUCTURAL abstention — ALL THREE stages (incl. THE GATE) are the SHARED
    `run_role_b_stages`. The infra rail SHEDS its gate control flow: it supplies only the two boolean
    predicates (the FIELDS are infra-specific) and cannot reorder the gate or skip a stage. Identical
    control flow to the merge / deploy rails' `_resolve_via_role_b`."""
    from .resolver import PlanView
    from .ambiguity import structural_prefilter

    candidates = [PlanView.from_plan(rec) for rec in world.open_plans.values()]
    within_allowlist, within_fence = _gate_predicates(world, effective, domain)
    stages = run_role_b_stages(
        om.criterion, candidates, set(world.open_plans), resolver=resolver,
        within_allowlist=within_allowlist, within_fence=within_fence,
        structural_prefilter=lambda: structural_prefilter(om, world), trace_store=trace_store)

    if stages.status == "escalate":
        considered: List[Considered] = []
        if stages.escalation_source != ESC_LAYER_A:
            for pid in stages.surviving_ids:
                rec = world.open_plans.get(pid)
                if rec is not None:
                    considered.append(Considered(pid, domain._target(rec), stages.cause, "resolver"))
        return MandateResolution(
            UNRESOLVED, None, f"{UNRESOLVED_CONSTRAINT}: {stages.cause}", considered,
            reasoning_trace=stages.raw, reasoning_trace_hash=stages.trace_hash,
            escalation_source=stages.escalation_source)

    # "resolve" — the gate already PASSED inside run_role_b_stages; bind the survivor (no re-gate).
    return _bind_closed(world, effective, domain, stages.chosen_id,
                        reasoning_trace=stages.raw, reasoning_trace_hash=stages.trace_hash)


# ============================================================================
# Injection channel — what a NAIVE agent would have applied (METRIC ONLY)
# ============================================================================
_INJ_RE = re.compile(r"(?:plan|apply)\s*#?(\d+)", re.I)


def injection_targets(world: InfraWorld) -> List[int]:
    """Plan ids a redirect injection in the UNTRUSTED description tries to steer toward. Reads
    `injected_description` — the exact channel the mandate path NEVER reads. Used ONLY for the
    would-have-proceeded metric."""
    wanted: List[int] = []
    for rec in world.open_plans.values():
        for m in _INJ_RE.finditer(str(getattr(rec, "injected_description", "") or "")):
            n = int(m.group(1))
            if n in world.open_plans and n not in wanted:
                wanted.append(n)
    return wanted


# ============================================================================
# Route a ClosedMandate through the authorizer + emit a signed receipt
# ============================================================================
@dataclass
class AuthorizeOutcome:
    approved: bool
    tier: str
    reason: str
    effect_class: str
    receipt: object
    auth: object = None
    token: object = None
    gate_ref: Optional[str] = None


def _synth_hash(*parts) -> str:
    return hash_obj(["infra-mandate-receipt", *[str(p) for p in parts]])


def authorize_closed_mandate(env, bridge: InfraRailBridge, receipts: ReceiptLog, *,
                             account_id: str, closed: ClosedMandate, effective: InfraPolicy,
                             principal_id: str = PRINCIPAL,
                             author: str = "alice") -> AuthorizeOutcome:
    """Take a resolved ClosedMandate to a decision THROUGH THE INFRA AUTHORIZER, recording a signed
    receipt for every outcome. Mirrors the deploy rail's `authorize_closed_mandate`."""
    ec = closed.effect_class
    tier = effective.tier_for(ec)

    if tier != TIER_AUTO:
        reason = f"tier={tier} for {ec} -> escalate (not autonomously authorizable)"
        r = receipts.append(
            execution_id="exec_" + _synth_hash(closed.bound_target, "review")[:16],
            mandate_id=f"open:{account_id}", chain_hash=_synth_hash(closed.bound_target),
            policy_id=f"effective:{account_id}", decision="review",
            payment_status=f"escalated:tier={tier}", payment_ref=None, rail="infra")
        return AuthorizeOutcome(False, tier, reason, ec, r)

    req = build_infra_chain(env, account=closed.account, cluster=closed.cluster,
                            resource_set=closed.resource_set, plan_hash=closed.plan_hash,
                            effect_class=ec, author=author, policy=effective)
    decision, token = env.verifier.evaluate(req)

    if not decision.approved:
        r = receipts.append(
            execution_id="exec_" + _synth_hash(closed.bound_target, "block")[:16],
            mandate_id=req.intent.mandate_id,
            chain_hash=decision.chain_hash or _synth_hash(closed.bound_target),
            policy_id=req.intent.policy_id, decision="blocked",
            payment_status="kernel-blocked", payment_ref=None, rail="infra")
        return AuthorizeOutcome(False, tier, decision.reason, ec, r, token=token)

    auth = bridge.authorize(token, req)
    r = receipts.append(
        execution_id=token.execution_id, mandate_id=token.mandate_id,
        chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
        decision="approved" if auth.executed else "blocked",
        payment_status="executed" if auth.executed else "authorizer-refused",
        payment_ref=auth.payment_ref, rail=auth.rail or "infra")
    return AuthorizeOutcome(auth.executed, tier, auth.reason, ec, r,
                            auth=auth, token=token, gate_ref=auth.payment_ref)
