"""Layered policy model for the deploy/promote rail — OFFLINE, agentdojo-free.

This mirrors the merge rail's `policy.py` in SHAPE (a typed frozen fence + a PolicySource the
agent cannot write + a monotonic `intersect` that only NARROWS), but its FIELD SET is
deploy-specific (services / environments / protected envs / provenance requirement instead of
path globs). The intersect itself is a per-rail fork: the SHAPE generalizes, the fields do not —
which is exactly the finding rail #2 exists to surface (see VERDICT in interface_inventory.md).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from evals._rail_core.policy_spec import evaluate_fence
from .domain import (ALLOWED_ENVIRONMENTS, CONFIGURED_SERVICES, EFFECT_DEPLOY,
                     EFFECT_DEPLOY_PROTECTED, PROTECTED_ENVIRONMENTS,
                     deploy_project_for_policy, deploy_spec_for_policy)

# ---- tiers (the disposition a fenced effect gets) — identical vocabulary to the merge rail ----
TIER_AUTO = "auto"
TIER_APPROVE = "approve"
TIER_COSIGN = "cosign"
TIER_DENY = "deny"
_TIER_ORDER = {TIER_AUTO: 0, TIER_APPROVE: 1, TIER_COSIGN: 2, TIER_DENY: 3}


def stricter(a: str, b: str) -> str:
    return a if _TIER_ORDER.get(a, 99) >= _TIER_ORDER.get(b, 99) else b


def _dedupe(items) -> tuple:
    seen, out = set(), []
    for g in items:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return tuple(out)


DEFAULT_TIERS = ((EFFECT_DEPLOY, TIER_AUTO), (EFFECT_DEPLOY_PROTECTED, TIER_DENY))


@dataclass(frozen=True)
class DeployPolicy:
    """A typed, layerable fence for the deploy rail. Frozen + hashable. `effect_tiers` is a tuple
    of (effect_class, tier) pairs (not a dict, so it stays frozen)."""
    allowed_services: tuple = CONFIGURED_SERVICES
    allowed_environments: tuple = ALLOWED_ENVIRONMENTS
    protected_environments: tuple = PROTECTED_ENVIRONMENTS    # fenced -> human review
    require_provenance: bool = True                            # build must be signed + scanned
    effect_tiers: tuple = DEFAULT_TIERS
    deploys_per_day: int = 10                                  # per-principal velocity cap
    freeze: bool = False                                       # force ALL effects >= cosign

    # -- tier resolution --
    def tier_for(self, effect_class: str) -> str:
        base = dict(self.effect_tiers).get(effect_class, TIER_DENY)  # unknown -> fail closed
        if self.freeze:
            base = stricter(base, TIER_COSIGN)
        return base

    # -- the fence (mirrors MergePolicy.is_fenced, but over env + provenance, not paths) --
    def env_disposition(self, build) -> str:
        env = str(getattr(build, "environment", "")).lower()
        if env in {e.lower() for e in self.protected_environments}:
            return "protected-env"
        if env not in {e.lower() for e in self.allowed_environments}:
            return "out-of-allow"
        if self.require_provenance and not (getattr(build, "signed", False)
                                            and getattr(build, "scanned", False)):
            return "no-provenance"
        return "in-fence"

    def is_fenced(self, build) -> bool:
        """True if the build's target environment is protected / out-of-allow, or its provenance
        is insufficient (-> requires review). Now DATA: the shared evaluator over the declared
        fence (protected_env==False AND environment∈allowed AND provenance_ok==True)."""
        return not evaluate_fence(deploy_project_for_policy(build, self),
                                  deploy_spec_for_policy(self))[0]

    # -- monotonic narrowing: a task may only ADD restrictions --
    def intersect(self, task: Optional["DeployPolicy"]) -> "DeployPolicy":
        if task is None:
            return self
        return DeployPolicy(
            # services / environments: intersection (a task can drop one, never add one).
            allowed_services=tuple(s for s in self.allowed_services
                                   if s in set(task.allowed_services)),
            allowed_environments=tuple(e for e in self.allowed_environments
                                       if e in set(task.allowed_environments)),
            # protected envs: union (a task can ADD a protection, never remove a standing one).
            protected_environments=_dedupe(self.protected_environments
                                           + task.protected_environments),
            # provenance: OR (a task can only tighten the requirement on).
            require_provenance=self.require_provenance or task.require_provenance,
            effect_tiers=_intersect_tiers(self.effect_tiers, task.effect_tiers),
            deploys_per_day=min(self.deploys_per_day, task.deploys_per_day),
            freeze=self.freeze or task.freeze,
        )


def _intersect_tiers(a: tuple, b: tuple) -> tuple:
    da, db = dict(a), dict(b)
    out = []
    for k in sorted(set(da) | set(db)):
        ta, tb = da.get(k), db.get(k)
        if ta is None:
            eff = tb
        elif tb is None:
            eff = ta
        else:
            eff = stricter(ta, tb)
        out.append((k, eff))
    return tuple(out)


DEFAULT_DEPLOY_POLICY = DeployPolicy()


# ============================================================================
# Policy SOURCE — the agent cannot write what enforcement reads (mirrors the merge rail)
# ============================================================================
class PolicySource:
    def load_effective_policy(self, service_id: str, principal_id: str) -> DeployPolicy:
        raise NotImplementedError


class InMemoryPolicySource(PolicySource):
    def __init__(self, table: Optional[dict] = None, default: Optional[DeployPolicy] = None):
        self._table = dict(table or {})
        self._default = default or DEFAULT_DEPLOY_POLICY

    def set(self, service_id: str, principal_id: str, policy: DeployPolicy) -> None:
        self._table[(service_id, principal_id)] = policy

    def load_effective_policy(self, service_id: str, principal_id: str) -> DeployPolicy:
        return self._table.get((service_id, principal_id), self._default)


def resolve_effective_policy(source: PolicySource, service_id: str, principal_id: str,
                             task_policy: Optional[DeployPolicy] = None) -> DeployPolicy:
    """standing (from the trusted source) ∩ task (narrowing only)."""
    standing = source.load_effective_policy(service_id, principal_id)
    return standing.intersect(task_policy)
