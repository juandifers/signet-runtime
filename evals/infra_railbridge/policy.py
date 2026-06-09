"""Layered policy model for the infra-as-code rail — OFFLINE, agentdojo-free.

This mirrors the deploy rail's `policy.py` in SHAPE (a typed frozen fence + a PolicySource the agent
cannot write + a monotonic `intersect` that only NARROWS), but it is the rail that finally exercises
a QUANTITATIVE fence: `is_fenced` is a CONJUNCTION richer than a protected-flag membership test —
(no protected resource type) AND (blast_radius <= blast_cap) AND (destroy_count <= destroy_cap). The
intersect narrows ALL of them monotonically: accounts/clusters/types INTERSECT, protected types
UNION, and the numeric caps take the MIN (a task can only LOWER the blast/destroy ceilings).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .domain import (ALLOWED_RESOURCE_TYPES, CONFIGURED_ACCOUNTS, CONFIGURED_CLUSTERS,
                     DEFAULT_BLAST_CAP, DEFAULT_DESTROY_CAP, EFFECT_INFRA_APPLY,
                     EFFECT_INFRA_APPLY_PROTECTED, PROTECTED_RESOURCE_TYPES)

# ---- tiers (the disposition a fenced effect gets) — identical vocabulary to the other rails ----
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


def _intersect(a, b) -> tuple:
    bs = set(b)
    return tuple(x for x in a if x in bs)


DEFAULT_TIERS = ((EFFECT_INFRA_APPLY, TIER_AUTO), (EFFECT_INFRA_APPLY_PROTECTED, TIER_DENY))


@dataclass(frozen=True)
class InfraPolicy:
    """A typed, layerable fence for the infra rail. Frozen + hashable. `effect_tiers` is a tuple of
    (effect_class, tier) pairs (not a dict, so it stays frozen)."""
    allowed_accounts: tuple = CONFIGURED_ACCOUNTS
    allowed_clusters: tuple = CONFIGURED_CLUSTERS
    allowed_resource_types: tuple = ALLOWED_RESOURCE_TYPES
    protected_resource_types: tuple = PROTECTED_RESOURCE_TYPES   # fenced -> human review
    blast_cap: int = DEFAULT_BLAST_CAP                            # max changed resources (QUANT)
    destroy_cap: int = DEFAULT_DESTROY_CAP                        # max destroys (QUANT)
    effect_tiers: tuple = DEFAULT_TIERS
    applies_per_day: int = 10                                     # per-principal velocity cap
    freeze: bool = False                                         # force ALL effects >= cosign

    # -- tier resolution --
    def tier_for(self, effect_class: str) -> str:
        base = dict(self.effect_tiers).get(effect_class, TIER_DENY)  # unknown -> fail closed
        if self.freeze:
            base = stricter(base, TIER_COSIGN)
        return base

    # -- the fence (the CONJUNCTION; set-membership AND two quantitative caps) --
    def change_disposition(self, plan) -> str:
        prot = {t.lower() for t in self.protected_resource_types}
        if any(str(t).lower() in prot for t in getattr(plan, "resource_types", frozenset())):
            return "protected-type"
        if int(getattr(plan, "blast_radius", 0)) > int(self.blast_cap):
            return "blast-over-cap"
        if int(getattr(plan, "destroy_count", 0)) > int(self.destroy_cap):
            return "destroy-over-cap"
        return "in-fence"

    def is_fenced(self, plan) -> bool:
        """True if the change-set touches a protected resource type, exceeds the blast cap, or
        exceeds the destroy cap (-> requires review)."""
        return self.change_disposition(plan) != "in-fence"

    # -- monotonic narrowing: a task may only ADD restrictions --
    def intersect(self, task: Optional["InfraPolicy"]) -> "InfraPolicy":
        if task is None:
            return self
        return InfraPolicy(
            # accounts / clusters / types: intersection (a task can drop one, never add one).
            allowed_accounts=_intersect(self.allowed_accounts, task.allowed_accounts),
            allowed_clusters=_intersect(self.allowed_clusters, task.allowed_clusters),
            allowed_resource_types=_intersect(self.allowed_resource_types,
                                              task.allowed_resource_types),
            # protected types: union (a task can ADD a protection, never remove a standing one).
            protected_resource_types=_dedupe(self.protected_resource_types
                                             + task.protected_resource_types),
            # the QUANTITATIVE caps: MIN (a task can only LOWER the blast / destroy ceilings).
            blast_cap=min(int(self.blast_cap), int(task.blast_cap)),
            destroy_cap=min(int(self.destroy_cap), int(task.destroy_cap)),
            effect_tiers=_intersect_tiers(self.effect_tiers, task.effect_tiers),
            applies_per_day=min(self.applies_per_day, task.applies_per_day),
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


DEFAULT_INFRA_POLICY = InfraPolicy()


# ============================================================================
# Policy SOURCE — the agent cannot write what enforcement reads (mirrors the other rails)
# ============================================================================
class PolicySource:
    def load_effective_policy(self, account_id: str, principal_id: str) -> InfraPolicy:
        raise NotImplementedError


class InMemoryPolicySource(PolicySource):
    def __init__(self, table: Optional[dict] = None, default: Optional[InfraPolicy] = None):
        self._table = dict(table or {})
        self._default = default or DEFAULT_INFRA_POLICY

    def set(self, account_id: str, principal_id: str, policy: InfraPolicy) -> None:
        self._table[(account_id, principal_id)] = policy

    def load_effective_policy(self, account_id: str, principal_id: str) -> InfraPolicy:
        return self._table.get((account_id, principal_id), self._default)


def resolve_effective_policy(source: PolicySource, account_id: str, principal_id: str,
                             task_policy: Optional[InfraPolicy] = None) -> InfraPolicy:
    """standing (from the trusted source) ∩ task (narrowing only)."""
    standing = source.load_effective_policy(account_id, principal_id)
    return standing.intersect(task_policy)
