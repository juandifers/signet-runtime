"""Layered policy model for the GitHub merge rail — OFFLINE, agentdojo-free.

CORE IDEA: "where the policy lives" is a pluggable SOURCE, not a location. The agent
must never be able to write the policy enforcement reads. A `PolicySource` returns the
authoritative standing fence from somewhere the agent's working tree cannot change
(a control plane, a blessed ref, ...); a per-task layer may only NARROW it.

Three pieces:
  * MergePolicy  — a typed, frozen fence (mirrors EffectPolicy/StandingPolicy style).
  * PolicySource — `load_effective_policy(repo_id, principal_id) -> MergePolicy`, with
                   in-memory (control-plane stub) and blessed-ref implementations.
  * intersect    — monotonic narrowing: `effective = standing.intersect(task)`; a task
                   can only ADD restrictions, never lift them.

No agentdojo, no network, no GitHub App. Path/tier/velocity all come from the policy.
"""
from __future__ import annotations

import fnmatch
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from .domain import (ALLOWED_BASES, CONFIGURED_REPO, EFFECT_MERGE,
                     EFFECT_MERGE_PROTECTED, PROTECTED_GLOBS)

# ---- tiers (the disposition a fenced effect gets) ----
TIER_AUTO = "auto"        # the agent may merge autonomously (kernel still context-binds)
TIER_APPROVE = "approve"  # a human must approve out-of-band
TIER_COSIGN = "cosign"    # a second signer (enforcer/human) must co-sign
TIER_DENY = "deny"        # never, for anyone on this rail
_TIER_ORDER = {TIER_AUTO: 0, TIER_APPROVE: 1, TIER_COSIGN: 2, TIER_DENY: 3}
_TIERS = (TIER_AUTO, TIER_APPROVE, TIER_COSIGN, TIER_DENY)


def stricter(a: str, b: str) -> str:
    """The more restrictive of two tiers (higher in the order)."""
    return a if _TIER_ORDER.get(a, 99) >= _TIER_ORDER.get(b, 99) else b


def _matches_any(path: str, globs) -> bool:
    p = str(path).replace("\\", "/").lower()
    for g in globs:
        gl = str(g).lower()
        prefix = gl.split("**", 1)[0].rstrip("/")
        if prefix and (p == prefix or p.startswith(prefix + "/")):
            return True
        if fnmatch.fnmatch(p, gl):
            return True
    return False


def _dedupe(globs) -> tuple:
    seen, out = set(), []
    for g in globs:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return tuple(out)


# Default tiers + default standing fence (mirrors the GitHubDomain defaults so the
# DEFAULT_MERGE_POLICY reproduces today's behavior exactly).
DEFAULT_TIERS = ((EFFECT_MERGE, TIER_AUTO), (EFFECT_MERGE_PROTECTED, TIER_DENY))


@dataclass(frozen=True)
class MergePolicy:
    """A typed, layerable fence for the GitHub merge rail. Frozen + hashable.

    `effect_tiers` is a tuple of (effect_class, tier) pairs (not a dict, so the policy
    stays frozen). `extra_allow_layers` is internal: each intersect() appends the task's
    `allow_paths` as a CONJUNCTIVE layer, so a path is in-fence only if it matches an
    allow glob in EVERY layer (this is how a task narrows `allow` without a free-form
    glob intersection).
    """
    allow_paths: tuple = ("**",)               # globs an autonomous merge MAY touch
    deny_paths: tuple = PROTECTED_GLOBS         # fenced-off globs (protected -> review)
    effect_tiers: tuple = DEFAULT_TIERS         # (effect_class, tier) pairs
    merges_per_day: int = 10                    # per-principal velocity cap (amount==1)
    freeze: bool = False                        # condition: force ALL effects >= cosign
    allowed_bases: tuple = ALLOWED_BASES        # merge target branches permitted
    repo_id: str = CONFIGURED_REPO
    extra_allow_layers: tuple = field(default=())  # internal conjunctive allow layers

    # -- tier resolution --
    def tier_for(self, effect_class: str) -> str:
        base = dict(self.effect_tiers).get(effect_class, TIER_DENY)  # unknown -> fail closed
        if self.freeze:
            base = stricter(base, TIER_COSIGN)   # freeze forces at least a co-signature
        return base

    # -- path fence --
    def _allowed(self, path: str) -> bool:
        if not _matches_any(path, self.allow_paths):
            return False
        return all(_matches_any(path, layer) for layer in self.extra_allow_layers)

    def _denied(self, path: str) -> bool:
        return _matches_any(path, self.deny_paths)

    def path_disposition(self, touched_paths) -> str:
        if any(self._denied(p) for p in touched_paths):
            return "denied"
        if any(not self._allowed(p) for p in touched_paths):
            return "out-of-allow"
        return "in-fence"

    def is_fenced(self, touched_paths) -> bool:
        """True if ANY touched path is denied or outside the allow fence (-> protected)."""
        return self.path_disposition(touched_paths) != "in-fence"

    # -- monotonic narrowing: a task may only ADD restrictions --
    def intersect(self, task: Optional["MergePolicy"]) -> "MergePolicy":
        if task is None:
            return self
        return MergePolicy(
            allow_paths=self.allow_paths,
            # union of denies: a task can ADD a deny but never REMOVE a standing one.
            deny_paths=_dedupe(self.deny_paths + task.deny_paths),
            effect_tiers=_intersect_tiers(self.effect_tiers, task.effect_tiers),
            merges_per_day=min(self.merges_per_day, task.merges_per_day),
            freeze=self.freeze or task.freeze,
            # bases: intersection (task can drop a base, never add one).
            allowed_bases=tuple(b for b in self.allowed_bases
                                if b in set(task.allowed_bases)),
            repo_id=self.repo_id or task.repo_id,
            # the task's allow becomes an extra CONJUNCTIVE layer (narrow, never widen).
            extra_allow_layers=self.extra_allow_layers + (task.allow_paths,)
            + task.extra_allow_layers,
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
            eff = stricter(ta, tb)   # both opine -> the stricter wins (task can't relax)
        out.append((k, eff))
    return tuple(out)


# A standing policy reproducing today's behavior exactly (so build_merge_chain's default
# is byte-identical to the pre-policy constants).
DEFAULT_MERGE_POLICY = MergePolicy()


# ============================================================================
# Policy SOURCE — the agent cannot write what enforcement reads
# ============================================================================
class PolicySource(ABC):
    @abstractmethod
    def load_effective_policy(self, repo_id: str, principal_id: str) -> MergePolicy:
        ...


class InMemoryPolicySource(PolicySource):
    """The control-plane stub: policy is set out-of-band (in tests), never from the
    agent's working tree. Keyed by (repo_id, principal_id), with a default fallback."""

    def __init__(self, table: Optional[dict] = None,
                 default: Optional[MergePolicy] = None):
        self._table = dict(table or {})
        self._default = default or DEFAULT_MERGE_POLICY

    def set(self, repo_id: str, principal_id: str, policy: MergePolicy) -> None:
        self._table[(repo_id, principal_id)] = policy

    def load_effective_policy(self, repo_id: str, principal_id: str) -> MergePolicy:
        return self._table.get((repo_id, principal_id), self._default)


class BlessedRefPolicySource(PolicySource):
    """Reads policy as of a TRUSTED ref (offline stub: returns a pinned MergePolicy).

    The point of the abstraction: the policy lives on a ref the agent's working tree
    cannot rewrite. `working_tree_policy` models a copy the agent CAN edit — and which
    this source DELIBERATELY IGNORES. Swapping control-plane vs separate-repo vs
    pinned-ref is a source swap; none of them is the agent's working tree.
    """

    def __init__(self, pinned: MergePolicy,
                 working_tree_policy: Optional[MergePolicy] = None,
                 ref: str = "refs/heads/policy-blessed"):
        self._pinned = pinned
        self.working_tree_policy = working_tree_policy   # agent-writable; NEVER consulted
        self.ref = ref

    def load_effective_policy(self, repo_id: str, principal_id: str) -> MergePolicy:
        # Trusted ref only. The working-tree copy is never read -- mutating it has no
        # effect on enforcement (that is the load-bearing property of this layer).
        return self._pinned


# ============================================================================
# Resolved-fence view (so a misconfiguration is VISIBLE, not a silent hole)
# ============================================================================
def describe_effective_policy(policy: MergePolicy, repo_id: Optional[str] = None,
                              principal_id: Optional[str] = None) -> str:
    lines = [
        f"effective merge fence   repo={repo_id or policy.repo_id or '*'}   "
        f"principal={principal_id or '*'}",
        f"  allowed bases : {list(policy.allowed_bases)}",
        f"  allow paths   : {list(policy.allow_paths)}"
        + (f"   + task layers {[list(l) for l in policy.extra_allow_layers]}"
           if policy.extra_allow_layers else ""),
        f"  deny  paths   : {list(policy.deny_paths)}   (protected -> human review)",
        "  effect tiers  :",
    ]
    for ec in (EFFECT_MERGE, EFFECT_MERGE_PROTECTED):
        lines.append(f"      {ec:<20} -> {policy.tier_for(ec)}")
    lines.append(f"  velocity      : {policy.merges_per_day} merges/principal/day")
    cond = f"  conditions    : freeze={policy.freeze}"
    if policy.freeze:
        cond += "   (ALL effects forced to >= cosign)"
    lines.append(cond)
    return "\n".join(lines)
