"""GitHub merge decision path — reads its fence from a PolicySource, applies the
task-layer narrowing, resolves a tier, and runs the UNMODIFIED kernel for auto merges.

This is where "the fence comes from a SOURCE, not a hardcoded constant" is wired in:
  1. standing = source.load_effective_policy(repo_id, principal_id)   # agent can't write
  2. effective = standing.intersect(task_policy)                      # task only narrows
  3. effect_class from the effective DENY fence (protected if fenced)
  4. tier from the effective tiers (+ freeze condition + base-branch gate)
  5. tier==auto  -> build_merge_chain(policy=effective) + kernel evaluate (context-bind,
                    consume-once, per-principal velocity all still enforced)
     tier!=auto  -> NOT auto-authorized (approve/cosign/deny escalate); no kernel call

Offline only: no control plane, no GitHub App, no network.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .domain import EFFECT_MERGE, EFFECT_MERGE_PROTECTED
from .merge_chain import PRINCIPAL, build_merge_chain
from .policy import (TIER_AUTO, TIER_DENY, MergePolicy, PolicySource,
                     describe_effective_policy)


@dataclass
class MergeDecision:
    approved: bool          # auto-authorized AND the kernel passed
    tier: str               # auto | approve | cosign | deny
    reason: str
    effect_class: str       # merge_pr | merge_pr_protected
    effective_policy: MergePolicy
    token: object = None    # the enforcer ExecutionToken when approved, else None


def resolve_effective_policy(source: PolicySource, repo_id: str, principal_id: str,
                             task_policy: Optional[MergePolicy] = None) -> MergePolicy:
    """standing (from the trusted source) ∩ task (narrowing only)."""
    standing = source.load_effective_policy(repo_id, principal_id)
    return standing.intersect(task_policy)


def enforce_merge(env, source: PolicySource, *, repo_id: str, principal_id: str,
                  pr: int, base: str, head_sha: str, touched_paths,
                  task_policy: Optional[MergePolicy] = None,
                  author: str = "alice") -> MergeDecision:
    pol = resolve_effective_policy(source, repo_id, principal_id, task_policy)

    # base-branch gate (the policy bounds which branches may be merged into).
    if base not in pol.allowed_bases:
        return MergeDecision(False, TIER_DENY,
                             f"base '{base}' not in allowed bases {list(pol.allowed_bases)}",
                             EFFECT_MERGE, pol)

    # path fence -> effect_class (a denied/out-of-allow path is protected).
    fenced = pol.is_fenced(touched_paths)
    ec = EFFECT_MERGE_PROTECTED if fenced else EFFECT_MERGE
    tier = pol.tier_for(ec)

    if tier != TIER_AUTO:
        # approve / cosign / deny -> NOT autonomously authorizable. No kernel call.
        return MergeDecision(
            False, tier,
            f"tier={tier} for {ec} ({pol.path_disposition(touched_paths)}"
            + (", freeze" if pol.freeze else "") + ")",
            ec, pol)

    # auto -> the kernel still enforces context-binding, consume-once and per-principal
    # velocity (cap from the effective policy). The merge clears only if the kernel passes.
    req = build_merge_chain(env, repo=pol.repo_id, pr=pr, base=base, head_sha=head_sha,
                            touched_paths=touched_paths, author=author, policy=pol)
    decision, token = env.verifier.evaluate(req)
    return MergeDecision(decision.approved, tier, decision.reason, ec, pol,
                         token if decision.approved else None)


# Convenience: the resolved-fence view for a given (source, repo, principal[, task]).
def describe_for(source: PolicySource, repo_id: str, principal_id: str,
                 task_policy: Optional[MergePolicy] = None) -> str:
    pol = resolve_effective_policy(source, repo_id, principal_id, task_policy)
    return describe_effective_policy(pol, repo_id, principal_id)
