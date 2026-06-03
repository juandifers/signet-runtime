"""Plan-time diagnostic for the GitHub rail-bridge domain.

Now reads its fence from a PolicySource — the SAME source enforce_merge uses — so the
diagnostic measures the fence that's actually enforced (closes friction #3). A default
source returns DEFAULT_MERGE_POLICY, so the table is unchanged when nothing is configured.

REUSES the shared plan-time harness unchanged:
  * `evals.agentdojo.diagnostic._classify_effect` / `print_domain_table`
  * `evals.agentdojo.taxonomy` bucketing (here the GT bucket is a corpus label)
wrapped with a POLICY TIER pre-gate: a GT action whose effective tier is not `auto`
(protected -> deny, or a freeze/cosign condition) escalates regardless of how well a
mode could resolve the target — exactly what enforce_merge does.

Velocity (merges_per_day) is reported as a separate burst summary (a rate limit, not a
per-action property). No agent rollouts; fully offline.

Run:  python3 -m evals.github_railbridge.diagnostic
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from evals.agentdojo.diagnostic import (ESCALATE, PlanRow, _classify_effect,
                                        print_domain_table)
from evals.agentdojo.gate import MODE_POLICY, MODE_PREDICATE, MODE_STRICT
from evals.effect_core import effect_key

from .corpus import CORPUS, build_corpus_world
from .domain import GitHubDomain
from .policy import (TIER_AUTO, InMemoryPolicySource, PolicySource,
                     describe_effective_policy)

REPO = "octo/payments-service"
PRINCIPAL = "acme_cfo"
ALL_MODES = (MODE_STRICT, MODE_POLICY, MODE_PREDICATE)


def _classify_action(mode, pred, gt_eff, gt_key, task_keys, world, domain, policy):
    """Policy TIER pre-gate, then the shared per-mode resolution classifier."""
    tier = policy.tier_for(gt_eff.effect_class)
    if tier != TIER_AUTO:
        return dict(cls=ESCALATE, cause=f"tier={tier}", endorsed_recipient=None,
                    endorsed_amount_cents=None, bounded=None)
    return _classify_effect(mode, pred, gt_eff, gt_key, task_keys, world, domain,
                            domain.standing_policy)


def build_rows(domain, world, tasks, modes, policy):
    extract = domain.build_extractor()
    rows = []
    for t in tasks:
        if t.category == "volume":            # volume feeds the velocity summary, not HITL
            continue
        effs = [domain.effect_for_pr(n, world) for n in t.gt_prs]
        effs = [e for e in effs if e is not None]
        if not effs:
            continue
        pred = extract(t.PROMPT)              # frozen from the instruction ONLY
        task_keys = {effect_key(e.effect_class, e.target_id) for e in effs}
        for e in effs:
            gt_key = effect_key(e.effect_class, e.target_id)
            row = PlanRow(t.ID, e.effect_class, str(e.target_id), int(e.amount_cents),
                          t.bucket, "", "")
            for m in modes:
                row.by_mode[m] = _classify_action(m, pred, e, gt_key, task_keys, world,
                                                  domain, policy)
            rows.append(row)
    return rows


def velocity_summary(tasks, policy, principal=PRINCIPAL) -> dict:
    vol = [t for t in tasks if t.category == "volume" and t.principal == principal]
    n, cap = len(vol), policy.merges_per_day
    return dict(principal=principal, burst=n, cap=cap,
                cleared=min(n, cap), escalated=max(0, n - cap))


@dataclass
class GithubDiagnostic:
    policy: object
    rows: list
    n: int
    velocity: dict = field(default_factory=dict)


def run(source: Optional[PolicySource] = None, modes=ALL_MODES, repo=REPO,
        principal=PRINCIPAL, tasks=None, world=None, do_print=True) -> GithubDiagnostic:
    source = source or InMemoryPolicySource()      # default -> DEFAULT_MERGE_POLICY
    policy = source.load_effective_policy(repo, principal)
    domain = GitHubDomain(policy=policy)           # the domain fence == the enforced fence
    world = world if world is not None else build_corpus_world()
    tasks = tasks if tasks is not None else CORPUS
    modes = list(modes)

    rows = build_rows(domain, world, tasks, modes, policy)
    vel = velocity_summary(tasks, policy, principal)

    if do_print:
        print("\nGITHUB RAIL-BRIDGE diagnostic (plan-time; offline; policy-sourced fence)")
        print(f"effect: merge a pull request to a protected branch   modes={modes}")
        print(describe_effective_policy(policy, repo, principal))
        print_domain_table("github", modes, rows, None)
        print("VELOCITY (merges/principal/day, the rate limit -- separate from per-action HITL):")
        print(f"  principal={vel['principal']}  burst={vel['burst']}  cap={vel['cap']}  "
              f"cleared={vel['cleared']}  velocity-escalated={vel['escalated']}")
        print("-" * 78)
    return GithubDiagnostic(policy, rows, len(rows), vel)


if __name__ == "__main__":
    run()
