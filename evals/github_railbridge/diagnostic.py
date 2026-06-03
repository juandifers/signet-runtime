"""Plan-time diagnostic for the GitHub rail-bridge domain.

REUSES the existing plan-time harness unchanged:
  * `evals.agentdojo.diagnostic._classify_effect`  (CORRECT / WRONG[bounded] / ESCALATE)
  * `evals.agentdojo.diagnostic.print_domain_table` (the headline HITL-load table)
  * `evals.agentdojo.taxonomy`                       (DI / DIQ / DD bucketing)
the SAME way effect-key domains (workspace/slack/travel) are diagnosed. No agent
rollouts (the §1 plan-time layer only); fully offline.

Run:  python3 -m evals.github_railbridge.diagnostic
"""
from __future__ import annotations

from evals.agentdojo.diagnostic import PlanRow, _classify_effect, print_domain_table
from evals.agentdojo.gate import MODE_POLICY, MODE_PREDICATE, MODE_STRICT
from evals.effect_core import effect_key

from .domain import GitHubDomain
from .tasks import TASKS, build_world

ALL_MODES = (MODE_STRICT, MODE_POLICY, MODE_PREDICATE)


def build_rows(domain: GitHubDomain, world, tasks, modes):
    extract = domain.build_extractor()
    rows = []
    for t in tasks:
        effs = [domain.effect_for_pr(n, world) for n in t.gt_prs]
        effs = [e for e in effs if e is not None]
        if not effs:
            continue
        pred = extract(t.PROMPT)                       # frozen from the instruction ONLY
        task_keys = {effect_key(e.effect_class, e.target_id) for e in effs}
        for e in effs:
            bucket, src = domain.classify(t.PROMPT, e.effect_class, e.target_id, world)
            gt_key = effect_key(e.effect_class, e.target_id)
            row = PlanRow(t.ID, e.effect_class, str(e.target_id), int(e.amount_cents),
                          bucket, src, "")
            for m in modes:
                row.by_mode[m] = _classify_effect(
                    m, pred, e, gt_key, task_keys, world, domain, domain.standing_policy)
            rows.append(row)
    return rows


def run(modes=ALL_MODES):
    domain = GitHubDomain()
    world = build_world()
    rows = build_rows(domain, world, TASKS, list(modes))
    print("\nGITHUB RAIL-BRIDGE diagnostic (plan-time; offline; no rollouts)")
    print(f"effect: merge a pull request to a protected branch   modes={list(modes)}")
    print(f"standing policy: {domain.standing_policy.description}")
    print_domain_table("github", list(modes), rows, None)
    return rows


if __name__ == "__main__":
    run()
