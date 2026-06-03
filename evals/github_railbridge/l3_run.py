"""L3 manual runner — drive the LIVE GitHub rail for a first hand test.

    python -m evals.github_railbridge.l3_run --dry-run   # print what it WOULD post
    python -m evals.github_railbridge.l3_run             # actually post Check Runs

For each open PR on SIGNET_GH_REPO: read changed files + head_sha + base, run the SAME
offline decision path (enforce_merge over a PolicySource with the default policy), and post
a real Check Run named "signet/enforced" reflecting the verdict. The decision logic is
unchanged -- this only swaps MockGitHubRail for LiveGitHubRail.

FAIL CLOSED: a blocked/escalated decision -> conclusion=failure; any error reading a PR or
deciding -> post failure (when a head_sha is known) or post nothing -- never success/neutral.
"""
from __future__ import annotations

import argparse
import sys

from .enforce import enforce_merge
from .merge_chain import PRINCIPAL, make_github_env
from .policy import InMemoryPolicySource, describe_effective_policy


def _conclusion(approved: bool) -> str:
    return "success" if approved else "failure"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Signet L3 live GitHub rail runner.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the effect/decision/conclusion WITHOUT posting")
    ap.add_argument("--repo", default=None,
                    help="override SIGNET_GH_REPO (owner/repo); policy is keyed on it")
    args = ap.parse_args(argv)

    # Build the live rail from the operator's environment (fail closed on missing creds).
    try:
        from .live_rail import LiveGitHubRail
        rail = LiveGitHubRail.from_env()
    except Exception as e:
        print(f"ERROR: cannot initialize the live GitHub rail: {e}", file=sys.stderr)
        return 2

    repo_id = args.repo or rail.repo
    source = InMemoryPolicySource()          # default policy (DEFAULT_MERGE_POLICY)
    env = make_github_env()                  # the Signet enforcer (local keys + verifier)

    print(f"Signet L3 runner  repo={repo_id}  principal={PRINCIPAL}  "
          f"mode={'DRY-RUN' if args.dry_run else 'LIVE'}")
    print(describe_effective_policy(source.load_effective_policy(repo_id, PRINCIPAL),
                                    repo_id, PRINCIPAL))
    print("-" * 78)

    try:
        prs = rail.list_open_prs()
    except Exception as e:
        print(f"ERROR: cannot list open PRs: {e}", file=sys.stderr)
        return 2
    if not prs:
        print("No open PRs.")
        return 0

    posted = 0
    for pr in prs:
        head_sha = None
        try:
            files, head_sha, base = rail.read_pr(pr)
            decision = enforce_merge(env, source, repo_id=repo_id, principal_id=PRINCIPAL,
                                     pr=pr, base=base, head_sha=head_sha, touched_paths=files)
            conclusion = _conclusion(decision.approved)
            summary = (f"tier={decision.tier}  effect={decision.effect_class}  "
                       f"approved={decision.approved}\n{decision.reason}")
            print(f"PR #{pr}  base={base}  head={head_sha[:8]}  files={len(files)}  "
                  f"effect={decision.effect_class}  tier={decision.tier}  -> {conclusion}")
        except Exception as e:
            # Fail closed: known head -> post failure; unknown head -> post nothing.
            print(f"PR #{pr}  ERROR: {e}  -> {'posting FAILURE' if head_sha else 'posting nothing'} "
                  f"(fail closed)")
            if head_sha and not args.dry_run:
                try:
                    rail.post_check(head_sha, "failure", f"Signet error: {e}")
                except Exception as pe:
                    print(f"        (failure post also failed: {pe})")
            continue

        if args.dry_run:
            print(f"        WOULD post check '{rail.CHECK_NAME}' @ {head_sha[:8]} = {conclusion}")
            continue
        try:
            cid = rail.post_check(head_sha, conclusion, summary)
            posted += 1
            print(f"        posted check {cid} = {conclusion}")
        except Exception as e:
            print(f"        POST FAILED: {e} (fail closed: no success recorded)")

    print("-" * 78)
    print(f"Done. {len(prs)} PR(s) evaluated, {posted} check run(s) posted"
          f"{' (dry-run: 0)' if args.dry_run else ''}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
