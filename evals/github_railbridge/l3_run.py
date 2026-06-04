"""L3 manual runner — drive the LIVE GitHub rail under a per-task AP2 Open/Closed mandate.

    python -m evals.github_railbridge.l3_run --mandate-file path/to/mandate.json --dry-run
    python -m evals.github_railbridge.l3_run --mandate-file path/to/mandate.json

The operator passes an OpenMandate (the job's TRUSTED grant: a path scope that narrows the
standing fence, a target criterion, and caps) via --mandate-file. It is loaded and FROZEN
BEFORE any PR, issue body, or other runtime data is read -- the same isolation discipline as
the §6 extractor: runtime data has NO channel into the grant.

For every open PR on SIGNET_GH_REPO: read changed files + head_sha + base (the low-capacity
decision input), assemble the principal's OWN-PR world, then:
  * effective fence = standing PolicySource INTERSECT OpenMandate (monotonic; only tightens);
  * resolve the criterion bounded-to-own -> a ClosedMandate (the bound effect), or escalate
    with ``unresolved_constraint`` (off-scope / ambiguous / named only in runtime data);
  * route the decision through GitHubRailBridge.authorize (verify_token + an independent
    effect-vs-context re-check) -- NOT a post_check short-circuit -- which concludes the
    required Check Run; a signed receipt is appended for EVERY decision (allow / block /
    review). Any open PR that is NOT the mandate's resolved target gets a fail-closed
    failure check (it is not authorized by THIS job).

FAIL CLOSED: a blocked/escalated/unauthorized PR -> conclusion=failure; any error reading a
PR -> failure when a head_sha is known, else nothing -- never success/neutral.

NOTE (the live demo of the injection redirect is DEFERRED to a manual run): the live rail
read only yields files/head_sha/base, so descriptor/issue criteria that need a title or
issue linkage will ESCALATE here (fail closed). The argument-injection redirect property is
proven OFFLINE in tests/test_github_railbridge_open_mandate.py.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from signet.receipts import ReceiptLog
from signet.authorizers.github_railbridge import GitHubRailBridge, MockGitHubRail

from .domain import target_id
from .mandate import (RESOLVED, authorize_closed_mandate, explain_pr, injection_targets,
                      load_open_mandate, resolve_task_mandate)
from .merge_chain import PRINCIPAL, make_github_env
from .policy import InMemoryPolicySource, describe_effective_policy
from .enforce import resolve_effective_policy


def _conclusion(approved: bool) -> str:
    return "success" if approved else "failure"


def _load_dotenv(path: Path) -> int:
    """Populate os.environ from a .env file WITHOUT overwriting already-exported vars.

    Dependency-free (no python-dotenv): handles `KEY=VALUE`, an optional `export `
    prefix, surrounding quotes, and `#` comments. Real shell exports always win, so a
    committed-by-accident value can't shadow what the operator deliberately set. Returns
    the number of vars loaded; silently does nothing if the file is absent.
    """
    if not path.is_file():
        return 0
    loaded = 0
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if val[:1] in ('"', "'"):
            # quoted value: take exactly what's inside the matching quote, keep any '#'
            q = val[0]
            end = val.find(q, 1)
            val = val[1:end] if end != -1 else val[1:]
        else:
            # unquoted: a ' #' (space then hash) starts an inline comment
            hash_at = val.find(" #")
            if hash_at != -1:
                val = val[:hash_at]
            val = val.strip()
        if key and key not in os.environ:
            os.environ[key] = val
            loaded += 1
    return loaded


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Signet L3 live GitHub rail runner (Open/Closed mandate).")
    ap.add_argument("--mandate-file", required=True,
                    help="path to a TRUSTED OpenMandate JSON file (loaded BEFORE any PR/issue "
                         "read); see evals/github_railbridge/example_mandate.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="decide + print WITHOUT posting any Check Run (uses a mock rail to "
                         "drive the SAME authorizer two-step)")
    ap.add_argument("--repo", default=None,
                    help="override SIGNET_GH_REPO (owner/repo); policy is keyed on it")
    ap.add_argument("--env-file", default=".env",
                    help="path to a .env file to load (real exports take precedence); "
                         "default '.env', skipped if absent")
    ap.add_argument("--resolver", choices=("deterministic", "llm", "adversarial"),
                    default="deterministic",
                    help="WHO proposes the candidate PR. 'deterministic' (default) = the "
                         "offline bounded-to-own resolver, NO LLM. 'llm' = a real-Claude "
                         "QUARANTINED Role B (needs ANTHROPIC_API_KEY). 'adversarial' = a "
                         "no-LLM stub that ALWAYS picks the off-scope PR (shows the gates "
                         "contain a fooled resolver). The gates run on the pick either way.")
    ap.add_argument("--provider", choices=("openai", "anthropic"), default=None,
                    help="LLM provider for --resolver=llm (default: auto-detect from the key "
                         "in the env — OPENAI_API_KEY -> openai)")
    ap.add_argument("--model", default=None,
                    help="model id for --resolver=llm (default: the provider's built-in)")
    ap.add_argument("--adversarial-pr", type=int, default=None,
                    help="PR id the 'adversarial' stub resolver always picks (default: the "
                         "highest-numbered open PR, i.e. the planted attacker)")
    args = ap.parse_args(argv)

    # --- THE GRANT IS TRUSTED INPUT: load + freeze it BEFORE touching any rail/runtime data. ---
    try:
        open_mandate = load_open_mandate(args.mandate_file)
    except Exception as e:
        print(f"ERROR: cannot load the OpenMandate from {args.mandate_file}: {e}", file=sys.stderr)
        return 2

    n = _load_dotenv(Path(args.env_file))
    if n:
        print(f"Loaded {n} var(s) from {args.env_file} (shell exports take precedence).")

    # Build the live rail from the operator's environment (fail closed on missing creds).
    try:
        from .live_rail import LiveGitHubRail, world_from_rail
        rail = LiveGitHubRail.from_env()
    except Exception as e:
        print(f"ERROR: cannot initialize the live GitHub rail: {e}", file=sys.stderr)
        return 2

    repo_id = args.repo or rail.repo
    source = InMemoryPolicySource()          # standing fence (DEFAULT_MERGE_POLICY)
    env = make_github_env()                  # the Signet enforcer (local keys + verifier)
    receipts = ReceiptLog(env.enforcer_sk, env.enforcer_vk)
    # Dry-run drives the SAME authorizer two-step against a mock rail (no network writes);
    # live mode concludes real Check Runs through the live rail.
    bridge = GitHubRailBridge(env.verifier, env.enforcer_vk,
                              github_rail=(MockGitHubRail() if args.dry_run else rail))

    effective = resolve_effective_policy(source, repo_id, PRINCIPAL,
                                         open_mandate.as_task_policy())
    print(f"Signet L3 runner  repo={repo_id}  principal={PRINCIPAL}  "
          f"mode={'DRY-RUN' if args.dry_run else 'LIVE'}")
    print(f"OpenMandate  criterion={open_mandate.criterion!r}  scope={list(open_mandate.scope_allow)}"
          f"  cap={open_mandate.cap}")
    print(describe_effective_policy(effective, repo_id, PRINCIPAL))
    print("-" * 78)

    try:
        prs = rail.list_open_prs()
    except Exception as e:
        print(f"ERROR: cannot list open PRs: {e}", file=sys.stderr)
        return 2
    if not prs:
        print("No open PRs.")
        return 0

    # Assemble the principal's OWN-PR world from the UNTRUSTED runtime data each PR exposes
    # (files/sha/base + title/body/head ref + linked issue + issue body). This feeds ONLY the
    # bounded-to-own resolver against the operator's frozen criterion; it never touches the
    # mandate or the fence. A PR whose runtime data can't be fetched is skipped (fail closed).
    world, skipped = world_from_rail(rail, repo_id, prs)
    for pr in skipped:
        print(f"PR #{pr}  ERROR reading runtime data -> skipping (fail closed, no target)")
    head_by_pr = {pr: rec.head_sha for pr, rec in world.open_prs.items()}

    # --- WHO proposes the candidate (opt-in). Default = deterministic, NO LLM call. ---
    resolver = None
    trace_store = None
    if args.resolver != "deterministic":
        from .resolver import FixedChoiceResolver, make_resolver
        from .transparency import ReasoningTraceStore
        trace_store = ReasoningTraceStore()      # SEPARATE untrusted-narrative store
        if args.resolver == "llm":
            try:
                resolver = make_resolver(provider=args.provider, model=args.model)
            except Exception as e:
                print(f"ERROR: cannot initialize the LLM resolver: {e}", file=sys.stderr)
                return 2
            print(f"Role B = QUARANTINED real-LLM resolver "
                  f"(provider={args.provider or 'auto'}, model={args.model or 'default'}); "
                  f"the gates run on its pick regardless of what it returns.")
        else:  # adversarial — a no-LLM stub that always picks the off-scope PR.
            pick = args.adversarial_pr or (max(world.open_prs) if world.open_prs else None)
            resolver = FixedChoiceResolver(pick, reason="forced (adversarial stub) pick")
            print(f"Role B = ADVERSARIAL stub that ALWAYS picks #{pick} (no LLM); "
                  f"the gates must contain it.")

    # Resolve the OpenMandate over the world (bounded-to-own) -> a ClosedMandate or escalate.
    resolution = resolve_task_mandate(open_mandate, world, effective,
                                      resolver=resolver, trace_store=trace_store)
    if resolution.reasoning_trace_hash:
        print(f"Role B reason: {resolution.reasoning_trace}".replace("\n", " ")[:300])
        print(f"reasoning_trace_hash (committed into the DecisionRecord, NOT the anchor): "
              f"{resolution.reasoning_trace_hash}")
    if resolution.kind == RESOLVED:
        print(f"resolved target: PR #{resolution.closed.pr}  -> {resolution.closed.bound_target}")
    else:
        print(f"UNRESOLVED: {resolution.cause}  (job ESCALATES, no autonomous merge)")
    for n in injection_targets(world):
        print(f"  injection-channel named PR #{n} (runtime data) -> never an authorized target")

    # Per-PR "why": allow-list ceiling (in-repo + base) THEN the scope/protected fence THEN
    # the criterion's issue THEN the verdict. Reads like an audit of the discrimination.
    resolved_pr = resolution.closed.pr if resolution.kind == RESOLVED else None
    crit_issue = open_mandate.criterion_issue()
    print("decisions (allow-list ceiling -> scope/protected fence -> criterion -> verdict):")
    for pr in sorted(world.open_prs):
        print("  " + explain_pr(world.open_prs[pr], effective, configured_repo=repo_id,
                                criterion_issue=crit_issue, endorsed_pr=resolved_pr))

    endorsed_pr = None
    posted = 0
    if resolution.kind == RESOLVED:
        outcome = authorize_closed_mandate(env, bridge, receipts, repo_id=repo_id,
                                           closed=resolution.closed, effective=effective)
        endorsed_pr = resolution.closed.pr if outcome.approved else None
        verb = "posted" if (outcome.approved and not args.dry_run) else \
               ("WOULD post" if args.dry_run else "did NOT post")
        print(f"PR #{resolution.closed.pr}  authorizer -> approved={outcome.approved}  "
              f"tier={outcome.tier}  ({verb} check {outcome.check_ref})")
        print(f"        reason: {outcome.reason}")
        if outcome.approved and not args.dry_run:
            posted += 1

    # Every OTHER open PR is NOT authorized by THIS job's mandate -> fail-closed failure check.
    for pr, rec in world.open_prs.items():
        if pr == endorsed_pr:
            continue
        head_sha = head_by_pr.get(pr)
        reason = ("the mandate's resolved target" if resolution.kind == RESOLVED
                  else f"unresolved_constraint ({resolution.cause})")
        receipts.append(
            execution_id=f"exec_unauth_{pr}", mandate_id=f"open:{repo_id}",
            chain_hash=target_id(repo_id, pr, rec.base, rec.head_sha),
            policy_id=f"effective:{repo_id}", decision="review",
            payment_status=f"not-authorized-by-mandate (not {reason})",
            payment_ref=None, rail="github")
        if args.dry_run:
            print(f"PR #{pr}  not authorized by this mandate -> WOULD post failure")
            continue
        try:
            rail.post_check(head_sha, "failure", "Not authorized by this job's mandate.")
            print(f"PR #{pr}  not authorized by this mandate -> posted failure")
        except Exception as e:
            print(f"PR #{pr}  POST FAILED: {e} (fail closed: no success recorded)")

    print("-" * 78)
    print(f"Done. {len(world.open_prs)} PR(s) evaluated, {posted} success check(s) posted"
          f"{' (dry-run: 0)' if args.dry_run else ''}, "
          f"{len(receipts.all())} receipt(s) appended.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
