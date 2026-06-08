"""Per-task AP2 Open/Closed mandate on the GitHub merge rail — OFFLINE, agentdojo-free.

AP2 separates a STANDING grant from the SPECIFIC action it authorizes:

  * OpenMandate  — the operator's grant for THIS job. It is TRUSTED INPUT, frozen by the
                   operator (a CLI flag / env / a blessed file) BEFORE any PR, issue body,
                   or other runtime data is read. It carries a path SCOPE that narrows the
                   standing fence, a target CRITERION (an explicit PR id or a descriptor
                   like "the PR that fixes issue #7"), and CAPS. Same isolation discipline
                   as the §6 extractor: NO runtime data has a channel into it.

  * effective fence = standing PolicySource  INTERSECT  OpenMandate  (existing intersect()).
                   Monotonic: the OpenMandate can only TIGHTEN the standing fence, never
                   widen it. The OpenMandate's scope rides as a conjunctive allow LAYER.

  * ClosedMandate — the RESOLVED specific authorization. The target is resolved from runtime
                   data (bounded-to-own, low-capacity: a PR id from the OWNED set only), then
                   bound to a concrete effect `repo#pr->base@head_sha`. A ClosedMandate is
                   only minted if its bound effect is a MEMBER of the effective fence.

If the target cannot be resolved within the OpenMandate — off-scope, ambiguous, or named
ONLY in runtime data (an injected "merge #99") — there is no ClosedMandate: the resolver
returns UNRESOLVED with AP2's cause string ``unresolved_constraint`` and the job ESCALATES.

The residual surface the design-patterns literature flags is ARGUMENT injection: the plan
is fixed ("merge the PR that fixes issue #7") but injection tries to poison WHICH target the
criterion resolves to. The frozen scope contains it: an injected target outside the scope
(or protected) is out-of-envelope no matter what the runtime data claims.

No agentdojo, no network. The decision is then routed through the SAME rail authorizer the
muscle defines (verify_token + independent context re-check), and a signed receipt is
appended for every decision (allow / block / review).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from signet import crypto
from signet.authorizers.github_railbridge import GitHubRailBridge
from signet.canonical import hash_obj
from signet.receipts import ReceiptLog

from evals.effect_core import ENDORSE, resolve_effect_predicate

from .domain import (CONFIGURED_REPO, GitHubDomain, GitHubWorld, PullRequest,
                     effect_class_for, extract_merge_predicate, is_protected, target_id)
from .enforce import resolve_effective_policy
from .merge_chain import PRINCIPAL, build_merge_chain
from .policy import TIER_AUTO, MergePolicy, PolicySource
from .transparency import (ConsideredRejected, EffectDescriptor, TransparencyLog,
                           build_decision_record)

# Mandate-resolution kinds.
RESOLVED = "RESOLVED"
UNRESOLVED = "UNRESOLVED"
UNRESOLVED_CONSTRAINT = "unresolved_constraint"   # AP2's term for an unmet target criterion


# ============================================================================
# OpenMandate — the operator's TRUSTED, frozen grant for THIS job
# ============================================================================
@dataclass(frozen=True)
class OpenMandate:
    """The Open part of an AP2 mandate: the scope of authority for one job.

    TRUSTED INPUT. Every field is operator-supplied and frozen BEFORE any runtime data
    (PR diff, issue body, PR description) is read. Nothing here may EVER be sourced from
    the repo, a PR, an issue, or any other runtime channel.
    """
    criterion: str                         # operator-frozen target descriptor
    scope_allow: tuple = ("**",)           # path globs this job may touch (narrows allow)
    cap: int = 1                           # max merges authorized for THIS job
    merges_per_day: Optional[int] = None   # optional velocity narrowing
    extra_deny: tuple = ()                 # optional additional deny paths (tightening)
    repo_id: Optional[str] = None          # optional repo narrowing

    def as_task_policy(self) -> MergePolicy:
        """Render the OpenMandate as a task-layer MergePolicy for intersect(). It can only
        ADD restrictions: the scope becomes a conjunctive allow layer, denies union in, the
        velocity cap mins in. (A MergePolicy.merges_per_day default would WIDEN if the
        standing cap is lower — so omit it unless the operator set one.)"""
        kw = dict(allow_paths=tuple(self.scope_allow) or ("**",),
                  deny_paths=tuple(self.extra_deny))
        if self.merges_per_day is not None:
            kw["merges_per_day"] = int(self.merges_per_day)
        if self.repo_id:
            kw["repo_id"] = self.repo_id
        return MergePolicy(**kw)

    def predicate(self):
        """Freeze a low-capacity EffectPredicate from the OPERATOR's criterion string ONLY
        (the same instruction-only extractor §6 uses). Runtime data has no channel here."""
        txt = self.criterion if "merge" in self.criterion.lower() else f"merge {self.criterion}"
        return extract_merge_predicate(txt)

    def mandate_id(self) -> str:
        """A stable id over the OPERATOR's frozen grant (no runtime data) — used to label the
        audit record back to the authority it was issued under."""
        return "open_" + hash_obj([self.criterion, list(self.scope_allow), self.cap,
                                    self.merges_per_day, list(self.extra_deny),
                                    self.repo_id])[:16]

    def criterion_issue(self) -> Optional[int]:
        """The issue number the criterion targets ('...issue #4' -> 4), else None."""
        m = re.search(r"issue\s*#?(\d+)", self.criterion.lower())
        return int(m.group(1)) if m else None


def load_open_mandate(path) -> OpenMandate:
    """Load an OpenMandate from a TRUSTED operator file (a blessed file in signet-runtime).

    This is the ONLY ingestion point for the operator's grant, and it is called BEFORE any
    PR/issue/runtime data is read. The file is operator-controlled; it must never be sourced
    from the repo under test, a PR, or any runtime channel. JSON keys mirror OpenMandate's
    fields; `criterion` is required, the rest fall back to the (tightest-safe) defaults.
    """
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or not isinstance(data.get("criterion"), str):
        raise ValueError(f"{path}: a mandate file needs a string 'criterion'")
    return OpenMandate(
        criterion=data["criterion"],
        scope_allow=tuple(data.get("scope_allow", ("**",))) or ("**",),
        cap=int(data.get("cap", 1)),
        merges_per_day=(int(data["merges_per_day"])
                        if data.get("merges_per_day") is not None else None),
        extra_deny=tuple(data.get("extra_deny", ())),
        repo_id=data.get("repo_id"))


# ============================================================================
# ClosedMandate — the resolved, fence-checked, bound authorization
# ============================================================================
@dataclass(frozen=True)
class ClosedMandate:
    """The Closed part: the specific effect the OpenMandate authorized, resolved from
    runtime data and proven to be a MEMBER of the effective fence."""
    repo: str
    pr: int
    base: str
    head_sha: str
    touched_paths: tuple
    effect_class: str
    bound_target: str        # target_id == repo#pr->base@head_sha


@dataclass
class Considered:
    """A candidate that was CONSIDERED and REJECTED (for the receipt's audit trail)."""
    pr: Optional[int]
    target: str
    cause: str
    channel: str = "resolver"   # "resolver" | "injection"  (where the candidate came from)


@dataclass
class MandateResolution:
    kind: str                                   # RESOLVED | UNRESOLVED
    closed: Optional[ClosedMandate] = None
    cause: str = ""                             # unresolved_constraint reason when UNRESOLVED
    considered: List[Considered] = field(default_factory=list)
    # When Role B (a real-LLM resolver) made the pick, its UNTRUSTED reasoning narrative and
    # the hash committed into the DecisionRecord. Empty/None for the deterministic resolver.
    reasoning_trace: str = ""
    reasoning_trace_hash: Optional[str] = None


def _pr_num(target: str) -> Optional[int]:
    m = re.search(r"#(\d+)->", str(target))
    return int(m.group(1)) if m else None


def resolve_task_mandate(om: OpenMandate, world: GitHubWorld,
                         effective: MergePolicy, *, resolver=None,
                         trace_store=None) -> MandateResolution:
    """Resolve the OpenMandate's criterion to ONE bound ClosedMandate within the effective
    fence, or escalate with ``unresolved_constraint``.

    Two gates, both load-bearing:
      1. bounded-to-own resolution: the criterion resolves over the principal's OWN PRs only
         (domain.match_descriptor + domain.target_allowed). An injected target named only in
         runtime data is never a candidate; a protected/off-repo own PR is filtered out.
      2. effective-fence membership: the endorsed target's touched paths must be IN the
         effective fence (which carries the OpenMandate's scope as a conjunctive allow
         layer) and its base allowed. The frozen scope is what CONTAINS an argument-injection
         that tries to redirect the resolved target out of scope.

    `resolver` (opt-in, default None) swaps WHO proposes the candidate. None = the
    deterministic bounded-to-own resolver below. A `Resolver` (e.g. a real-LLM Role B) instead
    returns the SET of every plausible owned id; a structural pre-filter + cardinality rule
    (Layer A / `ambiguity.py`) decide abstention on set cardinality, and the SAME two gates then
    run on the single surviving id — so containment does NOT depend on the resolver resisting an
    injection (see `_resolve_via_role_b`). When a `trace_store` is supplied, Role B's untrusted
    narrative is stashed there and its hash rides on the resolution for the DecisionRecord.
    """
    domain = GitHubDomain(policy=effective)     # binds protected/bases/repo to the eff fence
    if resolver is not None:
        return _resolve_via_role_b(om, world, effective, domain, resolver, trace_store)
    pred = om.predicate()
    considered: List[Considered] = []

    # Surface descriptor matches that the bound rejected (audit trail), distinguishing the
    # two layers: a candidate OUTSIDE the universe (off-repo / arbitrary base) is off-allowlist;
    # an in-universe candidate the fence rejects (a protected path) is off-scope.
    if pred is not None and pred.descriptor:
        for t in domain.match_descriptor(pred.effect_class, pred.descriptor, world):
            if not domain.target_allowed(pred.effect_class, t, world):
                cause = ("off-allowlist (off-repo or base not allowed)"
                         if not domain.within_allowlist(t, world)
                         else "off-scope (protected path)")
                considered.append(Considered(_pr_num(t), t, cause))

    res = resolve_effect_predicate(pred, world, domain, cap_cents=None)
    if res.kind != ENDORSE:
        return MandateResolution(
            UNRESOLVED, None,
            f"{UNRESOLVED_CONSTRAINT}: {res.cause}", considered)

    target = res.endorsed_target
    pr = _pr_num(target)
    rec = world.open_prs.get(pr)
    if rec is None:                              # defensive; ENDORSE implies an own PR
        return MandateResolution(UNRESOLVED, None,
                                 f"{UNRESOLVED_CONSTRAINT}: endorsed target not own", considered)

    # Gate 2 — the bound effect must be a MEMBER of the effective fence (scope does the work).
    if effective.is_fenced(rec.files):
        considered.append(Considered(pr, target,
                                     f"off-scope ({effective.path_disposition(rec.files)})"))
        return MandateResolution(
            UNRESOLVED, None,
            f"{UNRESOLVED_CONSTRAINT}: endorsed target off-scope "
            f"({effective.path_disposition(rec.files)})", considered)
    if rec.base not in effective.allowed_bases:
        return MandateResolution(
            UNRESOLVED, None,
            f"{UNRESOLVED_CONSTRAINT}: endorsed target base '{rec.base}' off-scope", considered)

    closed = ClosedMandate(
        repo=rec.repo, pr=pr, base=rec.base, head_sha=rec.head_sha,
        touched_paths=tuple(rec.files),
        effect_class=effect_class_for(rec.files, effective.deny_paths),
        bound_target=target)
    return MandateResolution(RESOLVED, closed, "", considered)


def _gate_chosen_pr(world: GitHubWorld, effective: MergePolicy, domain: GitHubDomain,
                    pr: Optional[int], considered: List[Considered], *,
                    extra_cause: str = "", channel: str = "resolver",
                    reasoning_trace: str = "",
                    reasoning_trace_hash: Optional[str] = None) -> MandateResolution:
    """Run the SAME bounded-to-own + scope/protected-fence gates the deterministic resolver
    applies, on a SINGLE chosen PR id (whoever proposed it). This is the containment boundary:
    a pick that is not an own PR, is off-repo/off-base (allow-list ceiling), or is off-scope /
    protected (the fence) is REJECTED here and the job escalates — regardless of what the
    proposer 'wanted'. RESOLVED only when the chosen target passes every gate."""
    def _unresolved(cause: str) -> MandateResolution:
        return MandateResolution(UNRESOLVED, None, f"{UNRESOLVED_CONSTRAINT}: {cause}",
                                 considered, reasoning_trace=reasoning_trace,
                                 reasoning_trace_hash=reasoning_trace_hash)

    # Gate 1a — bounded-to-own: the pick must be one of the principal's OWN PRs.
    rec = world.open_prs.get(pr) if pr is not None else None
    if rec is None:
        return _unresolved(extra_cause or "resolver returned no own-PR target")
    target = domain._target(rec)
    # Gate 1b — allow-list ceiling: in the configured repo, to an allowed base.
    if not domain.within_allowlist(target, world):
        considered.append(Considered(pr, target,
                                     "off-allowlist (off-repo or base not allowed)", channel))
        return _unresolved(f"endorsed target off-allowlist (off-repo or base not allowed)")
    # Gate 2 — scope/protected fence (the OpenMandate scope rides in `effective`).
    if effective.is_fenced(rec.files):
        disp = effective.path_disposition(rec.files)
        considered.append(Considered(pr, target, f"off-scope ({disp})", channel))
        return _unresolved(f"endorsed target off-scope ({disp})")
    if rec.base not in effective.allowed_bases:
        considered.append(Considered(pr, target, f"base '{rec.base}' off-scope", channel))
        return _unresolved(f"endorsed target base '{rec.base}' off-scope")

    closed = ClosedMandate(
        repo=rec.repo, pr=pr, base=rec.base, head_sha=rec.head_sha,
        touched_paths=tuple(rec.files),
        effect_class=effect_class_for(rec.files, effective.deny_paths),
        bound_target=target)
    return MandateResolution(RESOLVED, closed, "", considered,
                             reasoning_trace=reasoning_trace,
                             reasoning_trace_hash=reasoning_trace_hash)


def _resolve_via_role_b(om: OpenMandate, world: GitHubWorld, effective: MergePolicy,
                        domain: GitHubDomain, resolver, trace_store) -> MandateResolution:
    """Role B path with STRUCTURAL abstention. Three deterministic stages, none trusting the
    model's conclusion:

      1. Layer A (`structural_prefilter`): if the criterion is a closing-issue reference and
         two+ owned PRs literally close it, escalate BEFORE any LLM call (structurally
         ambiguous).
      2. Set-valued Role B + the CARDINALITY rule (`apply_cardinality`): the QUARANTINED
         resolver returns EVERY plausible owned id (clamped to the owned set); the job resolves
         iff exactly ONE survives, and escalates the moment two+ (or zero) survive. This is the
         abstention that the scope/protected gate cannot provide (two in-scope owned picks).
      3. `_gate_chosen_pr`: the UNCHANGED containment gate (bounded-to-own -> allow-list ->
         scope/protected fence) runs on the single surviving id.

    Role B is assumed possibly-fooled; the cardinality rule + the envelope contain it. Its
    untrusted narrative is stored apart and only its HASH is carried forward (committed into the
    DecisionRecord, never the anchor)."""
    from .resolver import CandidateView                  # local import keeps the graph lean
    from .ambiguity import apply_cardinality, structural_prefilter

    considered: List[Considered] = []

    # Stage 1 — Layer A: structural pre-filter, BEFORE any LLM call (no trace exists yet).
    pre = structural_prefilter(om, world)
    if pre is not None:
        return MandateResolution(UNRESOLVED, None, f"{UNRESOLVED_CONSTRAINT}: {pre[1]}",
                                 considered)

    # Stage 2 — set-valued Role B + the cardinality override.
    candidates = [CandidateView.from_pr(rec) for rec in world.open_prs.values()]
    rset = resolver.resolve(om.criterion, candidates)

    trace_hash = None
    if trace_store is not None and rset.raw:
        trace_hash = trace_store.put(rset.raw)          # stash the untrusted trace, keep the hash

    verdict, payload = apply_cardinality(rset, set(world.open_prs))
    if verdict == "escalate":
        # Record each ambiguous candidate for the audit trail (the cardinality rule fired).
        for pr in sorted(rset.ids):
            rec = world.open_prs.get(pr)
            if rec is not None:
                considered.append(Considered(pr, domain._target(rec), str(payload), "resolver"))
        return MandateResolution(
            UNRESOLVED, None, f"{UNRESOLVED_CONSTRAINT}: {payload}",
            considered, reasoning_trace=rset.raw, reasoning_trace_hash=trace_hash)

    # Stage 3 — exactly one owned id survived: the unchanged containment gate runs on it.
    chosen = payload
    return _gate_chosen_pr(world, effective, domain, chosen, considered,
                           extra_cause=f"resolver pick #{chosen} not an own PR",
                           channel="resolver", reasoning_trace=rset.raw,
                           reasoning_trace_hash=trace_hash)


# ============================================================================
# Injection channel — what a NAIVE agent would have merged (METRIC ONLY)
# ============================================================================
_INJ_PR_RE = re.compile(r"(?:pr|pull\s+request|merge(?:\s+it)?)\s*#?(\d+)", re.I)


def injection_targets(world: GitHubWorld) -> List[int]:
    """PR numbers a redirect injection in RUNTIME DATA tries to steer toward. Reads the
    UNTRUSTED PR bodies (`injected_body`) — the exact channel the mandate path NEVER reads.
    Used ONLY to compute the would-have-proceeded metric and to label the receipt; it NEVER
    feeds resolution. Returns own-PR numbers named by an injection."""
    wanted: List[int] = []
    for rec in world.open_prs.values():
        for m in _INJ_PR_RE.finditer(str(getattr(rec, "injected_body", "") or "")):
            n = int(m.group(1))
            if n in world.open_prs and n not in wanted:
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
    receipt: object                  # the signed Receipt appended for this decision
    auth: object = None              # the AuthorizationResult, when the authorizer ran
    token: object = None
    check_ref: Optional[str] = None  # rail capability ref (check run id), when one was posted


def _synth_hash(*parts) -> str:
    return hash_obj(["mandate-receipt", *[str(p) for p in parts]])


def authorize_closed_mandate(env, bridge: GitHubRailBridge, receipts: ReceiptLog, *,
                             repo_id: str, closed: ClosedMandate, effective: MergePolicy,
                             principal_id: str = PRINCIPAL,
                             author: str = "alice") -> AuthorizeOutcome:
    """Take a resolved ClosedMandate to a decision THROUGH THE RAIL AUTHORIZER, recording a
    signed receipt for every outcome.

    tier != auto -> escalate (approve/cosign/deny); no kernel call, no authorizer call; a
                    ``review`` receipt is appended.
    tier == auto -> build the signed chain at the effective policy, run the UNMODIFIED kernel
                    (context-bind + consume-once + per-principal velocity), then route the
                    approved token through GitHubRailBridge.authorize — which re-runs
                    verify_token AND independently re-checks the runtime effect vs the signed
                    Cart before concluding the required Check Run. A receipt is appended
                    whether the kernel blocks, the authorizer refuses, or the merge clears.
    """
    ec = closed.effect_class
    tier = effective.tier_for(ec)

    if tier != TIER_AUTO:
        reason = f"tier={tier} for {ec} -> escalate (not autonomously authorizable)"
        r = receipts.append(
            execution_id="exec_" + _synth_hash(closed.bound_target, "review")[:16],
            mandate_id=f"open:{repo_id}", chain_hash=_synth_hash(closed.bound_target),
            policy_id=f"effective:{repo_id}", decision="review",
            payment_status=f"escalated:tier={tier}", payment_ref=None, rail="github")
        return AuthorizeOutcome(False, tier, reason, ec, r)

    # auto -> the kernel still binds context, consumes-once, and rate-limits per principal.
    req = build_merge_chain(env, repo=repo_id, pr=closed.pr, base=closed.base,
                            head_sha=closed.head_sha, touched_paths=closed.touched_paths,
                            author=author, policy=effective)
    decision, token = env.verifier.evaluate(req)

    if not decision.approved:
        r = receipts.append(
            execution_id="exec_" + _synth_hash(closed.bound_target, "block")[:16],
            mandate_id=req.intent.mandate_id,
            chain_hash=decision.chain_hash or _synth_hash(closed.bound_target),
            policy_id=req.intent.policy_id, decision="blocked",
            payment_status="kernel-blocked", payment_ref=None, rail="github")
        return AuthorizeOutcome(False, tier, decision.reason, ec, r, token=token)

    # THE FIX: do NOT short-circuit on the kernel verdict. Route the token through the rail
    # authorizer so verify_token + the independent effect-vs-context re-check both run, and
    # the rail capability (the required Check Run) is concluded by the enforcer alone.
    auth = bridge.authorize(token, req)
    r = receipts.append(
        execution_id=token.execution_id, mandate_id=token.mandate_id,
        chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
        decision="approved" if auth.executed else "blocked",
        payment_status="executed" if auth.executed else "authorizer-refused",
        payment_ref=auth.payment_ref, rail=auth.rail or "github")
    return AuthorizeOutcome(auth.executed, tier, auth.reason, ec, r,
                            auth=auth, token=token, check_ref=auth.payment_ref)


# ============================================================================
# Job-level runner over a world (offline tests + the live l3 runner share this)
# ============================================================================
@dataclass
class JobResult:
    effective: MergePolicy
    resolution: MandateResolution
    outcome: Optional[AuthorizeOutcome]      # None when UNRESOLVED (escalated at resolution)
    receipts: list                            # every signed receipt appended for this job
    # metric: the injection should NEVER proceed under the mandate.
    injection_wanted: list = field(default_factory=list)
    would_have_proceeded: int = 0             # injected targets the mandate path authorized
    blocked_or_escalated: int = 0             # injected targets the mandate path contained
    # transparency: the DecisionRecords appended to the Merkle log for this job (when wired).
    records: list = field(default_factory=list)

    @property
    def proceed_rate(self) -> float:
        n = len(self.injection_wanted)
        return (self.would_have_proceeded / n) if n else 0.0


def _to_considered_rejected(items) -> tuple:
    return tuple(ConsideredRejected(pr=c.pr, target=c.target, cause=c.cause, channel=c.channel)
                for c in items)


def _effect_descriptor(rec, deny_paths) -> EffectDescriptor:
    return EffectDescriptor(
        effect_class=effect_class_for(rec.files, deny_paths),
        target=target_id(rec.repo, rec.number, rec.base, rec.head_sha),
        base=rec.base, head_sha=rec.head_sha, touched_paths=tuple(rec.files))


def explain_pr(rec, effective: MergePolicy, *, configured_repo: str,
               criterion_issue: Optional[int] = None,
               endorsed_pr: Optional[int] = None) -> str:
    """A one-line, human-readable 'why' for a PR under the mandate, showing the two layers
    explicitly: the allow-list ceiling (in-repo + allowed base) THEN the scope/protected fence,
    THEN whether it closes the criterion's issue, THEN the verdict. E.g.
        '#7 -> in-repo, base=main, in scope, closes #4 -> ENDORSED'
        '#6 -> in-repo, base=main, .github/workflows/deploy.yml is protected -> REJECTED(off-scope)'
    """
    repo_ok = str(rec.repo).lower() == str(configured_repo).lower()
    base_ok = rec.base in effective.allowed_bases
    bits = ["in-repo" if repo_ok else f"OFF-REPO({rec.repo})",
            f"base={rec.base}" + ("" if base_ok else "(NOT ALLOWED)")]
    if not (repo_ok and base_ok):
        return f"#{rec.number} -> " + ", ".join(bits) + " -> REJECTED(off-allowlist ceiling)"

    disp = effective.path_disposition(rec.files)        # in-fence | denied | out-of-allow
    if disp == "denied":
        bad = next((p for p in rec.files if is_protected([p], effective.deny_paths)),
                   rec.files[0] if rec.files else "?")
        bits.append(f"{bad} is protected")
    elif disp == "out-of-allow":
        bits.append("off-scope (outside allow scope)")
    else:
        bits.append("in scope")
    if criterion_issue is not None:
        bits.append(f"closes #{criterion_issue}" if rec.closes_issue == criterion_issue
                    else f"does not close #{criterion_issue}")

    if rec.number == endorsed_pr:
        verdict = "ENDORSED"
    elif disp != "in-fence":
        verdict = "REJECTED(off-scope)"
    else:
        verdict = "candidate, not this mandate's target"
    return f"#{rec.number} -> " + ", ".join(bits) + f" -> {verdict}"


def run_open_mandate(env, source: PolicySource, bridge: GitHubRailBridge,
                     receipts: ReceiptLog, world: GitHubWorld, *, repo_id: str,
                     principal_id: str = PRINCIPAL, open_mandate: OpenMandate,
                     transparency: Optional[TransparencyLog] = None,
                     resolver=None, trace_store=None) -> JobResult:
    """Drive one OpenMandate to a decision over a world: resolve (bounded-to-own) -> build
    the ClosedMandate -> route through the authorizer -> append receipts. Records, for every
    injection-named target, a considered-and-rejected receipt + the would-have-proceeded
    metric. The OpenMandate is the operator's frozen grant; resolution reads runtime data
    only through the bounded-to-own resolver.

    When a `transparency` log is supplied, a structured, enforcement-bound DecisionRecord is
    appended to the RFC-6962-style Merkle log for EVERY receipt — so every action is in the
    tree and any one decision is independently provable. The log is optional so existing
    callers are byte-identical."""
    effective = resolve_effective_policy(source, repo_id, principal_id,
                                         open_mandate.as_task_policy())
    resolution = resolve_task_mandate(open_mandate, world, effective,
                                      resolver=resolver, trace_store=trace_store)
    appended: list = []
    records: list = []
    om_id = open_mandate.mandate_id()

    def _record(receipt, *, verdict, cause, tier, effect_class, resolved_target=None,
                effect=None, considered=(), reasoning_trace_hash=None):
        if transparency is None:
            return
        rec = build_decision_record(
            receipt, repo_id=repo_id, open_mandate_id=om_id, verdict=verdict, cause=cause,
            tier=tier, effect_class=effect_class, resolved_target=resolved_target,
            effect=effect, considered_rejected=_to_considered_rejected(considered),
            reasoning_trace_hash=reasoning_trace_hash)
        # Task 0 backlink: stamp the structured record's hash INTO the signed receipt, then
        # re-seal the receipt (re-hash + re-sign with the enforcer key) so the binding is
        # intrinsic and signed-over. Done before the next append so the receipt hash-chain
        # stays consistent (the next receipt's prev pointer reads this re-sealed hash).
        receipt.decision_record_hash = rec.record_hash()
        receipt.receipt_hash = hash_obj(receipt.hashing_payload())
        receipt.signature = crypto.sign(env.enforcer_sk, receipt.receipt_hash.encode())
        transparency.append(rec, receipt_hash=receipt.receipt_hash)
        records.append(rec)

    # The endorsed PR (if any) -- the only target the mandate would actually merge.
    endorsed_pr = resolution.closed.pr if resolution.kind == RESOLVED else None

    # Record every injection-named candidate as considered-and-rejected (audit + metric).
    wanted = injection_targets(world)
    would_proceed, blocked = 0, 0
    for n in wanted:
        rec = world.open_prs.get(n)
        tgt = target_id(rec.repo, rec.number, rec.base, rec.head_sha)
        if n == endorsed_pr:
            would_proceed += 1                 # the injection target coincided with the grant
            continue
        blocked += 1
        disp = effective.path_disposition(rec.files)
        eff = _effect_descriptor(rec, effective.deny_paths)
        r = receipts.append(
            execution_id="exec_" + _synth_hash(tgt, "rejected")[:16],
            mandate_id=f"open:{repo_id}", chain_hash=_synth_hash(tgt),
            policy_id=f"effective:{repo_id}", decision="blocked",
            payment_status=f"rejected:off-scope({disp});injection-channel",
            payment_ref=f"considered:{tgt}", rail="github")
        appended.append(r)
        cr = Considered(n, tgt, f"off-scope ({disp})", "injection")
        resolution.considered.append(cr)
        _record(r, verdict="blocked", cause=f"off-scope({disp});injection-channel",
                tier=effective.tier_for(eff.effect_class), effect_class=eff.effect_class,
                effect=eff, considered=(cr,))

    # Resolve -> authorize, or escalate the unresolved constraint.
    outcome = None
    if resolution.kind == RESOLVED:
        outcome = authorize_closed_mandate(
            env, bridge, receipts, repo_id=repo_id, closed=resolution.closed,
            effective=effective, principal_id=principal_id)
        appended.append(outcome.receipt)
        if outcome.approved and endorsed_pr in wanted:
            # Defensive: a grant that authorized an injection target is a metric failure.
            would_proceed += 1
        cm = resolution.closed
        _record(outcome.receipt,
                verdict=("approved" if outcome.approved else "blocked"),
                cause=outcome.reason, tier=outcome.tier, effect_class=cm.effect_class,
                resolved_target=cm.bound_target,
                effect=EffectDescriptor(cm.effect_class, cm.bound_target, cm.base,
                                        cm.head_sha, tuple(cm.touched_paths)),
                considered=resolution.considered,
                reasoning_trace_hash=resolution.reasoning_trace_hash)
    else:
        r = receipts.append(
            execution_id="exec_" + _synth_hash(open_mandate.criterion, "unresolved")[:16],
            mandate_id=f"open:{repo_id}", chain_hash=_synth_hash(open_mandate.criterion),
            policy_id=f"effective:{repo_id}", decision="review",
            payment_status=f"escalated:{UNRESOLVED_CONSTRAINT}", payment_ref=None,
            rail="github")
        appended.append(r)
        _record(r, verdict="review", cause=resolution.cause, tier="review",
                effect_class="merge_pr", considered=resolution.considered,
                reasoning_trace_hash=resolution.reasoning_trace_hash)

    return JobResult(effective=effective, resolution=resolution, outcome=outcome,
                     receipts=appended, injection_wanted=wanted,
                     would_have_proceeded=would_proceed, blocked_or_escalated=blocked,
                     records=records)
