"""GitHub rail-bridge domain — the §6 effect-key machinery applied to
"merge a pull request to a protected branch".

This is a DOMAIN ADAPTER, not new kernel logic. It reuses, unchanged, the §6
primitives from `evals/agentdojo/effects.py`:
  * `Effect(effect_class, target_id, amount_cents)`  -- the canonical side effect
  * `EffectPredicate(...)`                            -- the trusted, instruction-only plan
  * `effect_key(effect_class, target_id)`            -- the opaque kernel-bound string
  * `resolve_effect_predicate(...)`                  -- ENDORSE/REVIEW/BLOCK resolver
and the `EffectDomainSpec` hook surface from `evals/agentdojo/domains.py`.

THE ENCODING (the crux — must match merge_chain.py + the authorizer):
    effect_class = "merge_pr_protected"  if the PR's touched paths intersect the
                   protected globs, else "merge_pr"
    target_id    = f"{repo}#{pr}->{base}@{head_sha}"   # binds head_sha + base branch
The kernel then binds `recipient = effect_key(effect_class, target_id)` and
`destination_account = diff_hash(touched_paths)`. Because the verifier's
context-binding (step 7) compares runtime vs Cart on recipient + destination +
action, a post-authorization force-push (new head_sha) or a base-branch swap
changes the bound recipient and the UNMODIFIED kernel blocks it. No new binding
logic lives here.

ISOLATION (the §6 trusted-input-only discipline): the predicate is frozen from
the user's INSTRUCTION ALONE (`extract_merge_predicate`). The canonicalizer reads
ONLY the PR's file LIST and SHAs (low-capacity, non-injectable facts) -- never the
PR body / commit messages / file contents. So an injected "also merge #99" in a PR
body can never widen the authorized envelope.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Optional

from signet.canonical import hash_obj

# Reuse the §6 machinery unchanged (do NOT reinvent it). The PURE primitives come
# from the agentdojo-FREE core so this production path never imports agentdojo;
# EffectDomainSpec/EffectPolicy come from domains.py (also agentdojo-free).
from evals.effect_core import Effect, EffectPredicate, SEL_NONE, effect_key
from evals.agentdojo.domains import EffectDomainSpec, EffectPolicy
from evals.agentdojo.taxonomy import LITERAL, RESOLVABLE, UNRESOLVABLE

# The declarative typed-policy grammar + the ONE shared evaluator (fence-is-data-not-code).
from evals._rail_core.policy_spec import (AttrDecl, BOOL, CATEGORICAL, Condition, EQ, IN_SET, OWN,
                                          PolicySpec, evaluate_allowlist, evaluate_fence)

# ---- standing operator config (TRUSTED; coarse, task-independent) ----
CONFIGURED_REPO = "octo/payments-service"
ALLOWED_BASES = ("main", "release")
# A protected path requires human review -> it is out-of-envelope for an autonomous
# merge. Globs are matched by prefix OR fnmatch so "auth/**" catches "auth/login.py".
PROTECTED_GLOBS = (".github/workflows/**", "auth/**", "src/auth/**", "infra/**",
                   "db/migrations/**")

EFFECT_MERGE = "merge_pr"
EFFECT_MERGE_PROTECTED = "merge_pr_protected"


# ============================================================================
# Synthetic, offline "GitHub" world (no live API)
# ============================================================================
@dataclass(frozen=True)
class PullRequest:
    repo: str
    number: int
    base: str
    head_sha: str
    files: tuple                # the touched paths (the low-capacity decision input)
    title: str = ""
    branch: str = ""
    author: str = "alice"
    injected_body: str = ""     # a malicious PR body (NEVER read by the canonicalizer)
    closes_issue: Optional[int] = None   # issue this PR closes (low-capacity own metadata)
    status: str = ""            # CI status: green | red | pending (non-injectable own field)
    created_order: int = 0      # monotonic recency rank (higher = more recent)


@dataclass
class GitHubWorld:
    """The principal's OWN open PRs -- the bounded set the resolver endorses over."""
    open_prs: dict = field(default_factory=dict)   # number -> PullRequest


# ============================================================================
# The encoding helpers (single source of truth, reused by merge_chain + tests)
# ============================================================================
def target_id(repo: str, pr: int, base: str, head_sha: str) -> str:
    """`{repo}#{pr}->{base}@{head_sha}` -- binds the base branch + the exact head."""
    return f"{repo}#{pr}->{base}@{head_sha}"


def diff_hash(touched_paths) -> str:
    """hash_obj(sorted(touched_paths)) -- rides as destination_account (extra bind)."""
    return hash_obj(sorted(str(p) for p in touched_paths))


def is_protected(touched_paths, protected_globs=PROTECTED_GLOBS) -> bool:
    for f in touched_paths:
        fl = str(f).replace("\\", "/").lower()
        for g in protected_globs:
            gl = g.lower()
            prefix = gl.split("**", 1)[0].rstrip("/")
            if prefix and (fl == prefix or fl.startswith(prefix + "/")):
                return True
            if fnmatch.fnmatch(fl, gl):
                return True
    return False


def effect_class_for(touched_paths, protected_globs=PROTECTED_GLOBS) -> str:
    return EFFECT_MERGE_PROTECTED if is_protected(touched_paths, protected_globs) else EFFECT_MERGE


# ============================================================================
# The DECLARATIVE typed policy: schema + project + spec (DATA; the decision is the shared evaluator).
#   allow-list (universe ceiling): repo == configured_repo AND base ∈ allowed_bases.
#   fence (per-task): no PROTECTED path AND every touched path within the allow-glob scope.
# The glob/membership matching is the BOOL-fold computation inside project (rail code is allowed to
# PROJECT); the DECISION (which conditions, which universes) is data evaluated by the shared evaluator.
# ============================================================================
def github_candidate_schema(*, repo, bases) -> tuple:
    return (
        AttrDecl("repo", CATEGORICAL([str(repo).lower()]), OWN),
        AttrDecl("base", CATEGORICAL(bases), OWN),
        AttrDecl("protected_path", BOOL(), OWN),
        AttrDecl("in_scope", BOOL(), OWN),
    )


def github_policy_spec(*, repo, bases) -> PolicySpec:
    return PolicySpec(
        allowlist=(
            Condition("repo", IN_SET, frozenset([str(repo).lower()])),
            Condition("base", IN_SET, frozenset(bases)),
        ),
        fence=(
            Condition("protected_path", EQ, False),
            Condition("in_scope", EQ, True),
        ),
    )


def github_fence_attrs(touched_paths, policy) -> dict:
    """The fence attributes from a path set: any DENIED path (protected) / all paths within the
    allow-glob scope. Uses the policy's own glob matchers (the membership is the BOOL fold)."""
    return {"protected_path": any(policy._denied(p) for p in touched_paths),
            "in_scope": all(policy._allowed(p) for p in touched_paths)}


def github_project(pr, policy) -> dict:
    return {"repo": str(pr.repo).lower(), "base": pr.base,
            **github_fence_attrs(pr.files, policy)}


# Convenience wrappers taking a duck-typed MergePolicy (used by MergePolicy.is_fenced + the plugin).
def github_spec_for_policy(policy) -> PolicySpec:
    return github_policy_spec(repo=policy.repo_id, bases=policy.allowed_bases)


def github_schema_for_policy(policy) -> tuple:
    return github_candidate_schema(repo=policy.repo_id, bases=policy.allowed_bases)


# ============================================================================
# The merge rail's POLICY as a rail-algebra DeclarativeMembership (signet.rail_algebra).
# It wraps the SHARED evaluator (evaluate_allowlist / evaluate_fence) over the typed PolicySpec — so
# `within_allowlist`/`within_fence` are byte-identical to the prior inline calls (BEHAVIOR-PRESERVED),
# but the merge gate now literally runs the Policy variant. All fence/allowlist attrs are OWN, so it
# is provenance-monotone. `project(world, pr_id)` maps an OWNED PR id to the declared attrs and fails
# CLOSED (empty attrs -> evaluate_* return False) for a missing id.
# ============================================================================
def github_membership_policy(policy):
    """Build the DeclarativeMembership Policy bound to an effective MergePolicy (duck-typed:
    repo_id, allowed_bases, the glob matchers github_project reads)."""
    from signet.rail_algebra import DeclarativeMembership
    repo, bases = policy.repo_id, policy.allowed_bases

    def project_attrs(world, pr_id):
        rec = getattr(world, "open_prs", {}).get(pr_id) if pr_id is not None else None
        return github_project(rec, policy) if rec is not None else {}

    return DeclarativeMembership(
        name="github", schema=github_candidate_schema(repo=repo, bases=bases),
        spec=github_policy_spec(repo=repo, bases=bases), project_attrs=project_attrs,
        allowlist_fn=evaluate_allowlist, fence_fn=evaluate_fence,
        allow_witness_values={"repo": str(repo).lower(), "base": bases[0],
                              "protected_path": False, "in_scope": True})


def _pr_number(target: str) -> Optional[int]:
    m = re.search(r"#(\d+)->", str(target))
    return int(m.group(1)) if m else None


# ============================================================================
# Trusted-input-only extractor (offline, deterministic).
#
# Live deployment swaps in an LLM extractor (domains.make_hardened_extractor +
# a json_schema strict EffectPredicate schema), EXACTLY like domains.py. Offline
# we parse the instruction deterministically -- but ONLY the instruction string,
# never any PR body / tool output (the §6 isolation seam).
# ============================================================================
_VAGUE = ("whatever", "anything", "looks ready", "is ready", "ready to ship",
          "ready to go", "seems ready", "good to go", "you think is best",
          "the usual", "just merge it")
_STATUS_WORDS = ("green", "red", "pending")
_LATEST_WORDS = ("latest", "newest", "most recent")
_BOILERPLATE_RE = re.compile(r"^\s*(?:please\s+)?(?:go\s+ahead\s+and\s+)?merge\s+"
                             r"(?:the\s+|a\s+|my\s+)?", re.I)
_PR_NOUN_RE = re.compile(r"\b(?:pull\s+request|pr)\b", re.I)


def extract_merge_predicate(instruction: str) -> Optional[EffectPredicate]:
    """Freeze a trusted, low-capacity EffectPredicate from the INSTRUCTION ONLY.

    Recognizes: an ISSUE reference (a descriptor over PRs that close it), an explicit
    PR number (a literal target), a CI-status word ("the green PR"), a recency word
    ("my latest PR"), a vague non-target ("whatever's ready"), or a residual keyword
    phrase. Never reads anything but the instruction string.
    """
    assert isinstance(instruction, str), "extractor input must be the instruction string"
    s = instruction.strip()
    low = s.lower()
    if "merge" not in low:
        return None
    # an ISSUE reference is a DESCRIPTOR (resolve over own PRs that close it), NOT a PR id.
    mi = re.search(r"issue\s*#?(\d+)", low)
    if mi:
        return EffectPredicate(EFFECT_MERGE, descriptor=f"issue #{mi.group(1)}")
    # an explicit PR number -> a LITERAL target (canonicalized over env on the literal path).
    mp = re.search(r"#(\d+)", s)
    if mp:
        return EffectPredicate(EFFECT_MERGE, target_literal=f"#{mp.group(1)}")
    # genuinely no trusted target.
    if any(v in low for v in _VAGUE):
        return EffectPredicate(EFFECT_MERGE, descriptor=None, selector=SEL_NONE)
    # a CI-status descriptor ("the green PR").
    for st in _STATUS_WORDS:
        if re.search(rf"\b{st}\b", low):
            return EffectPredicate(EFFECT_MERGE, descriptor=f"status:{st}")
    # a recency descriptor ("my latest PR").
    if any(w in low for w in _LATEST_WORDS):
        return EffectPredicate(EFFECT_MERGE, descriptor="latest")
    # otherwise: strip the "merge the ... PR" boilerplate -> the core keyword phrase.
    core = _PR_NOUN_RE.sub("", _BOILERPLATE_RE.sub("", low)).strip(" .,")
    return EffectPredicate(EFFECT_MERGE, descriptor=(core or None))


# ---- keyword tokenization for descriptor resolution over OWN PRs ----
_STOP = {"the", "that", "which", "with", "for", "and", "pull", "request",
         "merge", "please", "this", "fix", "branch", "into", "onto"}


def _tokens(s: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]+", str(s).lower())
            if len(w) >= 4 and w not in _STOP}


# ============================================================================
# The DomainSpec — the hook surface a new effect-key adapter must implement
# ============================================================================
class GitHubDomain(EffectDomainSpec):
    name = "github"
    suite_name = "github"
    version = "offline"
    configured_repo = CONFIGURED_REPO
    allowed_bases = ALLOWED_BASES
    protected_globs = PROTECTED_GLOBS
    high_impact_tools = {"merge_pull_request": EFFECT_MERGE, "merge_pr": EFFECT_MERGE}
    authorized_classes = {EFFECT_MERGE}
    # The injected attacker PR #99 lives in the world but is NEVER instruction-named;
    # its key marks "off-allowlist" for the bounded assertion.
    attacker_ids = set()
    standing_policy = EffectPolicy(
        f"merge approved PRs in {CONFIGURED_REPO} to bases {ALLOWED_BASES}; "
        "protected paths (.github/workflows, auth, infra) require human review; "
        "merges are unpriced (amount==1)",
        cap_cents=None)

    def __init__(self, policy=None):
        """Bind the domain's fence to a MergePolicy (duck-typed: deny_paths,
        allowed_bases, repo_id) so the diagnostic measures the SAME fence enforcement
        reads. policy=None keeps the class-attr defaults (== DEFAULT_MERGE_POLICY), so
        an unparameterized GitHubDomain() is byte-identical to before."""
        if policy is not None:
            self.protected_globs = tuple(policy.deny_paths)
            self.allowed_bases = tuple(policy.allowed_bases)
            if getattr(policy, "repo_id", None):
                self.configured_repo = policy.repo_id

    # -- env / canonicalize --
    def effect_for_pr(self, pr_number: int, world: GitHubWorld) -> Optional[Effect]:
        rec = world.open_prs.get(int(pr_number))
        if rec is None:
            return None
        ec = effect_class_for(rec.files, self.protected_globs)
        return Effect(ec, target_id(rec.repo, rec.number, rec.base, rec.head_sha), 1)

    def canonicalize(self, tool, args, env) -> Optional[Effect]:
        """Actual call -> one Effect. Reads ONLY the PR file list + SHAs from env."""
        if tool not in self.high_impact_tools:
            return None
        num = args.get("pull_number", args.get("pr", args.get("number")))
        if num is None:
            return None
        return self.effect_for_pr(int(num), env)

    def gt_effects(self, user_task, world) -> list:
        out = []
        for n in getattr(user_task, "gt_prs", ()):
            e = self.effect_for_pr(n, world)
            if e is not None:
                out.append(e)
        return out

    # -- resolver hooks --
    def canonicalize_literal(self, effect_class, target_literal, env) -> Optional[str]:
        """Keyed lookup of EXACTLY the named PR number -> its current bound target_id
        (repo#pr->base@head_sha). env supplies ONLY the binding detail (head_sha + base)
        for that one id -- it never selects WHICH PR. Returns None if the id is unknown,
        or is not an in-scope owned target (wrong repo/base, or it touches a protected
        path): a literally-named PROTECTED PR still escalates -- canonicalization binds
        the head, it does NOT bypass the envelope. Never reads PR body/title/contents."""
        m = re.fullmatch(r"#?(\d+)", str(target_literal).strip())
        if not m:
            return None
        rec = env.open_prs.get(int(m.group(1)))
        if rec is None:
            return None
        cand = self._target(rec)
        if not self.target_allowed(EFFECT_MERGE, cand, env):
            return None                              # off-allowlist / protected -> escalate
        return cand

    def amount_for(self, effect_class, target_id_str, env) -> Optional[int]:
        return 1                                     # merges are unpriced

    def literal_ok(self, effect_class, target, env) -> bool:
        return self._lookup(target, env) is not None

    def match_descriptor(self, effect_class, descriptor, env) -> list:
        """Resolve a descriptor over the principal's OWN open PRs. Supports: an issue
        reference, a CI-status word, a recency word, an explicit PR number, and a
        keyword phrase (ALL significant tokens must appear in the title/branch -- a
        tighter rule than any-overlap, so a stray shared word can't cause a spurious
        second match)."""
        key = (descriptor or "").strip().lower()
        if not key:
            return []
        # issue reference -> PRs that close that issue.
        mi = re.fullmatch(r"issue\s*#?(\d+)", key)
        if mi:
            n = int(mi.group(1))
            return [self._target(r) for r in env.open_prs.values() if r.closes_issue == n]
        # CI status descriptor.
        if key.startswith("status:"):
            st = key.split(":", 1)[1]
            return [self._target(r) for r in env.open_prs.values()
                    if str(r.status).lower() == st]
        # recency descriptor -> the single most-recent own PR.
        if key in ("latest", "newest", "most recent"):
            prs = list(env.open_prs.values())
            if not prs:
                return []
            return [self._target(max(prs, key=lambda r: r.created_order))]
        # explicit PR number.
        m = re.fullmatch(r"#?(\d+)", key)
        if m:
            rec = env.open_prs.get(int(m.group(1)))
            return [self._target(rec)] if rec is not None else []
        # keyword phrase: ALL significant tokens must appear in title/branch.
        toks = _tokens(key)
        if not toks:
            return []
        return [self._target(r) for r in env.open_prs.values()
                if toks <= _tokens(f"{r.title} {r.branch}")]

    def selector_candidates(self, effect_class, scope, env) -> list:
        return []                                    # no min/max selector for merges

    def within_allowlist(self, target, env) -> bool:
        """The bounded-to-own UNIVERSE ceiling (NOT the per-mandate fence): the target is a PR
        in the CONFIGURED repo, to an ALLOWED BASE, and not an explicitly-flagged attacker id.
        Repo + base ONLY -- this is what makes a real repo PR an 'own/approved' candidate, on
        the live path exactly as for the synthetic corpus. It deliberately does NOT look at
        protected paths or the allow-glob scope: that is the fence's job (below), so an in-repo
        protected-path PR PASSES the allow-list and is discriminated by the fence instead."""
        rec = self._lookup(target, env)
        if rec is None:
            return False
        spec = github_policy_spec(repo=self.configured_repo, bases=self.allowed_bases)
        return evaluate_allowlist({"repo": str(rec.repo).lower(), "base": rec.base}, spec)

    def within_fence(self, target, env) -> bool:
        """The scope/protected fence applied to a candidate: it must not touch a protected
        path. (The allow-glob scope, e.g. src/**, is enforced at mandate-close in
        resolve_task_mandate via effective.is_fenced, which also covers protected paths.)"""
        rec = self._lookup(target, env)
        if rec is None:
            return False
        return not is_protected(rec.files, self.protected_globs)

    def target_allowed(self, effect_class, target, env) -> bool:
        """A runtime-resolved target is endorsable iff it is within the bounded-to-own
        allow-list (the universe ceiling: configured repo + allowed base) AND within the
        scope/protected fence. The allow-list BOUNDS (no cross-repo / arbitrary base); the
        fence DISCRIMINATES which in-universe PR this mandate authorizes."""
        return (self.within_allowlist(target, env)
                and self.within_fence(target, env))

    # -- taxonomy (DI/DIQ/DD) --
    def value_source(self, prompt, effect_class, target_id_str, env) -> str:
        n = _pr_number(target_id_str)
        if n is not None and f"#{n}" in prompt:      # PR number named verbatim
            return LITERAL
        rec = env.open_prs.get(n)
        if rec is not None and _tokens(f"{rec.title} {rec.branch}") & _tokens(prompt):
            return RESOLVABLE                        # described, resolvable over own PRs
        return UNRESOLVABLE

    # -- extractor --
    def build_extractor(self, model=None, provider=None):
        """Offline: the deterministic instruction-only extractor. Live deployment
        swaps in domains.make_hardened_extractor(...) with a strict json schema."""
        return extract_merge_predicate

    # -- helpers --
    def _target(self, rec: PullRequest) -> str:
        return target_id(rec.repo, rec.number, rec.base, rec.head_sha)

    def _lookup(self, target, env) -> Optional[PullRequest]:
        n = _pr_number(target)
        return env.open_prs.get(n) if n is not None else None
