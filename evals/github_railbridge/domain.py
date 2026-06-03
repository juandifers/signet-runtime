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

# ---- standing operator config (TRUSTED; coarse, task-independent) ----
CONFIGURED_REPO = "octo/payments-service"
ALLOWED_BASES = ("main", "release")
# A protected path requires human review -> it is out-of-envelope for an autonomous
# merge. Globs are matched by prefix OR fnmatch so "auth/**" catches "auth/login.py".
PROTECTED_GLOBS = (".github/workflows/**", "auth/**", "src/auth/**", "infra/**")

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
          "ready to go", "seems ready", "good to go")
_DESC_RE = re.compile(r"\b(?:that|which|with the|for the|about|to close|closing)\b\s+(.*)$")


def extract_merge_predicate(instruction: str) -> Optional[EffectPredicate]:
    """Freeze a trusted, low-capacity EffectPredicate from the INSTRUCTION ONLY."""
    assert isinstance(instruction, str), "extractor input must be the instruction string"
    s = instruction.strip()
    low = s.lower()
    if "merge" not in low:
        return None
    m = re.search(r"#(\d+)", s)
    if m:                                            # an explicit PR number is named ->
        # a LITERAL target: the literal/STRICT path canonicalizes it to the bound
        # target_id (repo#pr->base@head_sha) over env. descriptor stays None so
        # resolution takes the literal branch, never a keyword search.
        return EffectPredicate(EFFECT_MERGE, target_literal=f"#{m.group(1)}")
    if any(v in low for v in _VAGUE):                # "merge whatever is ready" -> no target
        return EffectPredicate(EFFECT_MERGE, descriptor=None, selector=SEL_NONE)
    md = _DESC_RE.search(low)
    if md:                                           # "the PR that closes <X>" -> descriptor
        desc = md.group(1).strip(" .")
        return EffectPredicate(EFFECT_MERGE, descriptor=desc or None)
    return EffectPredicate(EFFECT_MERGE, descriptor=None, selector=SEL_NONE)


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
        """Resolve a descriptor over the principal's OWN open PRs (#N or keyword)."""
        key = (descriptor or "").strip().lower()
        if not key:
            return []
        m = re.fullmatch(r"#?(\d+)", key)
        if m:
            rec = env.open_prs.get(int(m.group(1)))
            return [self._target(rec)] if rec is not None else []
        toks = _tokens(key)
        if not toks:
            return []
        out = []
        for rec in env.open_prs.values():
            if toks & _tokens(f"{rec.title} {rec.branch}"):
                out.append(self._target(rec))
        return out

    def selector_candidates(self, effect_class, scope, env) -> list:
        return []                                    # no min/max selector for merges

    def target_allowed(self, effect_class, target, env) -> bool:
        """The standing-allowlist / ownership bound for a RUNTIME-RESOLVED target:
        the PR must be in the configured repo, to an allowed base, and NOT touch a
        protected path. A protected PR is never an auto-endorsable target."""
        rec = self._lookup(target, env)
        if rec is None:
            return False
        if str(rec.repo).lower() != self.configured_repo.lower():
            return False
        if rec.base not in self.allowed_bases:
            return False
        if is_protected(rec.files, self.protected_globs):
            return False
        if str(target).lower() in {a.lower() for a in self.attacker_ids}:
            return False
        return True

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
