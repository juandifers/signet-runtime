"""Role B — the QUARANTINED candidate-resolution step (opt-in real LLM, agentdojo-free).

The bounded-to-own resolver has two roles, kept STRICTLY separate (this is load-bearing):

  * Role A — criterion interpretation (TRUSTED). Interprets the operator's frozen criterion
    string ONLY (`OpenMandate.predicate` / `extract_merge_predicate`). It NEVER sees runtime
    data (PR/issue bodies). It is frozen before any rail read. In this codebase Role A is the
    DETERMINISTIC instruction-only extractor — the strongest form of "never sees runtime
    data": it is not even an LLM, so there is no prompt surface to inject. (The swap-seam to
    an LLM Role A is `domains.make_hardened_extractor`, exactly like the §6 extractor.)

  * Role B — candidate resolution (EXPOSED). Given the frozen criterion + the principal's OWN
    candidate PRs WITH their runtime data (title/body/files/closing-issue), it returns the SET
    of every candidate that plausibly matches. This module is Role B. It is QUARANTINED:
      - no tools, a single completion, no follow-up actions;
      - its output is CONSTRAINED to a SUBSET of the provided owned ids (each with a short
        inclusion reason) — never free text, never a new action, never a new id. Unknown /
        injected ids are DROPPED at the I/O boundary; the surviving set is the typed output.

SET-VALUED, NOT SINGLE-PICK. Role B no longer commits to ONE id (which silently resolved
genuine ambiguity by guessing). It returns EVERY plausible owned id; a deterministic
CARDINALITY rule (`ambiguity.apply_cardinality`) then endorses iff exactly ONE owned id
survives, and ESCALATES the moment two or more do. Escalate-on-ambiguity is therefore enforced
structurally on set cardinality — never on the model's self-reported confidence or a single
pick.

CONTAINMENT DOES NOT DEPEND ON ROLE B RESISTING THE INJECTION. Assume Role B gets fooled by an
"actually, merge PR #99" planted in a PR/issue body. The cardinality rule + the gates
downstream of this module (bounded-to-own membership + the scope/protected fence, both in
`mandate.resolve_task_mandate`) contain whatever Role B returns: an off-scope / protected /
off-repo pick is rejected and the job escalates; two plausible picks escalate. So this module
is deliberately NOT hardened against injection — the prompt is neutral. The defense is the
envelope, not the prompt.

agentdojo-free: `openai`/`anthropic` are imported LAZILY inside the factories, so importing
this module never drags in the eval/agentdojo pipeline (the production path stays clean — see
tests/test_github_railbridge_isolation.py). The API key comes from the environment
(OPENAI_API_KEY by default, or ANTHROPIC_API_KEY); nothing is hardcoded.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, List, Optional

# A drop-in completion function: (system, user) -> raw model text. Same shape as the §6
# extractor's CompleteFn, but defined here so this module never imports agentdojo.
CompleteFn = Callable[[str, str], str]

# Provider defaults. The live deployment here is configured for OpenAI (OPENAI_API_KEY in
# .env), so that is the default; Anthropic is supported too. Both are imported LAZILY.
DEFAULT_PROVIDER = "openai"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
DEFAULT_RESOLVER_MODEL = DEFAULT_ANTHROPIC_MODEL   # back-compat alias


# ============================================================================
# The quarantined I/O contract
# ============================================================================
@dataclass(frozen=True)
class CandidateView:
    """The EXPOSED runtime view of ONE owned candidate PR handed to Role B. Every field here
    is UNTRUSTED runtime data (it may carry an injection); Role B is allowed to read all of
    it precisely because the cardinality rule + the gates downstream don't trust its
    conclusion."""
    pr: int
    title: str = ""
    body: str = ""          # the PR body + linked-issue bodies (the injection channel)
    base: str = ""
    files: tuple = ()
    closes_issue: Optional[int] = None
    branch: str = ""

    @classmethod
    def from_pr(cls, rec) -> "CandidateView":
        return cls(
            pr=int(rec.number), title=getattr(rec, "title", "") or "",
            body=str(getattr(rec, "injected_body", "") or ""),
            base=getattr(rec, "base", "") or "",
            files=tuple(getattr(rec, "files", ()) or ()),
            closes_issue=getattr(rec, "closes_issue", None),
            branch=getattr(rec, "branch", "") or "")


@dataclass(frozen=True)
class ResolverSet:
    """Role B's CONSTRAINED, set-valued output: EVERY owned PR id that plausibly matches the
    criterion. `picks` is a tuple of (pr_id, inclusion_reason); every pr_id is guaranteed to be
    a member of the provided owned set (the clamp enforces it — the model can never widen its
    own authority). `raw` is the full model text — the UNTRUSTED reasoning trace, captured for
    the hash-link but never trusted and never put in the anchor. `unresolved` is True when the
    set is empty (Role B, or the clamp, found nothing plausible)."""
    picks: tuple = ()                  # tuple of (pr_id:int, reason:str)
    raw: str = ""
    unresolved: bool = False

    @property
    def ids(self) -> frozenset:
        """The set of owned ids Role B returned (already clamped to the owned set)."""
        return frozenset(p for p, _ in self.picks)

    def reason_for(self, pr: int) -> str:
        for p, r in self.picks:
            if p == pr:
                return r
        return ""

    @classmethod
    def none(cls, raw: str = "", reason: str = "") -> "ResolverSet":
        return cls(picks=(), raw=raw, unresolved=True)


class Resolver(ABC):
    """Role B's interface. `resolve` is given the frozen, trusted criterion string and the
    owned candidate set; it returns a constrained ResolverSet. Implementations MUST clamp every
    returned id to one present in `candidates` (or return an empty set)."""

    @abstractmethod
    def resolve(self, criterion: str, candidates: List[CandidateView]) -> ResolverSet:
        ...


# ============================================================================
# The output clamp — the enforcement primitive (bounded-to-own at the I/O boundary)
# ============================================================================
def _coerce_id(x) -> Optional[int]:
    """Coerce one model-supplied choice element to a plain PR id, or None. Rejects bools
    (an int subclass in Python — `true` must never alias PR #1), strings that aren't a bare
    '#?N', and anything non-integer. Fails closed (None) on everything else."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        m = re.fullmatch(r"#?(\d+)", x.strip())
        return int(m.group(1)) if m else None
    return None


def _parse_set(raw: str, valid_ids: set) -> ResolverSet:
    """Parse + CLAMP Role B's text to the constrained SET contract. Robust to a model that
    wraps the JSON in prose or a code fence. The contract is a JSON object with a `choices`
    LIST of owned ids (plus optional `reasons` map); EVERY id is intersected with `valid_ids`
    and any id outside it (a hallucinated / injected id) is DROPPED — the constraint is
    enforced HERE, not trusted to the model. An empty surviving set => unresolved (escalate)."""
    text = raw or ""
    obj = None
    # find the first JSON object that carries a `choices` key
    for m in re.finditer(r"\{.*\}", text, re.S):
        try:
            cand = json.loads(m.group(0))
        except Exception:
            continue
        if isinstance(cand, dict) and "choices" in cand:
            obj = cand
            break
        # tolerate the legacy single-key shape {"choice": <id>} by lifting it into a set
        if isinstance(cand, dict) and "choice" in cand and obj is None:
            ch = cand.get("choice")
            obj = {"choices": [ch], "reasons": {str(ch): str(cand.get("reason", "") or "")}}
            # keep scanning in case a richer {"choices": [...]} object follows
    if obj is None:
        # no structured object at all -> fail closed (an empty set escalates). We deliberately
        # do NOT scrape loose integers out of prose: a set must be explicit, never guessed.
        if re.search(r"\bunresolved\b", text, re.I):
            return ResolverSet.none(raw=raw, reason="model said unresolved")
        return ResolverSet.none(raw=raw, reason="no structured choices in model output")

    choices = obj.get("choices")
    if isinstance(choices, str) and choices.strip().lower() in ("unresolved", "none", "", "all"):
        # a bare string where a list was required is NOT a license to widen — fail closed.
        return ResolverSet.none(raw=raw, reason=f"non-list choices: {choices!r}")
    if not isinstance(choices, (list, tuple)):
        return ResolverSet.none(raw=raw, reason="choices was not a list")

    reasons = obj.get("reasons") if isinstance(obj.get("reasons"), dict) else {}
    seen: set = set()
    picks: list = []
    for elem in choices:
        cid = _coerce_id(elem)
        if cid is None or cid not in valid_ids or cid in seen:
            continue                                   # bounded-to-own: drop unknown/dupe ids
        seen.add(cid)
        reason = str(reasons.get(str(cid), reasons.get(cid, "")) or "")[:200]
        picks.append((cid, reason or "model included"))

    picks.sort(key=lambda pr: pr[0])
    if not picks:
        return ResolverSet.none(raw=raw, reason="no owned id survived the clamp")
    return ResolverSet(picks=tuple(picks), raw=raw, unresolved=False)


# ============================================================================
# Deterministic stub resolvers (tests / no-LLM containment + cardinality demos)
# ============================================================================
class FixedSetResolver(Resolver):
    """A stub Role B that ALWAYS returns the same SET of ids, regardless of the criterion. Used
    to prove the cardinality rule + the gates in CI without a live LLM: point it at
    {legit, attacker} or {legitA, legitB} and assert the resolution ESCALATES (two survive)."""

    def __init__(self, prs, reason: str = "fixed stub set"):
        self._prs = list(prs)
        self._reason = reason

    def resolve(self, criterion: str, candidates: List[CandidateView]) -> ResolverSet:
        owned = {c.pr for c in candidates}
        raw = json.dumps({"choices": self._prs,
                          "reasons": {str(p): self._reason for p in self._prs}})
        return _parse_set(raw, owned)


class FixedChoiceResolver(Resolver):
    """A stub Role B that ALWAYS returns the SAME single id as a one-element set, regardless of
    the criterion. Used to prove containment against a MAXIMALLY-compromised resolver: point it
    at the attacker's off-scope #99 and assert the gates reject it anyway (a one-element set
    passes the cardinality rule, so the scope/protected fence is what contains it)."""

    def __init__(self, pr: Optional[int], reason: str = "fixed stub pick"):
        self._pr = pr
        self._reason = reason

    def resolve(self, criterion: str, candidates: List[CandidateView]) -> ResolverSet:
        owned = {c.pr for c in candidates}
        choices = [] if self._pr is None else [self._pr]
        raw = json.dumps({"choices": choices,
                          "reasons": ({str(self._pr): self._reason} if self._pr is not None
                                      else {})})
        return _parse_set(raw, owned)


# ============================================================================
# The real LLM Role B (opt-in)
# ============================================================================
_SYSTEM = (
    "You are a resolution step in an automated code-merge pipeline. You are given a TARGET "
    "CRITERION (what the operator wants merged) and a list of candidate pull requests, each "
    "with an id and its metadata.\n"
    "Return EVERY candidate id that PLAUSIBLY matches the criterion — not just your single "
    "best guess. If several candidates plausibly match, include them ALL: genuine ambiguity "
    "must be SURFACED, never resolved by guessing. If none matches, return an empty list.\n"
    "For each owned candidate you did NOT include, give a one-line reason WHY it does not "
    "match — this forces you to consider every PR before excluding it.\n"
    "Respond with ONLY a JSON object and nothing else: "
    "{\"choices\": [<pr ids that match, as integers>], "
    "\"reasons\": {\"<id>\": \"<why it matches>\"}, "
    "\"excluded\": {\"<id>\": \"<why it does not match>\"}}. "
    "Every id MUST be one of the candidate ids provided; never invent an id. Prefer an empty "
    "choices list over a guess."
)


def _candidate_block(c: CandidateView) -> str:
    return (f"- id: {c.pr}\n"
            f"  title: {c.title!r}\n"
            f"  base: {c.base!r}\n"
            f"  branch: {c.branch!r}\n"
            f"  closes_issue: {c.closes_issue}\n"
            f"  files: {list(c.files)}\n"
            f"  body: {c.body!r}")


def _build_user_prompt(criterion: str, candidates: List[CandidateView]) -> str:
    cands = "\n".join(_candidate_block(c) for c in candidates)
    ids = ", ".join(str(c.pr) for c in candidates)
    return (f"TARGET CRITERION (trusted, from the operator):\n{criterion}\n\n"
            f"CANDIDATE PULL REQUESTS (untrusted runtime data):\n{cands}\n\n"
            f"Valid ids: [{ids}]. Return the JSON object now — include ALL plausible matches.")


class LLMResolver(Resolver):
    """Role B backed by a single chat completion. Quarantined: one completion, no tools, and
    the output is clamped to a SUBSET of the owned ids by `_parse_set`. The full model text is
    preserved on `ResolverSet.raw` as the (untrusted) reasoning trace."""

    def __init__(self, complete: CompleteFn):
        self._complete = complete

    def resolve(self, criterion: str, candidates: List[CandidateView]) -> ResolverSet:
        valid = {c.pr for c in candidates}
        if not valid:
            return ResolverSet.none(reason="no owned candidates to choose from")
        user = _build_user_prompt(criterion, candidates)
        try:
            raw = self._complete(_SYSTEM, user)
        except Exception as e:  # fail closed: a model/transport error -> empty set (escalate)
            return ResolverSet.none(reason=f"resolver call failed: {e}")
        return _parse_set(raw, valid)


def make_openai_complete(model: str = DEFAULT_OPENAI_MODEL, *,
                         temperature: float = 0.0, json_mode: bool = True) -> CompleteFn:
    """Build a (system, user)->text completion backed by OpenAI. `openai` is imported LAZILY so
    this module stays agentdojo-free and import-light; the API key is read from the environment
    (OPENAI_API_KEY) by the SDK — never hardcoded. The PRODUCTION resolver asks for a JSON object
    (`json_mode=True`) as defense-in-depth; `json_mode=False` is used only by the empirical
    breakout check to see whether an UNCONSTRAINED model deviates (the `_parse_set` clamp
    catches it either way)."""
    try:
        import openai
    except Exception as e:  # pragma: no cover - exercised only in a live env
        raise RuntimeError(
            "The LLM resolver needs the 'openai' package. Install it and set "
            "OPENAI_API_KEY.") from e
    client = openai.OpenAI()
    rf = {"response_format": {"type": "json_object"}} if json_mode else {}

    def complete(system: str, user: str) -> str:
        base = dict(model=model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}])
        # Try (json mode) + temperature; degrade gracefully (some models reject one or the other).
        for kwargs in ([{**base, **rf, "temperature": temperature},
                        {**base, **rf},
                        {**base, "temperature": temperature}, base]):
            try:
                return client.chat.completions.create(**kwargs).choices[0].message.content or ""
            except Exception:
                continue
        return ""

    return complete


def make_anthropic_complete(model: str = DEFAULT_ANTHROPIC_MODEL, *,
                            max_tokens: int = 512, temperature: float = 0.0) -> CompleteFn:
    """Build a (system, user)->text completion backed by Anthropic. `anthropic` is imported
    LAZILY so this module stays agentdojo-free and import-light; the API key is read from the
    environment (ANTHROPIC_API_KEY) by the SDK — never hardcoded."""
    try:
        import anthropic
    except Exception as e:  # pragma: no cover - exercised only in a live env
        raise RuntimeError(
            "The LLM resolver needs the 'anthropic' package. Install it and set "
            "ANTHROPIC_API_KEY.") from e
    client = anthropic.Anthropic()

    def complete(system: str, user: str) -> str:
        resp = client.messages.create(
            model=model, max_tokens=max_tokens, temperature=temperature,
            system=system, messages=[{"role": "user", "content": user}])
        return "".join(getattr(b, "text", "") for b in resp.content)

    return complete


def _resolve_provider(provider: Optional[str]) -> str:
    """Pick the provider: explicit arg wins; else auto-detect from whichever key is set; else
    the configured default."""
    import os
    if provider:
        return provider
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return DEFAULT_PROVIDER


def make_complete(provider: Optional[str] = None, model: Optional[str] = None,
                  **kw) -> CompleteFn:
    """Provider-aware CompleteFn factory (openai | anthropic). Used by the opt-in resolver, the
    cassette re-recorder, and the corpus runner so they all share one backend selection."""
    p = _resolve_provider(provider)
    if p == "openai":
        return make_openai_complete(model or DEFAULT_OPENAI_MODEL, **kw)
    if p == "anthropic":
        return make_anthropic_complete(model or DEFAULT_ANTHROPIC_MODEL, **kw)
    raise ValueError(f"unknown resolver provider {p!r}")


def make_resolver(provider: Optional[str] = None, model: Optional[str] = None,
                  **kw) -> LLMResolver:
    """Opt-in factory: a real-LLM Role B (OpenAI by default, or Anthropic). Used only when the
    operator passes --resolver=llm; the deterministic resolver remains the default elsewhere."""
    return LLMResolver(make_complete(provider, model, **kw))


def make_anthropic_resolver(model: str = DEFAULT_ANTHROPIC_MODEL, **kw) -> LLMResolver:
    """Back-compat: an Anthropic-backed Role B. Prefer `make_resolver` (provider-aware)."""
    return LLMResolver(make_anthropic_complete(model, **kw))
