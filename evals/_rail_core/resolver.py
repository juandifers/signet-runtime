"""Rail-AGNOSTIC Role-B resolver skeleton — the set-valued candidate resolver MINUS any
rail-specific candidate schema or match-prompt. Shared by every rail-bridge (GitHub merge,
deploy/promote, ...). The GitHub-shaped pieces (the `CandidateView` PR fields, the `_SYSTEM`
merge prompt, `_build_user_prompt`) live in each rail's own `resolver.py`, which binds them
into the generic classes here. Promoted from `evals/github_railbridge/resolver.py`.

What is rail-agnostic and lives here:
  * `ResolverSet`           — the constrained, set-valued output contract.
  * `Resolver`              — the Role-B interface.
  * `_coerce_id` / `parse_set` — the OUTPUT CLAMP (bounded-to-own at the I/O boundary). Takes a
                            raw string + a set of valid integer ids; drops everything outside
                            it. Knows NOTHING about PRs, builds, or any rail schema.
  * `FixedSetResolver` / `FixedChoiceResolver` — deterministic stubs (id_of-parameterized).
  * `GenericLLMResolver`    — a single-completion Role B parameterized by (system_prompt,
                            build_user_prompt, id_of). Each rail supplies those three.
  * the provider plumbing   — `make_openai_complete`, `make_anthropic_complete`,
                            `_resolve_provider`, `make_complete`.

The clamp + cardinality (in `_rail_core.ambiguity`) are what contain a fooled Role B; neither
trusts the model's conclusion, and neither is rail-typed. agentdojo-free: `openai`/`anthropic`
are imported LAZILY inside the factories.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, List, Optional

# (system, user) -> raw model text. Defined here so this module never imports agentdojo.
CompleteFn = Callable[[str, str], str]

DEFAULT_PROVIDER = "openai"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
DEFAULT_RESOLVER_MODEL = DEFAULT_ANTHROPIC_MODEL   # back-compat alias

# OpenAI reasoning models (gpt-5*, o1/o3/o4*) reject `temperature`/`top_p`, want
# `max_completion_tokens` (not `max_tokens`), and rename the system role to "developer".
# The `*-chat*` snapshots behave like the classic chat completion API, so exclude them.
_OPENAI_REASONING_PREFIXES = ("gpt-5", "o1", "o3", "o4")


def is_openai_reasoning_model(model: str) -> bool:
    """True for OpenAI reasoning models that need the developer-role / no-temperature branch."""
    m = (model or "").lower()
    if "chat" in m:                       # e.g. gpt-5-chat-latest takes the classic params
        return False
    return m.startswith(_OPENAI_REASONING_PREFIXES) or "reasoning" in m


# ============================================================================
# The constrained, set-valued output contract (rail-agnostic)
# ============================================================================
@dataclass(frozen=True)
class ResolverSet:
    """Role B's CONSTRAINED, set-valued output: EVERY owned candidate id that plausibly matches
    the criterion. `picks` is a tuple of (id, inclusion_reason); every id is guaranteed to be a
    member of the provided owned set (the clamp enforces it — the model can never widen its own
    authority). `raw` is the full model text (the UNTRUSTED reasoning trace, captured for the
    hash-link, never trusted, never anchored). `unresolved` is True when the set is empty."""
    picks: tuple = ()                  # tuple of (id:int, reason:str)
    raw: str = ""
    unresolved: bool = False

    @property
    def ids(self) -> frozenset:
        """The set of owned ids Role B returned (already clamped to the owned set)."""
        return frozenset(p for p, _ in self.picks)

    def reason_for(self, cid: int) -> str:
        for p, r in self.picks:
            if p == cid:
                return r
        return ""

    @classmethod
    def none(cls, raw: str = "", reason: str = "") -> "ResolverSet":
        return cls(picks=(), raw=raw, unresolved=True)


class Resolver(ABC):
    """Role B's interface. `resolve` is given the frozen, trusted criterion string and the owned
    candidate set; it returns a constrained ResolverSet. Implementations MUST clamp every
    returned id to one present in `candidates` (or return an empty set)."""

    @abstractmethod
    def resolve(self, criterion: str, candidates: List) -> ResolverSet:
        ...


# ============================================================================
# The output clamp — the enforcement primitive (bounded-to-own at the I/O boundary)
# ============================================================================
def _coerce_id(x) -> Optional[int]:
    """Coerce one model-supplied choice element to a plain id, or None. Rejects bools (an int
    subclass in Python — `true` must never alias id #1), strings that aren't a bare '#?N', and
    anything non-integer. Fails closed (None) on everything else."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        m = re.fullmatch(r"#?(\d+)", x.strip())
        return int(m.group(1)) if m else None
    return None


def parse_set(raw: str, valid_ids: set) -> ResolverSet:
    """Parse + CLAMP Role B's text to the constrained SET contract. Robust to a model that wraps
    the JSON in prose or a code fence. The contract is a JSON object with a `choices` LIST of
    owned ids (plus optional `reasons` map); EVERY id is intersected with `valid_ids` and any id
    outside it (a hallucinated / injected id) is DROPPED — the constraint is enforced HERE, not
    trusted to the model. An empty surviving set => unresolved (escalate). Rail-agnostic: it sees
    only ids, never any candidate schema."""
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
        # no structured object at all -> fail closed (an empty set escalates). We deliberately do
        # NOT scrape loose integers out of prose: a set must be explicit, never guessed.
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


# back-compat alias (the GitHub rail and its tests import `_parse_set`).
_parse_set = parse_set


def _default_id_of(c):
    """Neutral id accessor: prefer `.id`, fall back to `.pr` (GitHub) — so the shared stubs work
    for any rail whose candidate exposes one of them. Each rail SHOULD pass an explicit id_of."""
    v = getattr(c, "id", None)
    return v if v is not None else getattr(c, "pr", None)


# ============================================================================
# Deterministic stub resolvers (tests / no-LLM containment + cardinality demos)
# ============================================================================
class FixedSetResolver(Resolver):
    """A stub Role B that ALWAYS returns the same SET of ids, regardless of the criterion. Used
    to prove the cardinality rule + the gates in CI without a live LLM: point it at
    {legit, attacker} or {legitA, legitB} and assert the resolution ESCALATES (two survive)."""

    def __init__(self, ids, reason: str = "fixed stub set", *, id_of=_default_id_of):
        self._ids = list(ids)
        self._reason = reason
        self._id_of = id_of

    def resolve(self, criterion: str, candidates: List) -> ResolverSet:
        owned = {self._id_of(c) for c in candidates}
        raw = json.dumps({"choices": self._ids,
                          "reasons": {str(p): self._reason for p in self._ids}})
        return parse_set(raw, owned)


class FixedChoiceResolver(Resolver):
    """A stub Role B that ALWAYS returns the SAME single id as a one-element set, regardless of
    the criterion. Used to prove containment against a MAXIMALLY-compromised resolver: point it
    at the attacker's off-fence id and assert the gates reject it anyway (a one-element set
    passes the cardinality rule, so the scope/protected fence is what contains it)."""

    def __init__(self, cid: Optional[int], reason: str = "fixed stub pick", *,
                 id_of=_default_id_of):
        self._id = cid
        self._reason = reason
        self._id_of = id_of

    def resolve(self, criterion: str, candidates: List) -> ResolverSet:
        owned = {self._id_of(c) for c in candidates}
        choices = [] if self._id is None else [self._id]
        raw = json.dumps({"choices": choices,
                          "reasons": ({str(self._id): self._reason} if self._id is not None
                                      else {})})
        return parse_set(raw, owned)


# ============================================================================
# The real LLM Role B (opt-in) — parameterized by the rail's prompt + id accessor
# ============================================================================
class GenericLLMResolver(Resolver):
    """Role B backed by a single chat completion. Quarantined: one completion, no tools, and the
    output is clamped to a SUBSET of the owned ids by `parse_set`. The rail supplies the SYSTEM
    prompt, the user-prompt builder (criterion + candidates -> str), and the id accessor; this
    class owns only the call + clamp + fail-closed behavior. The full model text is preserved on
    `ResolverSet.raw` as the (untrusted) reasoning trace."""

    def __init__(self, complete: CompleteFn, *, system: str, build_user, id_of=_default_id_of):
        self._complete = complete
        self._system = system
        self._build_user = build_user
        self._id_of = id_of

    def resolve(self, criterion: str, candidates: List) -> ResolverSet:
        valid = {self._id_of(c) for c in candidates}
        if not valid:
            return ResolverSet.none(reason="no owned candidates to choose from")
        user = self._build_user(criterion, candidates)
        try:
            raw = self._complete(self._system, user)
        except Exception as e:  # fail closed: a model/transport error -> empty set (escalate)
            return ResolverSet.none(reason=f"resolver call failed: {e}")
        return parse_set(raw, valid)


# ============================================================================
# Provider plumbing (rail-agnostic) — lazy openai/anthropic imports
# ============================================================================
def make_openai_complete(model: str = DEFAULT_OPENAI_MODEL, *,
                         temperature: float = 0.0, json_mode: bool = True,
                         max_completion_tokens: Optional[int] = None) -> CompleteFn:
    """Build a (system, user)->text completion backed by OpenAI. `openai` is imported LAZILY so
    this module stays agentdojo-free and import-light; the API key is read from the environment
    (OPENAI_API_KEY) by the SDK — never hardcoded.

    Reasoning models (gpt-5*, o1/o3/o4*) take a DIFFERENT call shape: the system prompt goes in a
    "developer" message, `temperature`/`top_p` are rejected, and the output budget is
    `max_completion_tokens`. We branch on the model name so a GPT-5 thinking row doesn't error."""
    try:
        import openai
    except Exception as e:  # pragma: no cover - exercised only in a live env
        raise RuntimeError(
            "The LLM resolver needs the 'openai' package. Install it and set "
            "OPENAI_API_KEY.") from e
    client = openai.OpenAI()
    rf = {"response_format": {"type": "json_object"}} if json_mode else {}
    reasoning = is_openai_reasoning_model(model)
    sys_role = "developer" if reasoning else "system"

    def complete(system: str, user: str) -> str:
        base = dict(model=model,
                    messages=[{"role": sys_role, "content": system},
                              {"role": "user", "content": user}])
        if reasoning:
            # No temperature/top_p; budget via max_completion_tokens (reasoning + output).
            mct = {"max_completion_tokens": max_completion_tokens} if max_completion_tokens else {}
            attempts = [{**base, **rf, **mct}, {**base, **mct}]
        else:
            attempts = [{**base, **rf, "temperature": temperature},
                        {**base, **rf},
                        {**base, "temperature": temperature}, base]
        for kwargs in attempts:
            try:
                return client.chat.completions.create(**kwargs).choices[0].message.content or ""
            except Exception:
                continue
        return ""

    return complete


def make_anthropic_complete(model: str = DEFAULT_ANTHROPIC_MODEL, *,
                            max_tokens: int = 512, temperature: float = 0.0) -> CompleteFn:
    """Build a (system, user)->text completion backed by Anthropic. `anthropic` is imported
    LAZILY so this module stays agentdojo-free; the API key is read from the environment
    (ANTHROPIC_API_KEY) by the SDK — never hardcoded."""
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
    cassette re-recorders, and the corpus runners so they all share one backend selection."""
    p = _resolve_provider(provider)
    if p == "openai":
        return make_openai_complete(model or DEFAULT_OPENAI_MODEL, **kw)
    if p == "anthropic":
        return make_anthropic_complete(model or DEFAULT_ANTHROPIC_MODEL, **kw)
    raise ValueError(f"unknown resolver provider {p!r}")
