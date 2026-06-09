"""Pure, agentdojo-FREE core of the §6 effect-key machinery.

These primitives — `Effect`, `EffectPredicate`, `Resolution`, `effect_key`,
`resolve_effect_predicate`, and the kind/selector constants — carry NO dependency
on `agentdojo` (or any benchmark harness). They were factored out of
`evals/agentdojo/effects.py` so the PRODUCTION path (a rail-bridge authorizer + its
domain encoding) can reuse them without dragging the eval/agentdojo pipeline into
its import graph. `evals/agentdojo/effects.py` re-exports everything here unchanged
and keeps the agentdojo-dependent `EffectGatedToolsExecutor`.

A `domain` passed to `resolve_effect_predicate` is duck-typed (an `EffectDomainSpec`):
it supplies `authorized_classes`, `canonicalize_literal`, `amount_for`, `literal_ok`,
`match_descriptor`, `selector_candidates`, `target_allowed`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Resolution kinds + selectors (shared with the report).
ENDORSE = "ENDORSE"
REVIEW = "REVIEW"
BLOCK = "BLOCK"

SEL_NONE = "none"
SEL_CHEAPEST = "cheapest"       # min price (travel)
SEL_BEST_RATED = "best_rated"   # max rating (travel)
SEL_COMPUTED = "computed"       # an aggregate over data ("most active user") -> escalate
_SELECTORS = (SEL_NONE, SEL_CHEAPEST, SEL_BEST_RATED, SEL_COMPUTED)


@dataclass(frozen=True)
class Effect:
    """The canonical side effect (P1: bind the effect, not the tool)."""
    effect_class: str
    target_id: str
    amount_cents: int = 1            # 1 for non-priced effects; the price for travel


@dataclass(frozen=True)
class EffectPredicate:
    """A trusted, low-capacity predicate frozen from the instruction ONLY."""
    effect_class: str
    target_literal: Optional[str] = None   # a target named verbatim in the instruction
    descriptor: Optional[str] = None       # a NAME/keyword to resolve over own data
    selector: str = SEL_NONE               # cheapest/best_rated/computed (travel/aggregate)
    scope: Optional[str] = None            # a bounding scope from the instruction (e.g. a city)
    tiebreak: str = SEL_NONE               # secondary selector ("if multiple, higher price")


@dataclass
class Resolution:
    kind: str
    endorsed_target: Optional[str] = None
    endorsed_amount_cents: Optional[int] = None
    cause: str = ""
    candidates: list = field(default_factory=list)


def effect_key(effect_class: str, target_id: str) -> str:
    """The opaque string the kernel binds as the 'recipient'/destination."""
    return f"{effect_class}:{str(target_id).strip().lower()}"


# ============================================================================
# PREDICATE-mode resolver (the §4 mechanism, domain-parameterized)
# ============================================================================
def resolve_effect_predicate(pred: Optional[EffectPredicate], env, domain, *,
                             allowlist: Optional[set] = None,
                             cap_cents: Optional[int] = None) -> Resolution:
    """Endorse a runtime target over the principal's OWN bounded set. The criteria
    come only from the frozen predicate; the env supplies candidate values.
    """
    if pred is None:
        return Resolution(BLOCK, cause="out-of-predicate")
    ec = pred.effect_class
    if ec not in domain.authorized_classes:
        return Resolution(BLOCK, cause=f"out-of-envelope (effect_class {ec})")

    def _finish(target):
        amt = domain.amount_for(ec, target, env)
        if cap_cents is not None and amt is not None and amt > int(cap_cents):
            return Resolution(BLOCK, endorsed_target=target, endorsed_amount_cents=amt,
                              cause=f"over-budget ({amt} > cap {cap_cents})")
        return Resolution(ENDORSE, endorsed_target=target,
                          endorsed_amount_cents=(amt if amt is not None else 1),
                          cause="endorsed")

    # 1. literal target named in the instruction -> authorized by the instruction.
    #    First CANONICALIZE the literal over env (binding-only): a domain may resolve
    #    the EXACT named id to its full bound target_id (e.g. attach a runtime head_sha)
    #    so the kernel can context-bind it. The default hook returns the literal
    #    unchanged, so non-overriding domains are byte-identical. The hook is a keyed
    #    lookup of the one named id -- it never searches/selects among candidates, and
    #    it returns None for a literal that maps to zero or >1 in-scope owned targets
    #    (or that falls outside the envelope, e.g. a protected path) -> REVIEW, never
    #    guess. The same authorized-class gate (above) and the domain's literal_ok /
    #    cap gates (below) still run on the canonicalized target.
    if pred.target_literal:
        t = domain.canonicalize_literal(ec, str(pred.target_literal).strip(), env)
        if t is None:
            return Resolution(
                REVIEW,
                cause="literal not canonicalizable to a single in-scope target -> review")
        if not domain.literal_ok(ec, t, env):
            return Resolution(BLOCK, cause="no-match (named target not found)")
        return _finish(t)

    # 2. a computed aggregate ("most active user", "channel with most users") is NOT
    #    low-capacity -> escalate, never compute-and-guess.
    if pred.selector == SEL_COMPUTED:
        return Resolution(REVIEW, cause="computed-aggregate (not low-capacity) -> review")

    # 3. a min/max SELECTOR over a bounded scope (travel: cheapest/best in a city),
    #    computed over NON-INJECTABLE fields (price/rating), tie -> review.
    if pred.selector in (SEL_CHEAPEST, SEL_BEST_RATED):
        cands = domain.selector_candidates(ec, pred.scope, env)   # [(id, price, rating)]
        if not cands:
            return Resolution(BLOCK, cause="no-match (no candidates in scope)")
        keyf = (lambda c: c[1]) if pred.selector == SEL_CHEAPEST else (lambda c: -c[2])
        cands_sorted = sorted(cands, key=keyf)
        best = keyf(cands_sorted[0])
        winners = [c for c in cands_sorted if keyf(c) == best]
        if len(winners) > 1:
            # break ties with a secondary selector from the instruction, else review.
            if pred.tiebreak in (SEL_CHEAPEST, SEL_BEST_RATED):
                k2 = (lambda c: c[1]) if pred.tiebreak == SEL_CHEAPEST else (lambda c: -c[2])
                winners = sorted(winners, key=k2)
                if k2(winners[0]) == k2(winners[1]):
                    return Resolution(REVIEW, cause="ambiguous (selector tie) -> review",
                                      candidates=[w[0] for w in winners])
            else:
                return Resolution(REVIEW, cause="ambiguous (selector tie) -> review",
                                  candidates=[w[0] for w in winners])
        return _finish(winners[0][0])

    # 4. a descriptor (a NAME/keyword) resolved over the principal's OWN data, then
    #    bounded by what the domain considers a safe/approved target (the ownership /
    #    standing-allowlist bound — e.g. internal-domain emails, existing slack users).
    if pred.descriptor:
        cands = [c for c in domain.match_descriptor(ec, pred.descriptor, env)
                 if domain.target_allowed(ec, c, env)]
        if not cands:
            return Resolution(BLOCK, cause="off-allowlist/no-match (descriptor not an own/approved target)")
        if len(set(cands)) > 1:
            return Resolution(REVIEW, cause="ambiguous (descriptor -> >1 own target) -> review",
                              candidates=list(cands))
        return _finish(cands[0])

    return Resolution(REVIEW, cause="no trusted target -> review")
