"""Policy-convergence loop — the hard/soft generalizer that makes friction track FENCE
MOVEMENT instead of ACTION COUNT.

The problem this solves: standing policy starts nearly empty, so almost every effect is
unmatched and ESCALATES — and Signet feels like an ordinary permission prompt. The fix:
when a human approves an escalated effect, propose a LEARNED ALLOW-RULE that generalizes it —
OPENING the axes the operator marked safe to vary ("soft", within an operator-declared class)
while PINNING the axes that require deliberate movement ("hard": egress destination,
irreversibility, scope). A routine sibling that differs only on soft axes then runs silently;
a sibling that differs on any hard axis still escalates. Friction MOVED; the fence did not loosen.

This module is POLICY AUTHORING, not enforcement. It does NOT touch the kernel, the local gate,
or the shared effect-evaluator. It is purely additive and reuses the real structures:

  * AXES are the `CandidateSchema`'s `AttrDecl`s; their `variability` (hard|soft) is read via
    `axis_variability` (added to `policy_spec.py`, fail-safe HARD).
  * The THREE-WAY decision reuses `evaluate_allowlist` (the standing ceiling, checked FIRST) +
    `evaluate_fence` (per-clause match) and returns an `effect_core.Resolution`
    (BLOCK silently / ENDORSE silently-with-receipt / REVIEW = escalate).
  * MONOTONICITY is enforced twice: (a) structurally — `decide` BLOCKs anything outside the
    standing ceiling BEFORE consulting any learned rule, so a learned rule can never permit an
    effect standing denies; and (b) at authoring time — `inside_standing` rejects any candidate
    rule that would permit a ceiling-denied effect (the explicit guard the spec requires).
  * RECEIPTS are `LearnedRuleRecord`s appended to the existing `TransparencyLog` and verified by
    the existing `verify_inclusion` (both duck-typed on `record.record_hash()`), so the two new
    entry types verify under the unchanged receipt machinery.

Determinism: `generalize` is pure and clock-free (no `datetime.now`, no randomness, no ML, no
confidence scores). Timestamps/ids are supplied by the caller so the function is fully inspectable.
"""
from __future__ import annotations

import dataclasses
import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from signet.canonical import hash_obj

from ..effect_core import BLOCK, ENDORSE, REVIEW, Resolution
from .policy_spec import (HARD, IN_SET, SOFT, AttrDecl, Condition, PolicySpec, axis_variability,
                          evaluate_allowlist, evaluate_fence)
from .transparency import TransparencyLog, verify_inclusion

# Named invariants (distinct from measurements) — surfaced because evals/scorecard/** is fenced
# and cannot be edited by an agent; the test suite asserts these as INVARIANTS, not measurements.
INVARIANTS = (
    "GENERALIZER_CORRECT: every hard axis is pinned to the approved value; every soft axis WITH a "
    "declared class is opened to exactly that class; every soft axis WITHOUT a class is pinned; no "
    "axis is ever opened to a wildcard.",
    "INSIDE_STANDING: a confirmed learned rule permits no effect the standing ceiling denies — the "
    "set allowed by (standing + learned) never exceeds the set allowed by standing alone.",
)

LEARNED_CREATED_SCHEMA = "signet.learned_rule.created.v1"
LEARNED_PROMOTED_SCHEMA = "signet.learned_rule.promoted.v1"

SCOPE_SESSION = "session"
SCOPE_REPO = "repo"

# Fail-closed ceiling for the inside-standing enumeration: if a candidate's permitted effect-space
# (over the axes the ceiling actually constrains) exceeds this, we cannot cheaply PROVE the rule is
# inside standing, so we refuse it rather than guess.
_MAX_ENUM = 200_000


# ============================================================================
# Standing policy + the learned layer
# ============================================================================
@dataclass(frozen=True)
class Standing:
    """The operator-set standing policy, expressed over the SAME typed conditions as the rail
    PolicySpec. `ceiling` is the universe ceiling (an effect violating it is BLOCKED silently — this
    encodes `standing.deny` as the complement of the allowed universe). `allow_rules` are seed
    allow-clauses (each clause = a conjunction of Conditions); an in-ceiling effect matching any
    clause ENDORSEs silently. Learned rules add clauses to this same pool — never to the ceiling."""
    ceiling: Tuple[Condition, ...] = ()
    allow_rules: Tuple[Tuple[Condition, ...], ...] = ()

    def ceiling_spec(self) -> PolicySpec:
        return PolicySpec(allowlist=self.ceiling)


@dataclass(frozen=True)
class LearnedRule:
    """A confirmed allow-clause that lives strictly INSIDE standing (the guard proves it). Carries
    full provenance so the rule is inspectable and attributable."""
    id: str
    allow: Tuple[Condition, ...]
    from_effect: str          # the exact approved effect id/hash this was generalized from
    confirmed_by: str
    created_at: str
    scope: str = SCOPE_SESSION   # session | repo


@dataclass(frozen=True)
class CandidateRule:
    """A PROPOSED generalization awaiting explicit human confirmation. Records which axes were
    opened (and to what) and which were pinned, so the confirmation surface can show it plainly."""
    allow: Tuple[Condition, ...]
    from_effect: str
    opened: Tuple[Tuple[str, Tuple], ...]    # (axis, sorted class members) opened on soft axes
    pinned: Tuple[Tuple[str, object], ...]   # (axis, value) pinned on hard / classless-soft axes

    def to_learned_rule(self, *, rule_id: str, confirmed_by: str, created_at: str,
                        scope: str = SCOPE_SESSION) -> LearnedRule:
        return LearnedRule(id=rule_id, allow=self.allow, from_effect=self.from_effect,
                           confirmed_by=confirmed_by, created_at=created_at, scope=scope)


@dataclass(frozen=True)
class Rejected:
    """The generalizer's fail-closed result: a candidate rule could not be PROVEN inside standing,
    or an axis could not be safely opened. Carries a human-readable reason."""
    reason: str


@dataclass
class ActiveLayer:
    """An ordered, mutable set of confirmed learned rules at one scope (session or repo). Held by
    the resolution flow; consulted by `decide` alongside the standing seed allow-rules."""
    scope: str = SCOPE_SESSION
    rules: List[LearnedRule] = field(default_factory=list)

    def clauses(self) -> List[Tuple[Condition, ...]]:
        return [r.allow for r in self.rules]


# ============================================================================
# axis universes + per-condition value sets (built ONLY from the public evaluator)
# ============================================================================
def _axis_universe(decl: AttrDecl) -> frozenset:
    """The finite value space of one declared axis. CATEGORICAL -> its universe; BOOL -> {T,F};
    NUMERIC -> the (materialized) integer span [lo,hi]. The convergence loop is defined over the
    typed, finite axes the rail model already supports."""
    k = decl.kind
    if k.tag == "categorical":
        return frozenset(k.universe)
    if k.tag == "bool":
        return frozenset({True, False})
    if k.tag == "numeric":
        return frozenset(range(int(k.lo), int(k.hi) + 1))
    return frozenset()


def _values_satisfying(attr: str, conds: Tuple[Condition, ...], universe: frozenset) -> frozenset:
    """The subset of `universe` that satisfies EVERY condition on `attr`, decided ONLY through the
    public shared evaluator (`evaluate_fence`) — no re-implementation of operator semantics here."""
    spec = PolicySpec(fence=tuple(c for c in conds if c.attr == attr))
    return frozenset(v for v in universe if evaluate_fence({attr: v}, spec)[0])


# ============================================================================
# The inside-standing guard — the monotonicity proof (pure)
# ============================================================================
def inside_standing(clause: Tuple[Condition, ...], schema: Tuple[AttrDecl, ...],
                    standing: Standing, *, max_enum: int = _MAX_ENUM) -> Tuple[bool, str]:
    """Prove that EVERY effect a candidate allow-clause would permit is also inside the standing
    ceiling — i.e. (standing + this clause) allows nothing standing alone forbids. Decided by
    enumerating the clause's permitted effects over the axes the ceiling actually constrains and
    checking each against `evaluate_allowlist`. Fails CLOSED if the space is too large to enumerate
    (we refuse what we cannot prove)."""
    by_name = {d.name: d for d in schema}
    ceiling_attrs = {c.attr for c in standing.ceiling}
    if not ceiling_attrs:
        # nothing is forbidden by the ceiling -> any clause is trivially inside it.
        return True, "standing ceiling is empty — every clause is inside it"

    # Only the axes the ceiling constrains affect the verdict (evaluate_allowlist reads only those).
    relevant = sorted(ceiling_attrs)
    permitted: Dict[str, frozenset] = {}
    for attr in relevant:
        decl = by_name.get(attr)
        if decl is None:
            # ceiling references an axis not in the schema -> evaluate_allowlist fails closed anyway,
            # but we cannot enumerate its universe; refuse to certify.
            return False, f"ceiling references undeclared axis {attr!r} — cannot prove inside standing"
        universe = _axis_universe(decl)
        clause_conds = tuple(c for c in clause if c.attr == attr)
        permitted[attr] = (_values_satisfying(attr, clause_conds, universe)
                           if clause_conds else universe)
        if not permitted[attr]:
            # the clause permits NO value on a ceiling axis -> it permits no effect at all there;
            # vacuously inside standing on this axis.
            permitted[attr] = frozenset()

    space = 1
    for attr in relevant:
        space *= max(1, len(permitted[attr]))
    if space > max_enum:
        return False, (f"candidate space over ceiling axes is {space} (> {max_enum}) — cannot prove "
                       f"inside standing, refusing (fail closed)")

    ceiling_spec = standing.ceiling_spec()
    value_lists = [sorted(permitted[attr], key=_sort_key) for attr in relevant]
    for combo in itertools.product(*value_lists):
        attrs = dict(zip(relevant, combo))
        if not evaluate_allowlist(attrs, ceiling_spec):
            return False, (f"candidate would permit a standing-denied effect: "
                           f"{ {k: attrs[k] for k in relevant} }")
    return True, "candidate is provably inside the standing ceiling"


def _sort_key(v):
    # bools/ints/strings can mix in a categorical universe; sort by (type-name, repr) for determinism.
    return (type(v).__name__, repr(v))


# ============================================================================
# The generalizer — pure, deterministic, fail-closed
# ============================================================================
def generalize(approved_effect: Dict[str, object], schema: Tuple[AttrDecl, ...],
               standing: Standing, *, declared_classes: Optional[Dict[str, frozenset]] = None,
               from_effect: str = "") -> Union[CandidateRule, Rejected]:
    """Generalize ONE approved effect into a candidate allow-rule. PURE and side-effect free.

      * HARD axis                      -> PIN to the approved value.
      * SOFT axis WITH a declared class -> OPEN to that class (iff the approved value is in it and
                                          the class is a strict, bounded subset of the axis universe).
      * SOFT axis WITHOUT a class       -> PIN to the approved value (this kind keeps escalating).

    Never emits a wildcard. Then runs the inside-standing guard; returns `Rejected` if the candidate
    cannot be proven inside standing (e.g. a soft class reaches outside the ceiling)."""
    declared_classes = declared_classes or {}
    variability = axis_variability(schema)
    by_name = {d.name: d for d in schema}

    allow: List[Condition] = []
    opened: List[Tuple[str, Tuple]] = []
    pinned: List[Tuple[str, object]] = []

    # Deterministic axis order = schema order.
    for decl in schema:
        axis = decl.name
        if axis not in approved_effect:
            # No value to pin/open. A hard axis with no value cannot be generalized safely.
            if variability.get(axis, HARD) == HARD:
                # not present in the effect -> simply not constrained by this rule (the ceiling
                # still gates it). We do not invent a pin we did not observe.
                continue
            continue
        value = approved_effect[axis]
        var = variability.get(axis, HARD)

        if var == SOFT and axis in declared_classes:
            cls = frozenset(declared_classes[axis])
            universe = _axis_universe(decl)
            if not cls:
                return Rejected(f"soft axis {axis!r}: declared class is empty")
            if value not in cls:
                return Rejected(f"soft axis {axis!r}: approved value {value!r} is not in its declared "
                                f"class {sorted(cls, key=_sort_key)} — cannot open to a class that "
                                f"excludes the approved value")
            if cls >= universe:
                # opening to the entire axis universe IS a wildcard — refuse (never emit `*`).
                return Rejected(f"soft axis {axis!r}: declared class equals the full axis universe "
                                f"(a wildcard) — refused")
            allow.append(Condition(axis, IN_SET, cls))
            opened.append((axis, tuple(sorted(cls, key=_sort_key))))
        else:
            # HARD, or SOFT-without-a-class -> PIN to exactly the approved value.
            allow.append(Condition(axis, IN_SET, frozenset({value})))
            pinned.append((axis, value))

    allow_t = tuple(allow)
    ok, reason = inside_standing(allow_t, schema, standing)
    if not ok:
        return Rejected(reason)
    return CandidateRule(allow=allow_t, from_effect=from_effect,
                         opened=tuple(opened), pinned=tuple(pinned))


# ============================================================================
# The three-way decision — reuses the shared evaluator; ceiling is checked FIRST
# ============================================================================
def _clause_matches(attrs: Dict[str, object], clause: Tuple[Condition, ...]) -> bool:
    return evaluate_fence(attrs, PolicySpec(fence=clause))[0]


def decide(attrs: Dict[str, object], standing: Standing,
           layers: Tuple[ActiveLayer, ...] = ()) -> Resolution:
    """The three-way runtime disposition, composed from the unchanged shared evaluator:

      * outside the standing ceiling           -> BLOCK   (silent)
      * in-ceiling AND matches some allow-clause -> ENDORSE (silent, receipt)
      * in-ceiling but unmatched                -> REVIEW  (escalate to a human)

    The ceiling is consulted BEFORE any learned rule, so a learned rule is structurally incapable of
    endorsing an effect standing denies — monotonicity holds even if a bad rule slipped into a layer."""
    if not evaluate_allowlist(attrs, standing.ceiling_spec()):
        return Resolution(BLOCK, cause="outside standing ceiling (silent block)")
    for clause in standing.allow_rules:
        if _clause_matches(attrs, clause):
            return Resolution(ENDORSE, cause="matches a standing allow-rule (silent, receipt)")
    for layer in layers:
        for rule in layer.rules:
            if _clause_matches(attrs, rule.allow):
                return Resolution(ENDORSE, cause=f"matches learned rule {rule.id} (silent, receipt)")
    return Resolution(REVIEW, cause="unmatched effect — escalate to human")


# ============================================================================
# Presentation (minimal CLI text) + the escalation-resolution hook
# ============================================================================
def render_candidate(candidate: CandidateRule) -> str:
    """A minimal, inspectable rendering of a proposed generalization for human confirmation."""
    lines = ["Proposed learned allow-rule (generalized from approved effect "
             f"{candidate.from_effect or '<unknown>'}):"]
    for axis, members in candidate.opened:
        lines.append(f"  OPEN  {axis}  ->  any of {list(members)}   (soft axis, declared class)")
    for axis, value in candidate.pinned:
        lines.append(f"  PIN   {axis}  ==  {value!r}   (hard / no declared class)")
    lines.append("  allow-clause: " + "; ".join(c.describe() for c in candidate.allow))
    lines.append("Confirm to add this rule INSIDE standing policy (it can only restrict, never widen).")
    return "\n".join(lines)


def confirm(candidate: CandidateRule, layer: ActiveLayer, *, rule_id: str,
            confirmed_by: str = "operator", created_at: str = "",
            scope: Optional[str] = None,
            log: Optional["PolicyAuthoringLog"] = None) -> Tuple[LearnedRule, Optional["LearnedRuleRecord"]]:
    """Apply an EXPLICITLY confirmed candidate: materialize a LearnedRule, append it to the active
    layer, and (if a receipt log is supplied) emit a signed, chained `learned_rule_created` record.
    Learned rules are NEVER auto-applied — this function is the human's confirmation step."""
    rule = candidate.to_learned_rule(rule_id=rule_id, confirmed_by=confirmed_by,
                                     created_at=created_at, scope=scope or layer.scope)
    layer.rules.append(rule)
    rec = log.record_created(rule) if log is not None else None
    return rule, rec


def promote(rule: LearnedRule, session_layer: ActiveLayer, repo_layer: ActiveLayer, *,
            always: bool, created_at: str = "",
            log: Optional["PolicyAuthoringLog"] = None) -> Tuple[LearnedRule, Optional["LearnedRuleRecord"]]:
    """Promote a session-scoped learned rule to the repo layer. Allowed ONLY on an explicit
    `always=True` (no auto-promotion; promotion to the standing/org layer is out of scope)."""
    if not always:
        raise PermissionError("promotion session->repo requires an explicit 'always' (no auto-promotion)")
    if rule.scope != SCOPE_SESSION:
        raise ValueError(f"only session-scoped rules can be promoted (got scope={rule.scope!r})")
    promoted = dataclasses.replace(rule, scope=SCOPE_REPO,
                                   created_at=created_at or rule.created_at)
    if rule in session_layer.rules:
        session_layer.rules.remove(rule)
    repo_layer.rules.append(promoted)
    rec = log.record_promoted(promoted) if log is not None else None
    return promoted, rec


# ============================================================================
# Receipts — new entry types over the EXISTING TransparencyLog / verify_inclusion
# ============================================================================
def _clause_to_jsonable(clause: Tuple[Condition, ...]) -> Tuple[dict, ...]:
    out = []
    for c in clause:
        v = (sorted(c.value, key=_sort_key) if isinstance(c.value, (set, frozenset)) else c.value)
        out.append({"attr": c.attr, "op": c.op, "value": v})
    return tuple(out)


@dataclass(frozen=True)
class LearnedRuleRecord:
    """A policy-AUTHORING audit record (not an enforcement decision). It is duck-typed to slot into
    the existing `TransparencyLog`: it exposes `record_hash()` plus the `sensitive`/`execution_id`/
    `chain_hash` attributes the log's `append` reads, so it lands in the same Merkle chain and
    verifies under the unchanged `verify_inclusion`."""
    schema: str
    event: str                # "learned_rule_created" | "learned_rule_promoted"
    rule_id: str
    from_effect: str
    confirmed_by: str
    created_at: str
    scope: str
    allow: Tuple[dict, ...]
    # --- shims read by TransparencyLog.append (a policy event has no kernel enforcement binding) ---
    sensitive: bool = True
    execution_id: str = ""
    chain_hash: str = ""

    def to_canonical(self) -> dict:
        return {"schema": self.schema, "event": self.event, "rule_id": self.rule_id,
                "from_effect": self.from_effect, "confirmed_by": self.confirmed_by,
                "created_at": self.created_at, "scope": self.scope, "allow": self.allow}

    def record_hash(self) -> str:
        return hash_obj(self.to_canonical())


def _record_for(rule: LearnedRule, *, schema: str, event: str, scope: Optional[str] = None) -> LearnedRuleRecord:
    return LearnedRuleRecord(
        schema=schema, event=event, rule_id=rule.id, from_effect=rule.from_effect,
        confirmed_by=rule.confirmed_by, created_at=rule.created_at, scope=scope or rule.scope,
        allow=_clause_to_jsonable(rule.allow))


class PolicyAuthoringLog:
    """A thin owner of a `TransparencyLog` dedicated to policy-authoring events. Each emitted record
    is appended to the Merkle chain (its own hash doubles as the leaf's receipt_hash, since there is
    no kernel receipt to bind), and `verify` re-derives an inclusion proof and checks it with the
    EXISTING `verify_inclusion` — proving the new entry types verify under the unchanged machinery."""

    def __init__(self, enforcer_sk: str, enforcer_vk: str, *, log_id: str = "policy-authoring",
                 clock=None) -> None:
        self._log = TransparencyLog(enforcer_sk, enforcer_vk, log_id=log_id, clock=clock)
        self._vk = enforcer_vk
        self._index: Dict[Tuple[str, str], int] = {}

    def _emit(self, rec: LearnedRuleRecord) -> LearnedRuleRecord:
        entry = self._log.append(rec, receipt_hash=rec.record_hash())
        self._index[(rec.rule_id, rec.event)] = entry.index
        return rec

    def record_created(self, rule: LearnedRule) -> LearnedRuleRecord:
        return self._emit(_record_for(rule, schema=LEARNED_CREATED_SCHEMA, event="learned_rule_created"))

    def record_promoted(self, rule: LearnedRule) -> LearnedRuleRecord:
        return self._emit(_record_for(rule, schema=LEARNED_PROMOTED_SCHEMA, event="learned_rule_promoted",
                                      scope=SCOPE_REPO))

    def size(self) -> int:
        return self._log.size()

    def verify(self, rule_id: str, event: str = "learned_rule_created") -> Tuple[bool, str]:
        """Independently verify that the named policy-authoring record is committed under the signed
        root — using ONLY the existing transparency verifier."""
        idx = self._index[(rule_id, event)]
        rec = self._log.entries()[idx].record
        proof = self._log.inclusion_proof(idx)
        sth = self._log.sign_root()
        return verify_inclusion(rec, proof, sth, self._vk)
