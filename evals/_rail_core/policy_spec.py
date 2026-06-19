"""The declarative, TYPED policy grammar + the ONE shared evaluator — the heart of the
"fence-is-data-not-code" refactor.

A rail no longer ships fence/allow-list CODE. It ships:
  * a `CandidateSchema` — every attribute the policy is ALLOWED to read, each with a typed KIND
    (BOOL / CATEGORICAL(universe) / NUMERIC(lo, hi)) and a PROVENANCE (OWN / UNTRUSTED).
  * a `PolicySpec` — `allowlist` + `fence`, each a tuple of typed `Condition`s over those attrs.
  * a `project(candidate) -> {attr: value}` that maps a domain object to the declared attrs.

`evaluate_allowlist` and `evaluate_fence` below are the ONLY code that decides allow-list / fence.
Proven once, rail-independent. Because the decision is DATA evaluated by a shared function, a rail
physically cannot (a) read an attribute it did not declare (a Condition over an undeclared attr is a
load-time error, and a missing projected attr fails CLOSED), (b) write fail-open fence code (there is
no per-rail fence code to write), or (c) leave a declared dimension unswept (the battery sweeps the
whole schema). The honest residual — "is the DECLARED policy the INTENDED one" — is a review question,
made cheap by surfacing the PolicySpec as data (the scorecard renders + diffs it).

Set-aware comparisons: IN_SET / NOT_IN_SET work for a scalar attr (membership) AND a set-valued attr
(IN_SET == subset of the universe; NOT_IN_SET == disjoint from the universe), so a "resource types all
within the allowed universe" or "touches no protected type" predicate is DATA, not code.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ============================================================================
# attribute kinds
# ============================================================================
@dataclass(frozen=True)
class AttrKind:
    tag: str                                  # "bool" | "categorical" | "numeric"
    universe: frozenset = frozenset()          # categorical: the declared member universe
    lo: int = 0                                # numeric: declared attribute space [lo, hi]
    hi: int = 0


def BOOL() -> AttrKind:
    return AttrKind("bool")


def CATEGORICAL(universe) -> AttrKind:
    return AttrKind("categorical", universe=frozenset(universe))


def NUMERIC(lo: int, hi: int) -> AttrKind:
    return AttrKind("numeric", lo=int(lo), hi=int(hi))


# ============================================================================
# provenance — a fence/allow-list Condition may ONLY reference an OWN attribute
# ============================================================================
OWN = "own"
UNTRUSTED = "untrusted"


# ============================================================================
# variability — does widening an axis require the operator (HARD), or may a learned
# allow-rule open it within an operator-declared class (SOFT)?  This is the only
# addition to the shared policy model the policy-convergence loop needs; the shared
# EVALUATOR (`_holds` / `evaluate_*`) is deliberately left untouched. Missing/unknown
# variability is treated as HARD (fail safe: an axis is never silently learnable).
# ============================================================================
HARD = "hard"
SOFT = "soft"
_VARIABILITY = (HARD, SOFT)


def normalize_variability(v) -> str:
    """Fail safe: anything that is not EXACTLY SOFT collapses to HARD."""
    return SOFT if v == SOFT else HARD


@dataclass(frozen=True)
class AttrDecl:
    name: str
    kind: AttrKind
    provenance: str = OWN
    variability: str = HARD          # hard => operator-only widening; soft => learnable within a class

    def __post_init__(self):
        # normalize fail-safe without breaking frozen-ness (and without touching existing callers,
        # which simply omit the field and inherit HARD).
        object.__setattr__(self, "variability", normalize_variability(self.variability))


def axis_variability(schema) -> Dict[str, str]:
    """Map each declared axis name -> its (normalized) variability. The convergence generalizer
    reads ONLY this — an undeclared/missing axis is HARD, so it is never opened by a learned rule."""
    return {d.name: normalize_variability(getattr(d, "variability", HARD)) for d in schema}


# A CandidateSchema is just a tuple of AttrDecls (every attribute the policy may read).
CandidateSchema = Tuple[AttrDecl, ...]


# ============================================================================
# operators + conditions
# ============================================================================
IN_SET = "in_set"
NOT_IN_SET = "not_in_set"
LE = "le"
GE = "ge"
LT = "lt"
GT = "gt"
EQ = "eq"
OPS = (IN_SET, NOT_IN_SET, LE, GE, LT, GT, EQ)
_NUMERIC_OPS = (LE, GE, LT, GT)             # the bounding ops (a numeric attr needs one of these)


@dataclass(frozen=True)
class Condition:
    """One typed predicate over ONE declared attribute. `value` is a frozenset for IN_SET/NOT_IN_SET
    and a scalar for the comparison/EQ ops (kept hashable so a PolicySpec is frozen + diffable)."""
    attr: str
    op: str
    value: Any

    def describe(self) -> str:
        v = (sorted(self.value) if isinstance(self.value, (set, frozenset)) else self.value)
        return f"{self.attr} {self.op} {v}"


@dataclass(frozen=True)
class PolicySpec:
    """The resolved policy as DATA. `allowlist` is the universe ceiling; `fence` is the per-task
    discrimination. Within the universe iff ALL allowlist conditions hold; in-fence iff ALL fence
    conditions hold."""
    allowlist: Tuple[Condition, ...] = ()
    fence: Tuple[Condition, ...] = ()

    def describe(self) -> dict:
        return {"allowlist": [c.describe() for c in self.allowlist],
                "fence": [c.describe() for c in self.fence]}


# ============================================================================
# the ONE shared evaluator
# ============================================================================
def _holds(attr_value: Any, op: str, value: Any) -> bool:
    if op in (IN_SET, NOT_IN_SET):
        universe = value if isinstance(value, (set, frozenset)) else frozenset([value])
        if isinstance(attr_value, (set, frozenset)):       # set-valued attr: subset / disjoint
            member = set(attr_value) <= set(universe)
            return member if op == IN_SET else set(attr_value).isdisjoint(universe)
        member = attr_value in universe                    # scalar attr: membership
        return member if op == IN_SET else (not member)
    if op == EQ:
        return attr_value == value
    if op == LE:
        return attr_value <= value
    if op == GE:
        return attr_value >= value
    if op == LT:
        return attr_value < value
    if op == GT:
        return attr_value > value
    raise ValueError(f"unknown op {op!r}")


def _first_violation(attrs: Dict[str, Any], conditions: Tuple[Condition, ...]) -> Optional[str]:
    """Return the attr_name of the FIRST violated condition (the disposition), or None if all hold.
    A condition over an attribute MISSING from `attrs` fails CLOSED (its attr_name is returned) — a
    rail cannot read an undeclared/unprojected attribute and silently pass."""
    for c in conditions:
        if c.attr not in attrs:
            return c.attr
        if not _holds(attrs[c.attr], c.op, c.value):
            return c.attr
    return None


def evaluate_allowlist(attrs: Dict[str, Any], spec: PolicySpec) -> bool:
    """Within the universe iff EVERY allowlist condition holds (fail-closed on a missing attr)."""
    return _first_violation(attrs, spec.allowlist) is None


def evaluate_fence(attrs: Dict[str, Any], spec: PolicySpec) -> Tuple[bool, str]:
    """In-fence iff EVERY fence condition holds. Returns (in_fence, disposition) where disposition is
    the first violated condition's attr_name (telemetry), or "" when in-fence."""
    v = _first_violation(attrs, spec.fence)
    return (v is None, v or "")


# ============================================================================
# load-time structural checks (register_rail consumes these)
# ============================================================================
def schema_violations(schema: CandidateSchema, spec: PolicySpec) -> List[str]:
    """A Condition may ONLY reference a DECLARED, OWN attribute. A fence/allowlist condition over an
    UNTRUSTED attr (or an undeclared one) is a CONTRACT violation -> register_rail refuses the rail.
    This is what closes the prefilter-provenance gap for free: the policy can't read untrusted data."""
    by_name = {d.name: d for d in schema}
    out: List[str] = []
    for layer, conds in (("allowlist", spec.allowlist), ("fence", spec.fence)):
        for c in conds:
            d = by_name.get(c.attr)
            if d is None:
                out.append(f"{layer} condition {c.describe()!r} references UNDECLARED attr {c.attr!r}")
            elif d.provenance != OWN:
                out.append(f"{layer} condition {c.describe()!r} references {d.provenance.upper()} "
                           f"attr {c.attr!r} — fence/allowlist may reference ONLY OWN attributes")
    return out


def unbounded_numeric_warnings(schema: CandidateSchema, spec: PolicySpec) -> List[str]:
    """WARNING (not an invariant): a NUMERIC attribute declared in the schema but with NO bounding
    condition (LE/GE/LT/GT) anywhere in the fence/allowlist. The fence does not constrain it — the
    declarative analog of a fail-open quantitative gate. It does not BLOCK loading (the rail's code
    and its declared policy may honestly agree to ignore the axis), but it is surfaced so the rendered
    PolicySpec shows a numeric attr with no bound rather than silently passing."""
    bounded = {c.attr for c in (spec.allowlist + spec.fence) if c.op in _NUMERIC_OPS}
    return [f"NUMERIC attr {d.name!r} (space [{d.kind.lo},{d.kind.hi}]) has NO bounding condition "
            f"(LE/GE/LT/GT) — the fence does not constrain it (possible fail-open axis)"
            for d in schema if d.kind.tag == "numeric" and d.name not in bounded]


# ============================================================================
# EVALUATOR_SOUND — rail-independent proof that _holds applies the ops correctly (proven once)
# ============================================================================
def evaluator_soundness_failures() -> List[str]:
    """Enumerated truth-table over every op (scalar + set-valued). Returns a list of counterexamples
    (empty == sound). The battery runs this once per rail so EVALUATOR_SOUND is a load gate."""
    cases = [
        # (attr_value, op, value, expected)
        (3, LE, 3, True), (4, LE, 3, False), (3, LT, 3, False), (2, LT, 3, True),
        (3, GE, 3, True), (2, GE, 3, False), (4, GT, 3, True), (3, GT, 3, False),
        (True, EQ, True, True), (True, EQ, False, False), ("a", EQ, "a", True),
        ("x", IN_SET, frozenset({"x", "y"}), True), ("z", IN_SET, frozenset({"x", "y"}), False),
        ("z", NOT_IN_SET, frozenset({"x", "y"}), True), ("x", NOT_IN_SET, frozenset({"x"}), False),
        # set-valued attr: IN_SET == subset, NOT_IN_SET == disjoint
        (frozenset({"a"}), IN_SET, frozenset({"a", "b"}), True),
        (frozenset({"a", "c"}), IN_SET, frozenset({"a", "b"}), False),
        (frozenset({"c"}), NOT_IN_SET, frozenset({"a", "b"}), True),
        (frozenset({"a"}), NOT_IN_SET, frozenset({"a", "b"}), False),
    ]
    out = []
    for av, op, val, expected in cases:
        try:
            got = _holds(av, op, val)
        except Exception as e:                              # pragma: no cover
            out.append(f"_holds({av!r},{op},{val!r}) raised {e!r}")
            continue
        if got != expected:
            out.append(f"_holds({av!r},{op},{val!r})={got} expected {expected}")
    return out
