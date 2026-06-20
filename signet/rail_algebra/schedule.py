"""The LIFECYCLE dimension of the rail algebra: a SCHEDULE binding each axis (and each Policy LAYER)
to an ordered lifecycle PHASE.

The flat `Composition = (Policy, Bind, Door)` silently assumed all three axes fire together — true for
the egress ADMISSION rail, false for the merge RESOLUTION rail (its Policy fires at mandate
resolution, far upstream of the Bind+Door at authorize time). This module adds the missing first-class
object: merge and egress differ in their SCHEDULE, not their axes.

The schedule is DECLARED (the `MERGE_SCHEDULE` / `EGRESS_SCHEDULE` constants) and verified FAITHFUL
against what actually executes (SPEC §3): each strategy SELF-MARKS its component when invoked, the rail
establishes the lifecycle PHASE via `phase_scope(...)` around the region, and `observe()` collects the
real (component, phase) sequence. The faithfulness test asserts observed == declared. The marks are
no-ops unless an `observe()` is active, so production behavior is unchanged (BEHAVIOR-PRESERVED) — this
is metadata + opt-in instrumentation, never control flow.

This module is PURE: it imports nothing from `signet.*` or `evals.*` (the algebra stays a dependency
leaf). The phase is supplied by the lifecycle CONTEXT (a contextvar the rail sets), not hand-written at
each axis call — so relocating an axis into a different lifecycle region flips its observed phase and
the faithfulness test catches the drift.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Tuple


# ============================================================================
# Phase — the ORDERED lifecycle points (the minimal set, see SCHEDULE.md §5.2)
# ============================================================================
class Phase(IntEnum):
    """The minimal lifecycle phase set the observed-map adjudication ended on.

    The §1 hypothesis offered four phases (RESOLVE, CLOSE, ADMIT, AUTHORIZE). Tracing the real
    invocation sites ELIMINATED CLOSE: merge's allow-scope (`in_scope`) is computed and consumed
    INSIDE the fence evaluator at RESOLVE — there is no distinct close-time policy decision (binding
    the survivor to a ClosedMandate is record construction, not a Policy axis). So CLOSE folds into
    RESOLVE and the minimal set is {RESOLVE, ADMIT, AUTHORIZE}."""
    RESOLVE = 0     # open mandate -> closed: set-valued narrowing + cardinality + fence (merge Policy)
    ADMIT = 1       # a concrete request admitted in one shot (egress: all three axes)
    AUTHORIZE = 2   # bind + enforce the closed effect (merge Bind + Door)


# Component labels a strategy self-marks with. Policy may decompose into LAYERS.
POLICY_ALLOWLIST = "policy:allowlist"   # merge: the universe ceiling (repo/service + base/env)
POLICY_FENCE = "policy:fence"           # merge: the scope/protected fence layer
POLICY = "policy"                       # egress: the single pattern-allowlist layer
BIND = "bind"
DOOR = "door"


# ============================================================================
# Step / Schedule — the new first-class objects
# ============================================================================
@dataclass(frozen=True)
class Step:
    """One scheduled component invocation: a component (a Policy LAYER, the Bind, or the Door) bound
    to the lifecycle Phase at which it fires."""
    component: str
    phase: Phase

    def __repr__(self) -> str:                              # pragma: no cover - cosmetic
        return f"{self.component}@{self.phase.name}"


@dataclass(frozen=True)
class Schedule:
    """An ordered sequence of Steps — the lifecycle schedule of a Composition. Two rails over the
    SAME axes differ only here."""
    steps: Tuple[Step, ...] = ()
    name: str = ""

    def __iter__(self):
        return iter(self.steps)

    def __len__(self) -> int:
        return len(self.steps)

    def is_monotonic(self) -> bool:
        """No axis fires before its inputs: phases are non-decreasing across the sequence."""
        return all(self.steps[i].phase <= self.steps[i + 1].phase
                   for i in range(len(self.steps) - 1))

    def matches(self, observed: "Schedule") -> bool:
        """Faithfulness: the declared (component, phase) sequence equals the observed one."""
        return tuple(self.steps) == tuple(observed.steps)

    def phases(self) -> Tuple[Phase, ...]:
        return tuple(s.phase for s in self.steps)


# ============================================================================
# Observation machinery — strategies self-mark; rails set the phase; tests observe
# ============================================================================
_CUR_PHASE: contextvars.ContextVar[Optional[Phase]] = contextvars.ContextVar(
    "signet_rail_phase", default=None)
_OBSERVATION: contextvars.ContextVar[Optional[List[Step]]] = contextvars.ContextVar(
    "signet_rail_observation", default=None)


@contextmanager
def phase_scope(phase: Phase):
    """A rail enters this around a lifecycle region (the resolve gate; the authorize hooks; the
    inline admission). Self-marks inside inherit `phase`. Negligible cost, never changes a verdict."""
    tok = _CUR_PHASE.set(phase)
    try:
        yield
    finally:
        _CUR_PHASE.reset(tok)


@contextmanager
def observe():
    """Collect the real (component, phase) marks emitted while running a rail end-to-end. Returns the
    growing list; wrap it in a Schedule with `observed_schedule(...)`. Test-only — outside an
    `observe()` block, `mark(...)` is a no-op (zero production overhead, BEHAVIOR-PRESERVED)."""
    rec: List[Step] = []
    tok = _OBSERVATION.set(rec)
    try:
        yield rec
    finally:
        _OBSERVATION.reset(tok)


def mark(component: str) -> None:
    """A strategy records that ITS component just fired. The phase comes from the active
    `phase_scope` (the lifecycle context), NOT from the call site — so an axis moved into a different
    lifecycle region reports a different phase and the faithfulness test catches it. No-op unless an
    `observe()` is active."""
    rec = _OBSERVATION.get()
    if rec is None:
        return
    rec.append(Step(component, _CUR_PHASE.get()))


def observed_schedule(rec: List[Step], name: str = "") -> Schedule:
    """Wrap a collected mark list as a Schedule for comparison against a declared one."""
    return Schedule(tuple(rec), name)


# ============================================================================
# The two DECLARED schedules — one per rail shape (verified faithful in §3 tests)
# ============================================================================
# RESOLUTION RAIL (merge): Policy decomposes into two LAYERS at RESOLVE (the universe-ceiling
# allowlist then the scope/protected fence), then Bind + Door fire together at AUTHORIZE.
MERGE_SCHEDULE = Schedule(
    (Step(POLICY_ALLOWLIST, Phase.RESOLVE),
     Step(POLICY_FENCE, Phase.RESOLVE),
     Step(BIND, Phase.AUTHORIZE),
     Step(DOOR, Phase.AUTHORIZE)),
    name="merge")

# ADMISSION RAIL (egress): all three axes fire at the single inline-admission point, in the order
# the authorizer's two hooks invoke them: Bind.recheck, then Policy.decide, then Door.enforce.
EGRESS_SCHEDULE = Schedule(
    (Step(BIND, Phase.ADMIT),
     Step(POLICY, Phase.ADMIT),
     Step(DOOR, Phase.ADMIT)),
    name="egress")
