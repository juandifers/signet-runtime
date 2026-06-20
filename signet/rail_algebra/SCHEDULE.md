# SCHEDULE.md — the lifecycle dimension of the rail algebra

The implementation report (`IMPLEMENTATION.md`) found that `{Policy, Bind, Door}` are the right
STRATEGIES, but the flat triple silently assumed all three fire **together** — the egress shape. The
merge rail breaks that: its Policy fires at mandate *resolution*, far upstream of the Bind+Door at
*authorize* time. This pass adds the missing dimension — a **Schedule** binding each axis (and each
Policy *layer*) to a lifecycle **Phase** — and re-expresses both rails as two schedules over the same
axes. Behavior is unchanged (the committed golden is the gate); the schedule is metadata +
opt-in instrumentation, never control flow. `base.Authorizer` is **not** made schedule-driven here
(§5.5 gates that next step).

---

## 1. The observed-phase map (traced) vs. the declared schedule

§0 ground truth — every axis/Policy-layer invocation traced to a real call site, then tagged with the
lifecycle phase it executes in:

| rail | axis / Policy layer | invocation site (traced) | phase |
|---|---|---|---|
| merge | Policy `within_allowlist` (universe ceiling: repo + base) | `role_b.py:62` (`run_gate`) ← lambda `mandate.py:276` ← `policy.py:within_allowlist` | **RESOLVE** |
| merge | Policy `within_fence` (scope/protected fence) | `role_b.py:67` (`run_gate`) ← lambda `mandate.py:277` ← `policy.py:within_fence` | **RESOLVE** |
| merge | allow-scope (`in_scope`) closes | computed in `github_project` → consumed *inside* `evaluate_fence` (the `within_fence` layer) | **RESOLVE** (no distinct CLOSE) |
| merge | Bind `recheck` (TOCTOU: chain_hash + effect == Cart) | `github_railbridge.py:recheck_against_context` ← `base.py:62` | **AUTHORIZE** |
| merge | Door `enforce` (conclude required Check Run) | `github_railbridge.py:produce_capability` ← `base.py:66` | **AUTHORIZE** |
| egress | Bind `recheck` (chain-bind + effect == Cart) | `egress/authorizer.py:recheck_against_context` ← `base.py:62` | **ADMIT** |
| egress | Policy `decide` (dest ∈ mandate ∩ standing) | `egress/authorizer.py:recheck_against_context` | **ADMIT** |
| egress | Door `enforce` (inline proxy admission) | `egress/authorizer.py:produce_capability` ← `base.py:66` | **ADMIT** |

Declared schedules (`schedule.py`), side by side with the observed sequence the faithfulness tests
re-derive at runtime:

```
RESOLUTION RAIL (merge)  MERGE_SCHEDULE              ADMISSION RAIL (egress)  EGRESS_SCHEDULE
  policy:allowlist @ RESOLVE                           bind   @ ADMIT
  policy:fence     @ RESOLVE                           policy @ ADMIT
  bind             @ AUTHORIZE                          door   @ ADMIT
  door             @ AUTHORIZE
```

Both are verified faithful in `tests/test_rail_schedule.py` (§3): a full passing run of each rail is
executed under `observe()`, and the collected `(component, phase)` sequence is asserted **equal** to
the declared `Schedule` — same components, same phases, same order.

---

## 2. Phase-set adjudication (the §5.2 verdict)

**The §1 hypothesis offered four phases — `{RESOLVE, CLOSE, ADMIT, AUTHORIZE}`. The observed map
eliminates `CLOSE`. The minimal phase set is `{RESOLVE, ADMIT, AUTHORIZE}`.**

The argument is from the trace, not aesthetics. `CLOSE` was hypothesized to hold "allow-scope fixed at
mandate close" as a *distinct* lifecycle point. But following the code:

- Allow-scope is the `in_scope` boolean. It is computed in `github_project` and **consumed inside the
  fence evaluator** (`evaluate_fence`, reached through the `within_fence` layer) — i.e. at RESOLVE,
  in the same breath as the `protected_path` check. There is no later re-evaluation of scope.
- What happens "at close" is the construction of a `ClosedMandate` (`mandate.py`, the `RESOLVED`
  branch). That is **record-binding** — packaging the already-gated survivor's `repo/pr/base/head_sha`
  into a frozen struct. It invokes **no Policy axis**: `decide`/`within_*` are not called again.

So a distinct `CLOSE` phase would name a lifecycle point at which **no scheduled component fires**.
That is not a phase in this model (phases are defined by where axes execute). `CLOSE` folds into
`RESOLVE`. The `Phase` IntEnum therefore ships exactly three ordered values.

(Symmetrically, the egress rail uses only `ADMIT`; merge uses only `RESOLVE` and `AUTHORIZE`. No rail
uses all three — the union, not any single rail, is what makes the three-value set minimal-yet-
sufficient.)

---

## 3. Layered Policy — how the merge fence decomposed

The merge Policy is **not one predicate**. The gate (`role_b.run_gate`) calls two distinct rail
predicates in order: `within_allowlist` (the universe ceiling — repo/service + base/environment) then
`within_fence` (scope + protected paths). Both already exist as separate methods on the
`DeclarativeMembership` Policy variant, so the layer→phase mapping was **clean, not forced**: each
method self-marks a distinct component (`policy:allowlist`, `policy:fence`) and both land at RESOLVE.

The decomposition is honest down to one subtlety worth recording: the `within_fence` *layer* itself
bundles two sub-decisions (path is not protected **AND** path is in allow-scope) inside the single
`evaluate_fence` call. The schedule models `within_fence` as **one** layer because that is the
granularity at which the gate *invokes* it — it is one predicate call, one rejection cause-string
seam. Splitting protected-vs-allow-scope into two scheduled layers would over-model: they do not fire
at separable lifecycle points, they are one evaluator pass. So the layering is "as fine as the
invocation sites are, no finer." The egress Policy, by contrast, is genuinely single-layer (one
`decide` over the pattern allowlist), so it marks a single `policy` component.

---

## 4. Faithfulness — where declared and observed matched (and the one risk it leaves)

Declared **equals** observed for both rails, on the first trace — no mismatch surfaced. That is the
expected outcome *because the schedule was declared FROM the observed map*, not guessed; the test's
value is catching future **drift**, not validating a guess.

The instrumentation is built to make drift observable rather than papered over: the phase is supplied
by the lifecycle **context** (`phase_scope`, a contextvar the rail enters around a region), and each
strategy **self-marks** its component when it executes. So if an axis is later moved into a different
lifecycle region — e.g. a Policy check relocated from the resolve gate into the authorize hook — its
observed phase flips automatically (it now runs inside a different `phase_scope`), and the faithfulness
test fails against the unchanged declaration. An axis moved **out** of every scoped region marks
`phase=None` and likewise fails. This is genuinely observed phasing, not a static annotation.

The residual risk, stated honestly: the `phase_scope(...)` *label* is still chosen by the rail at the
region boundary. A developer who both mislabels the scope **and** edits the declared `Schedule` to
match would pass a lie past the test — the same irreducible limit any declarative-vs-declared check
has. The test defends the common drift (code moves, declaration doesn't); it cannot defend a
coordinated mis-declaration. The mitigating factor is that the `phase_scope` regions are coarse and
few (one per lifecycle stage), so they are cheap to audit by eye against this table.

---

## 5. Readiness verdict — is `Composition + Schedule` the right shape to DRIVE `base.Authorizer`?

**Verdict: the shape is right for the AUTHORIZE-side axes (Bind, Door), but driving the template on
the *full* schedule is NOT yet safe — one thing must be resolved first.** Deferring (§9) was correct.

What the modeling confirmed is ready:
- The Bind+Door half of every rail fires at exactly one phase (AUTHORIZE for merge, ADMIT for egress),
  in a fixed order, *inside* `base.Authorizer.authorize`'s two hooks. A template that called
  `bind → door` in schedule order at authorize time would faithfully reproduce both rails. This half
  is promotable.

What the modeling exposed as a blocker:
- The merge **Policy fires at RESOLVE — a different lifecycle phase, in different code
  (`mandate.py`), before `authorize` is ever called.** `base.Authorizer` only ever sees the AUTHORIZE
  phase. So an "axis-driven template" that drove `policy → bind → door` would either (a) be wrong for
  merge (whose Policy is not at authorize time) or (b) force merge's resolution-time gate to be
  re-run at authorize time — a behavior change, and exactly the "harden egress's all-at-once
  assumption into the trusted base" mistake §9 warns against.

The clean resolution this pass points to (for the next, human-gated change): the template should be
driven **per-phase**, not per-Composition. A schedule-aware base would expose a phase boundary
(`run_phase(RESOLVE, ...)` at the resolve seam; `run_phase(AUTHORIZE, ...)` inside `authorize`) and
invoke only the components scheduled for that phase. Merge's Policy slots into the RESOLVE boundary
(owned by the rail's resolver), Bind+Door into AUTHORIZE (owned by the template). Egress's three
collapse into the one ADMIT boundary. That is a strictly larger change than this pass and touches the
read-only `base.py`, so it stays deferred — but the schedule is the right object to drive it, and the
phase set `{RESOLVE, ADMIT, AUTHORIZE}` is the right axis to drive it *along*.

---

### What surprised me

The hypothesised `CLOSE` phase evaporated on contact with the trace: "mandate close" felt like a
decision point but is pure record construction — no axis fires there. The lesson the flat triple
already taught, restated: a lifecycle phase is defined by *where an axis executes*, not by where the
narrative says something important happens. Modeling the schedule from the observed call sites (rather
than the conceptual story) is what kept the phase set minimal.
