# PROMOTION.md — making `base.Authorizer` schedule-driven (AUTHORIZE/ADMIT half)

Implementation report for SPEC v2. The first DELIBERATE edit to the trusted-base authorizer template:
`base.Authorizer` now DRIVES a composed rail's terminal (Door) phase via its declared `Schedule`
instead of two hardcoded hooks — the half SCHEDULE.md §5.5 certified promotable. Every non-composed
rail stays on the unchanged legacy hooks (COEXISTENCE). Behavior is preserved against the committed
golden (extended-first, never regenerated); the 10 kernel files are byte-identical (K0); RESOLVE-phase
driving stays deferred (§7 here / SPEC §8).

Written against the real interface; line numbers as of this commit.

---

## 1. The `authorize()` branch — composed vs legacy, and the before→after

`signet/authorizers/base.py` now carries a class attribute `composition = None` (base.py:77) and a
two-way branch in the FINAL `authorize` template (base.py:79–104):

```python
if not self._verifier.verify_token(token, self._enforcer_vk):      # unchanged FIRST line
    return AuthorizationResult(False, "Enforcer token invalid/expired.", rail=self.rail)
composition = self.composition
if composition is not None and getattr(composition, "schedule", None) is not None:
    return self.run_phase(composition.schedule.driven_phase(), composition, token, req)   # COMPOSED
ok, reason = self.recheck_against_context(token, req)              # LEGACY (byte-for-byte the prior flow)
if not ok:
    self.on_rejected(token, req, reason)
    return AuthorizationResult(False, reason, rail=self.rail)
return self.produce_capability(token, req)
```

`verify_token` stays the unconditional first gate for BOTH paths (the AUTHZ_TEMPLATE invariant; the
conformance battery still drives `authorize` with an invalid token and a recheck-failing request and
both BLOCK — `evals/conformance/battery.py`). The legacy `else` arm is the prior body verbatim.

**merge** (`signet/authorizers/github_railbridge.py`):
- *before*: `recheck_against_context` = `EffectKeyOneShot.recheck` wrapped in `phase_scope(AUTHORIZE)`;
  `produce_capability` = `ExternalEnforcer.enforce` wrapped in `phase_scope(AUTHORIZE)`. `authorize`
  (in base) called them in order.
- *after*: a `Composition(policy=None, bind, door, schedule=MERGE_SCHEDULE)` is declared in `__init__`
  (github_railbridge.py:108), so `authorize` drives the terminal phase AUTHORIZE = `[Bind, Door]`. The
  Bind/Door content moved into shared helpers `_bind_outcome` (railbridge.py:159) and `_door_result`
  (railbridge.py:166); `_components_for` (railbridge.py:181) returns `[Bind, Door]` at AUTHORIZE and
  `[]` elsewhere. `on_rejected` (railbridge.py:189) is unchanged (Door.decline → conclude the Check
  Run as failure). The two legacy hooks REMAIN DEFINED (railbridge.py:197, 203) and delegate to the
  same helpers — one implementation, no drift.

**egress** (`signet/rails/egress/authorizer.py`):
- *before*: `recheck_against_context` bundled `bind.recheck` + two INLINE lifecycle guards
  (no-frozen-mandate / mandate-expired, plus the `last_mandate_hash` side effect) + `policy.decide`,
  all under one `phase_scope(ADMIT)`; `produce_capability` = `NetworkSolePath.enforce`.
- *after*: `authorize` drives ADMIT = `[Bind, MandateFreshness, Policy, Door]`. The two inline guards
  are promoted into the first-class `MandateFreshness` component (authorizer.py:41) backed by
  `_check_mandate_freshness` (authorizer.py:138, which preserves the `last_mandate_hash` side effect);
  Bind/Policy/Door content moved into `_bind_outcome`/`_policy_outcome`/`_door_result`
  (authorizer.py:150/156/164); `_components_for` (authorizer.py:177) returns the four ADMIT components
  in EGRESS_SCHEDULE order. The two legacy hooks REMAIN DEFINED (authorizer.py:193, 205) — the
  conformance/rail-algebra tests assert they are in `EgressAuthorizer.__dict__` — and delegate to the
  same helpers.

## 2. `run_phase` contract

`base.run_phase(phase, composition, token, req)` (base.py:105–136) invokes exactly the components the
Schedule places at `phase`, in declared order, fail-closed:

- `steps = composition.schedule.steps_for(phase)` (the declared steps at this phase); the rail supplies
  the matching `components = self._components_for(phase, token, req)`.
- **The Schedule DRIVES**: if there are no steps, or the component LABELS do not equal the declared
  `Step.component` labels in order, it BLOCKS (`schedule/component mismatch`). This binds invocation to
  the declaration — a rail cannot quietly run a different/extra/re-ordered component than its schedule
  says.
- Components run inside `with phase_scope(phase)` (base.py:121), so each strategy's self-`mark`
  reports the driven phase — SCHEDULE-FAITHFUL stays a genuine runtime observation, not a static label.
- `*gates, last = components`: each GATE component returns a `ComponentOutcome`; a raise → BLOCK
  (`{label} raised`) after `on_rejected`; a `not ok` → BLOCK with its cause after `on_rejected` (this
  reproduces the legacy "recheck failed → on_rejected → deny"). The terminal `last` must be the Door
  (`is_door`); it returns the final `AuthorizationResult` directly and NEVER triggers `on_rejected`
  (reproducing the legacy "produce_capability owns the success/Blocked result"). A missing terminal
  Door or a raising Door → BLOCK. No path returns an implicit allow.

`Schedule.driven_phase()` (schedule.py:99) returns the phase of the LAST step (always the Door) — the
single phase a lone authorizer owns. For merge that is AUTHORIZE; for egress, ADMIT. `steps_for`
(schedule.py:93) returns the ordered steps at a phase.

## 3. Phase-isolation evidence (PHASE-ISOLATION)

Merge's Policy is scheduled at RESOLVE (`MERGE_SCHEDULE`), and `run_phase(AUTHORIZE)` pulls only
`steps_for(AUTHORIZE)` = `[Bind, Door]` — Policy is *structurally* excluded from the authorizer's
driven phase; there is no code path that re-invokes it at AUTHORIZE. This is stronger than a counter:
the Policy cannot run at AUTHORIZE because it is not scheduled there and `_components_for` returns `[]`
for any non-AUTHORIZE phase. `test_merge_policy_not_rerun_at_authorize` confirms it dynamically: in a
full observed merge run, zero `policy*` marks carry `phase == AUTHORIZE`, while `policy:allowlist` and
`policy:fence` DO fire at RESOLVE (so the assertion is not vacuous).

## 4. Inline-guard enumeration + no-drop evidence (A1/A3, COMPONENT-COMPLETENESS)

Per-composed-rail gate inventory (SPEC §0.5), re-confirmed against source:

- **merge** AUTHORIZE recheck: ONE guard, `bind.recheck` (a composition component). NO inline guards.
  `[Bind, Door]` is complete — **CLEAN**.
- **egress** ADMIT recheck (pre-promotion): `bind.recheck` (component) → `mandate is None →
  "no-frozen-mandate"` (INLINE) → `mandate.is_expired → "mandate-expired"` (INLINE; sets
  `last_mandate_hash`) → `policy.decide` (component). Two inline guards + one side effect would have
  been DROPPED by a naïve `[Bind, Policy, Door]` drive — **DIRTY → required A2**.

No-drop evidence: the two inline guards are now the `MandateFreshness` component
(`_check_mandate_freshness`, authorizer.py:138), scheduled as the second `BIND` step at ADMIT. The
golden was EXTENDED FIRST (§6) with the two characterizing rows, and
`test_egress_mandate_freshness_not_dropped` drives the real `authorize → run_phase` path and asserts:
expired mandate → `block "mandate-expired"`; missing mandate → `block "no-frozen-mandate"`; fresh
mandate → ALLOW with `authz.last_mandate_hash` set (`em_…`). This is the test that would have failed
had the guards been silently dropped.

## 5. Coexistence state (NON-COMPOSED-UNCHANGED)

All `Authorizer` subclasses found: `MockCredentialBroker`, `GitHubRailBridge` (merge),
`DeployRailBridge`, `InfraRailBridge`, `EgressAuthorizer` (egress), `SupabaseAuthorizer`, plus the
cosigners (`XRPLCosigner`, `MPCThresholdCosigner`) which deliberately override `authorize` to raise.

| authorizer | composition? | path |
|---|---|---|
| GitHubRailBridge (merge) | yes (MERGE_SCHEDULE) | **schedule-driven** @ AUTHORIZE = [Bind, Door] |
| EgressAuthorizer (egress) | yes (EGRESS_SCHEDULE) | **schedule-driven** @ ADMIT = [Bind, MandateFreshness, Policy, Door] |
| MockCredentialBroker | no | legacy hooks (unchanged) |
| DeployRailBridge | no | legacy hooks (unchanged) |
| InfraRailBridge | no | legacy hooks (unchanged) |
| SupabaseAuthorizer | no | legacy hooks (unchanged) |
| XRPL / MPC cosigners | no | override `authorize` to raise (documented exception) |

Only merge + egress carry a `composition` (verified: `self.composition =` appears only in
github_railbridge.py and egress/authorizer.py). The class-level default `composition = None` keeps all
others on the legacy arm with ZERO behavior change. The full suite (410 passed, 6 skipped) — which
exercises deploy/infra/supabase/broker through their own batteries — stays green;
`test_legacy_rail_unchanged` additionally spot-checks the branch and that the real legacy bridges carry
no composition. The "two functions" structural claim still holds: the new driving hook is PRIVATE
(`_components_for`), so a rail's public content surface remains exactly the two hooks
(`demos/two_functions_proof.py` / `tests/test_two_functions.py` green — see §8).

## 6. Golden (BEHAVIOR-PRESERVED, extended-first)

`tests/_golden/rail_verdicts.json` existing rows were NOT regenerated; `test_golden_unchanged`
(`build_corpus() == _GOLDEN`) is byte-for-byte green post-promotion — including the egress rows now
reproduced THROUGH the driven schedule (`MandateFreshness`/`run_phase`). Two NEW egress rows were added:

```
{ "label": "mandate_expired",   "host": "api.allowed.test", "port": 443, "admitted": false, "cause": "mandate-expired" }
{ "label": "no_frozen_mandate", "host": "api.allowed.test", "port": 443, "admitted": false, "cause": "no-frozen-mandate" }
```

Git ordering (the proof they characterize PRE-change behavior):
- commit `55625f4` — *"golden: extend egress corpus with mandate-lifecycle rows (pre-promotion
  baseline)"* — adds the two rows from the unmodified tree (pure extension; the diff is additions only).
- the promotion commit (this one) — follows it; the same two rows are reproduced verdict-for-verdict.

## 7. RESOLVE-driving readiness verdict (SPEC §4.7 — gates the follow-on)

**Verdict: `run_phase(RESOLVE)` at the resolver seam is READY as the next increment; this pass exposed
no blocker — it surfaced the shape it needs.** The dispatch generalizes cleanly: `run_phase` already
takes an arbitrary `phase`, `steps_for(RESOLVE)` already returns merge's `[policy:allowlist,
policy:fence]`, and the label/order consistency check + fail-closed flow are phase-agnostic. The one
real difference RESOLVE introduces (not a blocker, a design input): the merge Policy is a per-CANDIDATE
predicate consumed inside the Role-B gate (`run_gate`), not a single pass/fail over one frozen effect —
so a `_components_for(RESOLVE)` would model the gate's two layers as components whose `invoke` is
evaluated against the resolver's chosen candidate, and the RESOLVE boundary is owned by the resolver
seam (`mandate.py`), not `authorize`. That is a larger change touching the gate's predicate
consumption (SPEC §8 / out of scope here). Recommendation: do it next, behind the same
GOLDEN-EXTENDED-FIRST + COMPONENT-COMPLETENESS discipline; the schedule object and the `{RESOLVE,
ADMIT, AUTHORIZE}` phase set are the right primitives to drive it.

## 8. Residue / surprises

- **The driving hook had to be PRIVATE, and that is the honest design.** The first full-suite run went
  red on `tests/test_two_functions.py`: a public `components_for` registered as an "extra public
  method", regressing the "writing a rail is two functions" claim. Renaming to `_components_for`
  (base.py:138; the overrides in both composed rails) resolved it WITHOUT touching the test or the
  proof — `demos/two_functions_proof.py` already treats underscore-prefixed methods as private helpers.
  This is correct, not a dodge: the two PUBLIC content hooks (`recheck_against_context`,
  `produce_capability`) remain a rail's only public surface; `_components_for` is internal plumbing
  that re-expresses the SAME content as ordered, phase-tagged steps for the Schedule to drive.
- **`MandateFreshness` marks BIND, so `EGRESS_SCHEDULE` grew a second `bind` step** (`[BIND, BIND,
  POLICY, DOOR]`). The egress faithfulness fixture now observes four marks and still matches the
  declared schedule — which is exactly the point of A2: the schedule now MODELS what runs, dissolving
  (not caveating) the egress-Bind disclosure asymmetry the schedule verification flagged.
- **The legacy hooks were kept (not removed) AND made to delegate.** Removing them was out of scope and
  would have broken `EgressAuthorizer.__dict__` assertions; leaving them as dead duplicates risked
  drift. Delegating both composed rails' hooks to the shared `_*_outcome`/`_door_result` helpers keeps
  one implementation of the Bind/Door/Policy content for both the driven and legacy paths.
- **No `self.composition` on merge pre-promotion.** Merge previously carried only `SCHEDULE =
  MERGE_SCHEDULE` (a class attr) and `self.bind`/`self.door`; the branch needed a real `Composition`,
  so one was declared with `policy=None` (the merge Policy lives upstream at RESOLVE — §3).
- **Local gate inactive this session.** `.signet/policy.yaml` still lists `signet/authorizers/**` as
  protected, but the `signet hook` PreToolUse gate is not wired in this checkout's
  `.claude/settings.local.json`, so these human-directed trusted-base edits were not intercepted. The
  policy fence is unchanged; a human relaxes it via the CLI, not the agent.
