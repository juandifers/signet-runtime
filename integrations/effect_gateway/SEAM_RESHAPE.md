# SEAM_RESHAPE — generalize `RailBinding` from resolution-only to {resolution, admission}

The FIRST deliberate edit to `integrations/effect_gateway/seam.py` — the orchestrator-agnostic
trusted-base primitive that was byte-identical (`8761fe98…`) through merge, egress, and supabase.
`SEAM-SHAPE-OVERFIT` was `[confirmed, 2 votes]`: two structurally-independent admission rails
(egress, supabase) proved the contract over-fit the RESOLUTION shape. This change generalizes it
**without changing a single verdict** — the seam-layer twin of the schedule promotion: behavior
preserved against committed goldens, all THREE known-good rails reproduced verdict-for-verdict,
fail-closed, K0 intact.

Acceptance: `tests/test_seam_reshape.py` (12 tests). Old sha `8761fe98…` → **new sha
`653afde94c8de70ec77fb0567e9d54991a18c35b96e5db9a441499526e60d49c`**.

---

## 1. Orient re-confirmation (the unpushed bindings vs their reports)

merge is on origin; egress + supabase are unpushed, so their call paths were re-confirmed against
the LOCAL files before editing (not trusted from the reports). All three matched their reports:

| Rail | shape | prepare hook (was `resolver_for`) | `submit` body | verifier | resume |
| --- | --- | --- | --- | --- | --- |
| merge (`rails_github.py`) | resolution | wraps a raw pick → `FixedChoiceResolver`/`FixedSetResolver` | `resolve_task_mandate(mandate, world, effective, resolver=<proposal>)` → `authorize_closed_mandate` reaching `env.verifier.evaluate` | **`env.verifier`** | yes (`resume`, L167) |
| egress (`rails_egress.py`) | admission | vestigial pass-through → now honest identity-prepare | ignores `proposal`/`world`/`env`; `broker.mint_token` then `EgressAuthorizer.authorize` | **per-effect** (`broker_core.mint_token`) | none |
| supabase (`rails_supabase.py`) | admission | vestigial pass-through → now honest identity-prepare | ignores `proposal`/`world`/`env`; reads `mandate.task_id` (load-bearing); `DbBrokerCore.mint_token` then `SupabaseAuthorizer.authorize` | **per-effect** (`DbBrokerCore._verifier_for`) | none |

Both faces of the over-fit reproduced exactly as recorded — the reshape is the strictly larger
change the two bends pointed to, nothing new surfaced (§8).

## 2. The seam before → after

**`RailBinding` Protocol** — gains a first-class `shape`, renames the prepare hook, renames the
`submit` kwarg, and the docstring stops claiming one authoritative verifier:

```diff
 class RailBinding(Protocol):
     name: str
+    shape: str                       # "resolution" | "admission"
     def handles(self, eff) -> bool: ...
-    def resolver_for(self, proposal): ...     # always coerce into a candidate-picker
+    def proposal_for(self, proposal): ...     # resolution: a Role-B Resolver; admission: the effect
-    def submit(self, eff, *, mandate, world, env, bridge, receipts, resolver) -> "Decision": ...
+    def submit(self, eff, *, mandate, world, env, bridge, receipts, proposal) -> "Decision": ...
```

**`intercept` — routes by shape** (no universal resolver coercion; unknown/absent shape fails closed):

```python
shape = getattr(binding, "shape", None)
if shape not in _SHAPES:                       # {"resolution","admission"} — else BLOCK (no_binding)
    return Decision(Outcome.BLOCK, "...declares no known shape...", escalation_source="no_binding")
...
if shape == "resolution":
    proposal = proposer if _is_resolver(proposer) else binding.proposal_for(proposer)
else:                                          # admission — honest identity-prepare
    proposal = binding.proposal_for(proposer)
return binding.submit(..., proposal=proposal)
```

**`resume` — shape-gated, not `hasattr`-gated.** Only resolution rails escalate, so the seam now
REFUSES a resume on an admission binding STRUCTURALLY:

```python
if binding is None or getattr(binding, "shape", None) != "resolution":
    return Decision(Outcome.BLOCK,
                    f"resume not valid for tool {eff.tool!r} (only resolution rails escalate)",
                    escalation_source="no_binding")
```

`NO-ESCALATE-V0` for egress + supabase is now a SEAM-LEVEL guarantee, not merely an absent method.

**Face 2 (verifier).** No code MOVES — the bindings already mint a per-effect verifier (admission)
or read `env.verifier` (resolution). The CONTRACT is made honest (the Protocol docstring states the
verifier is binding-determined and correlates with shape) and a test (§6.8) gates it.

## 3. Per-rail preservation evidence (verdict-for-verdict, goldens untouched)

Through the RESHAPED seam (`tests/test_seam_reshape.py`):

| Rail (shape) | corpus through `intercept` | result |
| --- | --- | --- |
| merge (resolution) | RESOLVED→ALLOW (#7), contained→BLOCK (#99), cardinality≥2→ESCALATE ([7,8]), resume(choice=7)→ALLOW | identical |
| egress (admission) | `api.allowed.test:443`→ALLOW; `evil.test:443` / `:22` / raw-IP→BLOCK; malformed→BLOCK | identical |
| supabase (admission) | `staging.analytics_events` insert→ALLOW; delete (off-mandate)→BLOCK; `prod.users` insert→BLOCK; malformed→BLOCK | identical |

The committed goldens were **neither regenerated nor extended** — `git status --short tests/_golden/`
is empty. (Those goldens are computed through rail-core entry points — `GitHubPlugin().resolve`,
`EgressBroker.admit` — so they never exercise the seam; seam-level preservation is therefore proven
here, AND by the unchanged green `test_egress_binding` / `test_supabase_binding` / `test_langgraph_adapter`
suites which all route through `intercept`/`resume`.) Full suite: **475 passed, 6 skipped** (was 463+6;
+12 from this file; 6 skips unchanged — langgraph/privilege/LLM).

## 4. SHAPE-COMPLETENESS + RESUME-SHAPE-GATED evidence

- `test_all_bindings_declare_shape` — merge=`resolution`, egress=`admission`, supabase=`admission`,
  on both the instances and the classes.
- `test_unknown_shape_fails_closed` (shape `"frobnicate"`) + `test_absent_shape_fails_closed`
  (no `shape` attr) → BLOCK (`no_binding`, "no known shape"), before `submit`.
- `test_resume_refused_on_admission_binding` — `interceptor.resume(...)` on an egress effect → BLOCK
  at the seam (`escalation_source="no_binding"`, cause "only resolution rails escalate"); no binding
  code reached.

## 5. FACE-2 evidence

- `test_admission_independent_of_env_verifier` — with `interceptor.env` set to an **all-attribute
  poison** (any read raises), egress + supabase still produce correct ALLOW/BLOCK (they mint their
  own per-effect verifier and never touch `env`).
- `test_merge_depends_on_env_verifier` — the contrapositive: with `env.verifier` poisoned, merge
  does NOT reach its ALLOW (fails closed to BLOCK). The dependency is rail-SHAPED — exactly what the
  reshape makes honest.

## 6. Blast radius (every renamed site)

- `integrations/effect_gateway/seam.py` — `_SHAPES`; Protocol `shape` + `proposal_for` + `submit`
  kwarg; `intercept` shape-routing; shape-gated `resume`; docstrings (face-2 honest).
- `integrations/effect_gateway/rails_github.py` — `shape="resolution"`; `resolver_for→proposal_for`;
  `submit(..., resolver→proposal)` (body `resolve_task_mandate(..., resolver=proposal)`).
- `integrations/effect_gateway/rails_egress.py` — `shape="admission"`; `resolver_for→proposal_for`;
  `submit` kwarg; module docstring.
- `integrations/effect_gateway/rails_supabase.py` — `shape="admission"`; `resolver_for→proposal_for`;
  `submit` kwarg; module docstring.
- `tests/test_egress_binding.py` / `tests/test_supabase_binding.py` — `SEAM_SHA256` → new sha;
  `test_*_seam_byte_identical` → `test_*_seam_pinned` (post-reshape wording).
- `tests/test_seam_reshape.py` — NEW (the acceptance file).

The LangGraph adapter (`integrations/langgraph/guarded_tool.py`) is UNTOUCHED — it calls the seam's
public `intercept`/`resume`, never the renamed Protocol hook, so the rename does not reach it.

## 7. Register update

`SEAM-SHAPE-OVERFIT` moved `[confirmed, 2 votes]` → **`[resolved by reshape @ 653afde9]`**. The seam
now declares two rail families, the prepare hook is honestly named (`proposal_for`), the verifier is
binding-determined, and `resume` is shape-gated. `SEAM-EFFECT-PHASE` is **untouched** (still
`[open, watch]`, one vote — it waits for a second capability-issuing rail, out of scope here).

## 8. Residue / surprises

- **Three different "resolver" meanings; only ONE renamed.** The rename had to distinguish the seam
  Protocol's `resolver`/`resolver_for` (renamed) from the RAIL-CORE `resolve_task_mandate(...,
  resolver=...)` kwarg (unchanged — it is internal to merge's `submit`/`resume`) and from egress's
  `EgressBinding.__init__(resolver=...)` DNS resolver (unchanged). Renaming only the seam-contract
  hook, and leaving the other two, is what keeps every verdict identical. This is the one place the
  blast-radius grep over-reports: most `resolver=` hits in `tests/` are the rail-core kwarg, not the
  seam contract.
- **No drift from the unpushed reports.** Re-confirming egress + supabase against the local files
  (§1) surfaced nothing new — both bindings already used a per-effect verifier and ignored
  `world`/`env`/`proposal`, exactly as their reports claimed. The reshape only made the contract say
  out loud what the bends already did.
- **The golden corpus does not touch the seam.** `rail_verdicts.json` is computed through rail-core
  entry points, so "goldens unchanged" is necessary but not sufficient evidence; the seam-level
  preservation is carried by `test_seam_reshape.py` + the green binding suites. Recorded so the
  next reader does not mistake an untouched golden for seam coverage.

*The abstraction was taught by the effect that didn't fit — and only reshaped once a second effect
agreed.*
