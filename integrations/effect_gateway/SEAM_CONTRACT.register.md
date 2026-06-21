# SEAM_CONTRACT — register of findings against the seam contract

The seam (`seam.py`) is the orchestrator-agnostic control-plane primitive. This register records
where its `RailBinding` contract over-fits a particular rail SHAPE, so the generalization is
modeled-before-promoted (a finding is opened by the rail that doesn't fit, and closed only when a
second instance of the same shape votes to reshape the seam).

---

## SEAM-SHAPE-OVERFIT  `[resolved by reshape @ 653afde9]`

**Raised by:** `EgressBinding` (`rails_egress.py`) — the seam's first ADMISSION rail
(EGRESS_BINDING.md). **Confirmed by:** `SupabaseBinding` (`rails_supabase.py`) — the seam's second,
structurally-independent ADMISSION rail (SUPABASE_BINDING.md §2). **Resolved by:** the seam reshape
(SEAM_RESHAPE.md) — the first deliberate edit to `seam.py` (sha `8761fe98…` → `653afde9…`).

**RESOLVED @ 653afde9 (SEAM_RESHAPE.md).** The seam now declares `shape ∈ {resolution, admission}`
and routes by it; the prepare hook is honestly named (`resolver_for → proposal_for` — a Role-B
resolver for resolution rails, the self-describing effect for admission rails); the `submit` kwarg
is `proposal`; the verifier is binding-determined (resolution reads `env.verifier`, admission mints
a per-effect verifier — face 2 made honest in the contract); and `resume` is shape-gated (the seam
REFUSES a resume on an admission binding structurally — NO-ESCALATE-V0 is now seam-level). All THREE
known-good rails (merge=resolution, egress+supabase=admission) reproduced verdict-for-verdict against
committed goldens (NOT regenerated, NOT extended); K0 intact; full suite 475 passed / 6 skipped.
Evidence: `tests/test_seam_reshape.py` (12 tests). The text below is the original finding, kept for
the record.

---

**The over-fit.** The `RailBinding` Protocol assumes the RESOLUTION shape — "pick one owned
candidate out of a `world`, then authorize the bound effect":

- `resolver_for(proposal) -> Role-B Resolver` assumes the proposal coerces into a candidate-picker.
- `submit(..., resolver, world)` assumes a candidate `world` to clamp against.
- `Outcome.ESCALATE` + `resume(...)` assume a human pause to disambiguate cardinality ≥ 2.

Egress — the first effect that does NOT fit — is self-describing `(host, port, protocol)`, admitted
or denied directly. Against that shape: `resolver_for` is vestigial, the `resolver`/`world` params
are ignored, admission is binary, and there is no resume. The binding BENDS (records the vestigial
hooks, reads the destination from `eff.args`, ships no resume) and keeps the seam byte-identical
(sha256 `8761fe98…`, K0 intact).

A second face of the same over-fit: the seam assumes ONE `env.verifier` per interceptor (merge uses
it). Egress's kernel policy is effect-scoped, so the binding mints through a PER-EFFECT verifier
(`broker_core.mint_token`). The seam's "one verifier" is itself a resolution-shape assumption.

**The deferred generalization.** Promote `resolver_for → proposal_for` (returns a Role-B resolver
for resolution rails, a self-describing effect for admission rails), OR have a binding DECLARE
`shape ∈ {resolution, admission}` and let the seam route accordingly. This is the strictly larger
change the bend points to.

**Promotion gate (model-before-promote) — CROSSED.** Was DEFERRED until a SECOND admission rail or
the OpenAI Agents SDK adapter independently confirmed the over-fit. `SupabaseBinding` is that second
instance: a credential-broker db-write rail, structurally independent of egress (different effect
type, different door class, different downstream PEP), and it confirms BOTH faces — face 1 (`DbEffect`
self-describing, no candidate set, `resolver_for` vestigial) and face 2 (`DbBrokerCore._verifier_for`
mints a per-effect verifier, not the shared `env.verifier`). Two votes, not one — the schedule's
lifecycle lesson (a flat abstraction over-fit to its first instance, corrected by the second)
applied to the seam.

**Next step (NOT performed here).** The reshape is the FIRST deliberate edit to `seam.py`, its OWN
human-gated spec: `resolver_for → proposal_for` (returns a Role-B resolver for resolution rails, a
self-describing effect for admission rails) OR a `shape ∈ {resolution, admission}` declaration (face
1); and a per-effect-verifier-aware `env` or binding-supplied verifier (face 2). It must preserve all
THREE known-good rails verdict-for-verdict against committed goldens (merge=resolution,
egress+supabase=admission) — the schedule-promotion discipline applied to the seam.

*The abstraction is taught by the effect that doesn't fit.*

**Evidence:** `tests/test_egress_binding.py` (22 tests) + `tests/test_supabase_binding.py` (24
tests), all green; EGRESS_BINDING.md §1/§7/§8; SUPABASE_BINDING.md §1/§2/§7.

---

## SEAM-EFFECT-PHASE  `[open, watch]`

**Raised by:** `SupabaseBinding` (`rails_supabase.py`) — the seam's first CAPABILITY-ISSUING door
(SUPABASE_BINDING.md §4/§6).

**The over-fit.** The seam's `Outcome.ALLOW` conflates two different things:

- **effect CONCLUDED** — merge posts a Check Run, egress admits the connection inline. The effect is
  done when ALLOW returns.
- **capability ISSUED** — supabase mints a scoped ES256 JWT. The effect (the DB write) happens LATER,
  performed by the holder and enforced at a downstream PEP (`resource_sim.SupabaseGateway` / a real
  PostgREST). ALLOW means "a credential was minted", not "the write happened".

A consequence surfaced under test (NO-FAKE): the resource PEP binds the capability at **role
granularity** (`role → GRANT`), NOT at the finer `signet_effect_hash` the JWT carries. So op-class
escalation (read JWT → delete) and cross-schema (staging → prod) ARE rejected at the resource, but a
same-role-class substitution (rw insert → rw delete on the same table) is NOT — the effect_hash is
bound at MINT (Bind / consume-once) and **advisory at the resource PEP in v0**. The egress Bind
defense is therefore PROMOTED only `[designed]→[partially proven]` on this rail: proven at role
granularity (the door issues an effect-scoped credential the resource independently enforces), not at
effect_hash granularity.

**The deferred generalization.** Should `Decision` carry an explicit capability handle (instead of
overloading `check_ref`) AND an out-of-band-enforcement marker (so a reader can tell "enforced
inline" from "enforced later at a downstream PEP")? This is the PDP/capability/PEP triad with the
capability finally load-bearing.

**Promotion gate (model-before-promote).** DEFERRED until a SECOND capability-issuing door (e.g. a
signing / payment co-signer rail) independently votes. One instance is a data point. Until then v0 is
unblocked (the JWT rides in `receipt.payment_ref` / `Decision.check_ref`) and the gap is recorded
executably — do NOT act.

**Evidence:** `tests/test_supabase_binding.py::test_db_effect_key_reachable` (what IS enforced) +
`::test_db_effect_hash_advisory_at_resource_v0` (the gap, asserted); SUPABASE_BINDING.md §4/§6/§8.
