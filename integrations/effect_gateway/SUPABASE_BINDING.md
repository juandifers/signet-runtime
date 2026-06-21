# SUPABASE_BINDING — the seam's second ADMISSION rail (the deciding vote)

`integrations/effect_gateway/rails_supabase.py` (`SupabaseBinding`) adapts the EXISTING Supabase
credential-broker pipeline (`signet/rails/supabase/*` + `signet/broker/*`) to the
orchestrator-agnostic seam (`integrations/effect_gateway/seam.py`). Same `signet_guarded_tool`, a
THIRD rail, a credential-broker door (the broker mints a scoped ES256 JWT; the agent never holds the
signing key). The seam is BYTE-IDENTICAL; the binding bends to the contract.

Deliverable for the spec §4. Acceptance lives in `tests/test_supabase_binding.py` (24 tests).

---

## 1. The bend, concretely

The seam's `RailBinding` is RESOLUTION-shaped: `resolver_for(proposal) -> Role-B Resolver`, and
`submit(..., resolver, world)` assumes the proposal is coerced into a candidate-picker that
`resolve_task_mandate` consumes over a candidate `world`. Supabase — like egress — is an ADMISSION
rail: the operation is self-describing `(database, schema, table, op, predicate)`, admitted or
denied directly, with no candidate set and no resume. The binding bends three seam assumptions and
keeps the seam unchanged:

| Seam assumption (resolution shape) | Supabase (admission) reality |
| --- | --- |
| `resolver_for(proposal)` returns a candidate-picker | VESTIGIAL — returns the proposal unchanged so the seam's `_is_resolver`/`resolver_for` plumbing is satisfied |
| `submit(..., resolver, world)` picks from `world` | `resolver`, `world`, `env`, `bridge` are IGNORED — the operation is read from `eff.args` |
| ESCALATE → human pause → `resume` | NO `resume` method; admission is binary. A seam `resume` on supabase fails closed to BLOCK (NO-ESCALATE-V0) |

The `submit` admission sequence mirrors `DbBrokerCore.mint_token` + the broker server's authorize:

```python
effect = self._effect_from_args(eff.args)                       # {database,schema,table,op,predicate}
decision, token, req, verifier = self._broker.mint_token(effect, task_id, agent_id)  # PER-EFFECT verifier
if not decision.approved or token is None: BLOCK(kernel_blocked)
authorizer = SupabaseAuthorizer(verifier, ..., minter, ttl, ...)
auth = authorizer.authorize(token, req)                         # Bind+Freshness+Policy+Door (legacy hooks)
ALLOW(jwt=auth.payment_ref) if auth.executed else BLOCK(auth.reason)
```

**The seam diff is EMPTY.** `seam.py` sha256 is unchanged (`test_db_seam_byte_identical`, pinned
`8761fe98…`).

## 2. THE BALLOT — two independent admission rails now confirm BOTH over-fit faces

`SEAM-SHAPE-OVERFIT` was raised by egress with ONE vote. Supabase casts the SECOND vote on each
face, INDEPENDENTLY — different effect type, different door class (inline byte-splice vs. a minted
ES256 credential), different downstream PEP. Both confirm:

| Face | Prediction | Supabase evidence (file:line) | Vote |
| --- | --- | --- | --- |
| **1 — proposal shape** (`resolver_for` over-fit) | the effect is self-describing; there is NO candidate set → admission, `resolver_for` vestigial | `rails_supabase.py:78` (`resolver_for` returns the proposal unchanged); `effect.py:18` (`DbEffect` is a frozen self-describing 5-tuple); `submit` ignores `resolver`/`world` (`rails_supabase.py:88`) | 2/2 ✓ |
| **2 — policy scope** (`env.verifier` over-fit) | the kernel policy is PER-EFFECT, not one shared `env.verifier` | `chain_adapter.py:76` (`DbBrokerCore._verifier_for(effect)` builds a Verifier with `allowed_recipients=[effect.target()]`, `allowed_actions=["db.<op>"]`); the binding mints through it (`rails_supabase.py:100`), `env` accepted-but-unused | 2/2 ✓ |

Plainly: **two structurally-independent admission rails (egress, supabase) confirm BOTH faces.** The
seam reshape (`proposal_for` for face 1; a per-effect-verifier-aware `env` for face 2) is now
justified as the next deliberate, human-gated edit to `seam.py` (§7, §8). Model-before-promote is
satisfied: two votes, not one.

## 3. Outcome mapping

Every BLOCK cause traces to the `recheck` step (or kernel) that produced it; ALLOW = a scoped
capability was issued. `escalation_source` is the binding's label; `cause` is the verbatim
composition reason.

| Step (`SupabaseAuthorizer`) | Condition | Outcome | escalation_source | example cause |
| --- | --- | --- | --- | --- |
| (binding, pre-kernel) | malformed / missing / oob operation | BLOCK | `gate_contained` | `malformed or missing db operation …` |
| (binding, pre-kernel) | no frozen Role-A mandate | BLOCK | `gate_contained` | `no frozen task mandate (fail closed)` |
| kernel verify | decision not approved / no token | BLOCK | `kernel_blocked` | `Replay…` → `replay` |
| Bind (`recheck` step 1) | chain_hash ≠ recompute | BLOCK | `admission_denied` | `unbound-token` |
| Bind (`recheck` step 2) | cart effect ≠ context effect | BLOCK | `admission_denied` | `effect-context-mismatch` |
| MandateFreshness (`recheck`) | no-frozen / expired | BLOCK | `admission_denied` | `no-frozen-mandate` / `mandate-expired` |
| Policy (`effective_permits`) | op ∉ mandate ∩ standing | BLOCK | `admission_denied` | `out-of-mandate` / `out-of-standing-policy` |
| Door (`produce_capability`) | scoped ES256 JWT minted | ALLOW | `resolved` | `minted ES256 JWT role=signet_staging_rw ttl=60s for staging.analytics_events.insert` |

ALLOW means **a least-privilege, effect-bound, short-TTL capability (the JWT) was ISSUED** — NOT that
the write executed. The JWT rides in `receipt.payment_ref` and `Decision.check_ref`; the holder
performs the write later at the resource PEP (the §6 third face).

### ADMISSION-PARITY evidence (binding verdict == `effective_permits`, verdict-for-verdict)

Frozen mandate `staging.analytics_events {select,insert}`; standing `{staging.* all4; prod.* select}`:

```
operation                          binding  effective_permits  cause
staging.analytics_events.select    allow    ALLOW              minted ES256 JWT role=signet_staging_ro ttl=60
staging.analytics_events.insert    allow    ALLOW              minted ES256 JWT role=signet_staging_rw ttl=60
staging.analytics_events.delete    block    BLOCK              out-of-mandate
staging.analytics_events.update    block    BLOCK              out-of-mandate
staging.secrets.insert             block    BLOCK              out-of-mandate
prod.users.select                  block    BLOCK              out-of-mandate
prod.users.insert                  block    BLOCK              out-of-standing-policy
```

Asserted by `test_db_binding_parity` (corpus, `binding == effective_permits`).

## 4. EFFECT-KEY-REACHABLE evidence — and the honest gap (NO-FAKE)

The spec §6.8 predicted a JWT minted for `(orders, insert)`, presented for `(orders, delete)`, would
be REJECTED "on effect-hash mismatch". **Implementation revealed this is NOT how the resource binds**
— and per NO-FAKE this is reported, not patched to force the predicted green.

What is TRUE (confirmed empirically — `roles.role_permits`, and `test_db_effect_key_reachable`):

- The minted JWT is scoped to a RESTRICTED role chosen by the effect at mint
  (`role_for_effect`: `op_class` → `signet_<schema>_{ro|rw}`). The resource (`SupabaseGateway`)
  enforces **role → GRANT**, independent of the broker (mint is separated from use — a real
  credential-broker door).
- A **read** JWT (`select` → `signet_staging_ro`) presented for `delete` → **REJECTED** (`no GRANT`).
  Op-class escalation is caught at the resource.
- A **staging** JWT presented for `prod.users` → **REJECTED** (`no GRANT on prod.users`). Cross-schema
  is caught at the resource.

What is the GAP (`test_db_effect_hash_advisory_at_resource_v0`, asserted, not hidden):

- The resource binds at **ROLE granularity**, NOT at the finer `signet_effect_hash`. So a `rw` JWT
  minted for `insert` IS accepted for `delete` on the same table — both map to `signet_staging_rw`.
  The `signet_effect_hash` is bound at **MINT** (Bind recheck + consume-once on `chain_hash`) but is
  **NOT re-checked at the resource PEP in v0**. The JWT carries it; the resource ignores it.

**Therefore the egress Bind.recheck defense is PROMOTED `[designed]→[partially proven]`, NOT fully
proven.** Proven: the door issues a credential whose ROLE scope is fixed by the requested effect, and
the resource refuses any use outside that scope — with no broker in the loop (the residue egress
could only assert by direct injection is here reached through the real door, *at role granularity*).
Not proven: the finer per-operation `signet_effect_hash` binding is load-bearing at the resource —
it is advisory there in v0. WHY the proven part holds: the agent cannot obtain a credential except by
passing Bind + Freshness + Policy at the broker for the exact requested effect, and it cannot re-mint
(no signing key); the credential it holds is role-scoped and the resource enforces that scope
independently. This is recorded as the third face (`SEAM-EFFECT-PHASE`, §6 / register).

## 5. Seam-hash + kernel-hash

- `seam.py` sha256 `8761fe982239774350387cc5b58b0fcdeef6452b02fa8068ae28268ad05b879b` — unchanged
  (`test_db_seam_byte_identical`). SEAM-BYTE-IDENTICAL.
- `kernel_edit_check()["edits"] == 0` — the 10 kernel files byte-identical
  (`test_db_kernel_baseline_unchanged`). K0.

## 6. Third-face observation — capability issuance vs. effect conclusion `[open, watch]`

The seam's ALLOW conflates "the effect CONCLUDED" (merge Check Run, egress inline admit) with "a
CAPABILITY was ISSUED" (supabase's scoped JWT — the write happens LATER, at the resource PEP). v0 is
unblocked: the JWT handle rides in `receipt.payment_ref` and `Decision.check_ref`, and the §4 gap is
recorded executably. Does this strain the `Decision` model? Mildly — `check_ref` is doing
double-duty (a Check Run id for merge, an inline ref for egress, a bearer JWT for supabase), and
there is no marker distinguishing "enforced inline" from "enforced out-of-band at a downstream PEP".
A THIRD capability-issuing rail (a signing/payment co-signer door) would be the vote on whether
`Decision` should carry an explicit capability slot + an out-of-band-enforcement marker. **Recorded,
NOT acted on** (`SEAM-EFFECT-PHASE` in the register).

## 7. Seam-generalization readiness verdict

**PROMOTE the finding; DEFER the edit (the edit is its own human-gated spec).** With two independent
admission votes on each face, `SEAM-SHAPE-OVERFIT` is promoted `[open, 1 vote]` →
`[confirmed, 2 votes — reshape authorized]` in the register. The reshape itself — `resolver_for →
proposal_for` (face 1) and a per-effect-verifier-aware `env` (face 2) — is the FIRST deliberate edit
to `seam.py` and the NEXT, separate step (§8). It must preserve all THREE known-good rails
verdict-for-verdict against committed goldens (the schedule-promotion discipline applied to the
seam):

- **merge** (`rails_github.py`) — RESOLUTION: pick one owned candidate from a `world`, then authorize.
- **egress** (`rails_egress.py`) — ADMISSION: self-describing `(host,port,protocol)`, per-effect verifier.
- **supabase** (`rails_supabase.py`) — ADMISSION: self-describing `(db,schema,table,op)`, per-effect verifier.

Neither face FAILED to confirm, so the promote is not blocked. (The `SEAM-EFFECT-PHASE` third face
stays open and does NOT gate this reshape — it is a separate, single-vote finding awaiting a third
capability-issuing rail.)

## 8. Residue / surprises

- **Effect_hash advisory at the resource PEP (§4).** The biggest surprise: the spec's predicted
  "REJECTED on effect-hash mismatch" does not hold for a same-role-class op substitution, because the
  resource binds at role granularity. Surfaced as an executable finding
  (`test_db_effect_hash_advisory_at_resource_v0`) and the third face, not patched.
- **Per-effect verifier, not `env.verifier`** (face 2). Same deviation egress recorded; here it is a
  confirming vote, not a one-off. The binding mints through `DbBrokerCore.mint_token`; `env` is
  accepted for signature parity and unused.
- **Bind.recheck (steps 1/2) is not reachable through the binding's own request construction.** The
  binding builds a self-consistent chain (Cart and RuntimeContext from the same `eff.args`), so
  `unbound-token` / `effect-context-mismatch` cannot arise from `eff.args` alone — identical to the
  egress residue. The gates are still LIVE in the path the binding drives;
  `test_db_unbound_token_blocked` / `test_db_effect_context_mismatch_blocked` inject the divergence
  directly against the SAME `SupabaseAuthorizer` composition and assert the block.
- **The frozen Role-A mandate is the task selector.** `submit` reads `task_id` from the seam's frozen
  `mandate` (`mandate.task_id`); the authorizer's recheck re-fetches it from the provider. So the
  seam mandate is not fully ignored (its `task_id` is load-bearing), unlike `world`/`resolver`.
- **ALLOW receipt `payment_status="capability_issued"`** (vs egress's `"admitted"`) — names the
  capability-issuance shape (§6) precisely so the receipt log records WHAT kind of ALLOW it was.
