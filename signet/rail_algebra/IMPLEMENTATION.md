# Rail algebra — implementation report

How the merge and egress rails were refactored in place to COMPOSE three reusable strategy
interfaces (`Policy`, `Bind`, `Door`) instead of bespoke per-rail code. The 10 kernel files are
byte-identical (K0 PASS, 0 edits); `signet/sandbox/netns.py` and the broker privilege drop are
wrapped, not edited; every refactored rail reproduces the §0.3 golden corpus
(`tests/_golden/rail_verdicts.json`) verdict-for-verdict.

The algebra lives in `signet/rail_algebra/`:
- `types.py` — `Features`, `Verdict` (ALLOW/DENY/ESCALATE), `Capability`, `Lifecycle`/`Soundness`
  constants, `Effect | Blocked`, `Composition`, and `provenance_audit`.
- `policy.py` — `DeclarativeMembership`, `PatternAllowlist`, `Quantitative` (stub),
  `Content` / `AllowOnUntrustedContent`.
- `bind.py` — `EffectKeyOneShot`, `InlineCapability`, `MeteredLedger` (stub).
- `door.py` — `ExternalEnforcer`, `KeyholderBroker`, `NetworkSolePath`, `AdvisoryInline`.
- `payment.py` — the `payment_composition()` stub.

---

## 1. Per-rail decomposition

### merge = DeclarativeMembership × EffectKeyOneShot × ExternalEnforcer

The merge rail has its PDP and its PEP at **two different points in the flow**, so the composition
is assembled across two files:

- **Policy — `DeclarativeMembership`** at mandate resolution. `evals/github_railbridge/domain.py`
  gained `github_membership_policy(effective)`, which wraps the rail's SHARED evaluator
  (`evaluate_allowlist` / `evaluate_fence`) over the typed `PolicySpec`. The Role-B gate in
  `evals/github_railbridge/mandate.py::_resolve_via_role_b` now sources its two predicates from it:

  Before:
  ```python
  within_allowlist = lambda pr: domain.within_allowlist(domain._target(world.open_prs[pr]), world)
  within_fence     = lambda pr: not effective.is_fenced(world.open_prs[pr].files)
  ```
  After:
  ```python
  membership = github_membership_policy(effective)
  within_allowlist = lambda pr: membership.within_allowlist(membership.project(world, pr))
  within_fence     = lambda pr: membership.within_fence(membership.project(world, pr))
  ```
  Byte-identical results — the membership policy is a façade over the SAME evaluator, projecting
  `github_project(rec, effective)` (`repo`, `base`, `protected_path`, `in_scope`) and reading the
  allowlist conditions (`repo`, `base`) and fence conditions (`protected_path==False`,
  `in_scope==True`). `run_role_b_stages` still owns the order + fail-closed.

- **Bind — `EffectKeyOneShot`** and **Door — `ExternalEnforcer`** in
  `signet/authorizers/github_railbridge.py`. `GitHubRailBridge.__init__` now builds
  `self.bind = EffectKeyOneShot(recheck_fn=self._chain_bound)` and
  `self.door = ExternalEnforcer(perform=self._conclude_success, decline=self._conclude_failure)`.
  The two template hooks became wiring:

  Before (`produce_capability`):
  ```python
  check_run_id = self._rail.open_check(token.chain_hash, head_sha)
  try:
      ref = self._rail.conclude(check_run_id, recomputed, "success")
  except PermissionError as e:
      return AuthorizationResult(False, str(e), payment_ref=check_run_id, rail=self.rail)
  return AuthorizationResult(True, "Check Run concluded success; ...", payment_ref=ref, ...)
  ```
  After:
  ```python
  outcome = self.door.enforce(self._cap(token, req))
  if isinstance(outcome, Effect):
      return AuthorizationResult(True, "Check Run concluded success; ...", payment_ref=outcome.ref, ...)
  return AuthorizationResult(False, outcome.reason, payment_ref=self._last_check_ref, ...)
  ```
  `recheck_against_context` is now `if not self.bind.recheck(token, req): return False, <reason>`.
  The Door's soundness is `EXTERNAL`: the real PEP is the protected-branch ruleset waiting on the
  required Check Run; the enforcer concludes it.

### egress = PatternAllowlist × EffectKeyOneShot × NetworkSolePath

`signet/rails/egress/authorizer.py::EgressAuthorizer.__init__` now assembles a FULL `Composition`,
because the egress PDP and PEP coincide at the single inline-admission point:

```python
self.composition = Composition(
    policy=PatternAllowlist(name="egress", project_features=self._project_features),
    bind=EffectKeyOneShot(recheck_fn=self._chain_bound),
    door=NetworkSolePath(admit=self._admit, sole_path=False),   # v0: advisory (no netns)
    name="egress")
```

- `recheck_against_context` = `bind.recheck` (chain_hash bound + effect == signed Cart) → frozen-
  mandate lifecycle (`no-frozen-mandate` / `mandate-expired`) → `policy.decide(policy.project(...))`.
  `PatternAllowlist.decide` is pure boolean logic over the OWN ceiling/grant/trusted-resolution
  booleans the rail's `_project_features` computes, so the exact cause strings survive
  (`out-of-standing-policy`, `out-of-mandate-destination`, `within mandate ∩ policy`,
  `raw-ip matches a resolved allowlisted host`).

  Before:
  ```python
  if is_ip_literal(eff.host):
      ok = self._raw_ip_in_resolved_allowset(eff, mandate)
      return (True, "raw-ip ...") if ok else (False, "out-of-mandate-destination")
  return effective_admits(eff, mandate, self._standing)
  ```
  After:
  ```python
  verdict = self.composition.policy.decide(self.composition.policy.project(mandate, eff))
  return verdict.is_allow, verdict.reason
  ```
- `produce_capability` = `door.enforce` (NetworkSolePath wraps the inline admit; no bearer token).

### payment = Quantitative × MeteredLedger × KeyholderBroker (stub)

`payment.py::payment_composition()` names the otherwise-unexercised ends of all three axes. It has
no rail; constructing it proves the axes compose, but its Bind/Door raise if driven (the atomic
ledger and a live credential minter are named, not built).

---

## 2. Residue — what a general variant could NOT express cleanly

1. **The merge PDP and PEP sit at different points; egress's coincide.** Egress holds a whole
   `Composition` at one method; merge's `GitHubRailBridge` holds only the `bind`/`door` pair because
   its Policy fires UPSTREAM at mandate resolution (the Role-B gate). This is a real axis the sketch
   did not name: **where the PDP sits relative to the PEP**. It is honestly-bespoke per rail (a
   consequence of the AP2 open/closed-mandate split), not a missing variant — so the full merge
   composition is assembled at the resolve seam, and the authorizer carries the half it owns.

2. **The merge rail has more than one fence-evaluation seam.** Besides the Role-B gate (now routed
   through `DeclarativeMembership`), `GitHubDomain.within_fence` (target-level, protected-only) and
   `MergePolicy.is_fenced` (the deterministic `resolver=None` path) call the shared evaluator
   directly. They reduce to the same evaluator but were left calling it WITHOUT the façade — routing
   them too is mechanical and behavior-neutral, but each is a distinct seam and unifying all of them
   was out of the minimal-risk scope (NO-FAKE-EQUALITY: I did not insert glue to pretend they are
   one). `GitHubDomain.within_fence` is additionally a NARROWER fence than the gate's (protected
   path only, no `in_scope`) because the allow-scope is enforced separately at mandate close — so a
   single `DeclarativeMembership` configuration cannot reproduce both the gate fence and the target-
   level fence. The right fix is **(b) a finer axis** — the fence is not one predicate but a layered
   {universe ceiling, protected, allow-scope} stack evaluated at different lifecycle points — not a
   new variant.

3. **The egress `recheck` is two algebra roles in one template hook.** `recheck_against_context`
   carries BOTH `Bind.recheck` (TOCTOU) and `Policy.decide` (membership) plus the frozen-mandate
   lifecycle. The base `Authorizer` template exposes a single `recheck_against_context` hook, so the
   composition is invoked *inside* it rather than the template invoking Policy/Bind/Door directly.
   This is honestly-bespoke: bringing the template itself under the algebra (so `base.Authorizer`
   calls `policy.decide` / `bind.recheck` / `door.enforce` in order) is a clean follow-up but would
   touch `signet/authorizers/base.py`, which the spec scoped out.

4. **Bind.recheck returns `bool`, but the rails need a reason string.** The binding-field reason
   (`unbound-token` vs `effect-context-mismatch`) is rail telemetry re-derived on failure
   (`_bind_reason`). Not a missing variant — the algebra contract is the boolean gate; the label is
   the rail's, exactly as `role_b` carries its own `cause` strings.

5. **Egress is not a Role-B `register_rail` plugin.** The conformance battery
   (`evals/conformance/`) drives a set-valued Role-B resolver + `run_gate`; egress's PDP is inline
   admission, not resolution-with-cardinality. So "register_rail green for both rails" holds
   literally only for merge; egress's conformance is its unchanged authorizer-template contract +
   `provenance_audit`. Reported here rather than papered over with an egress shim.

---

## 3. Provenance

`provenance_audit(policy)` (`types.py`) is behavioral, not static: it takes the policy's own
`allow_witness()`, NEUTRALIZES every UNTRUSTED feature (`neutralize_untrusted`), and re-decides. If
the ALLOW survives, it rested only on OWN features (monotone); if neutralizing untrusted features
flips it away from ALLOW, the ALLOW depended on attacker-controlled data — a violation.

- `DeclarativeMembership` (merge): every fence/allowlist attr is OWN (the rail's load gate,
  `schema_violations`, already refuses an UNTRUSTED condition). `neutralize_untrusted` is the
  identity → ALLOW survives → `[]`.
- `PatternAllowlist` (egress): **the subtle one.** The agent-supplied destination host is genuinely
  attacker-controlled, but it must NOT permit. I split host identity into an UNTRUSTED
  `agent_host` string (carried for the audit, `NEUTRAL = ""`) and the OWN permitting booleans
  `in_standing` / `in_mandate` / `raw_ip_resolved_match` — the last computed by the proxy's TRUSTED
  resolver (`_raw_ip_in_resolved_allowset`), never the agent's. Neutralizing `agent_host` leaves the
  OWN booleans intact → the witness stays ALLOW → `[]`. This encodes the real property: the agent
  host only NARROWS; the trusted resolution + the operator ceiling PERMIT.
- `AllowOnUntrustedContent` (the negative fixture): returns ALLOW precisely because an UNTRUSTED
  `payload` matched a token. Neutralizing `payload` → DENY → flip → FLAGGED. This is what
  `test_provenance_monotonicity_catches_violation` asserts; `Content` (deny-on-match) is the correct
  twin and passes.

---

## 4. Placement + trust direction

The abstraction lives in `signet/rail_algebra/` (the trusted zone, per the §2 default). The decisive
property: **`signet/rail_algebra/` imports nothing from `signet.*` or `evals.*`** — it is a leaf in
the dependency graph. The general variants are SHAPES; every rail-specific backend is INJECTED:

- `DeclarativeMembership` takes `allowlist_fn` / `fence_fn` / `spec` / `project_attrs` — the merge
  wiring in `evals/github_railbridge/domain.py` injects `evaluate_allowlist` / `evaluate_fence`.
- `PatternAllowlist` takes `project_features` — the egress wiring injects the host matchers + the
  trusted resolver.
- `EffectKeyOneShot` takes `recheck_fn`; `ExternalEnforcer` takes `perform`/`decline`;
  `NetworkSolePath` takes `admit`.

So **no trusted module depends on editable rail code**: the merge authorizer
(`signet/authorizers/github_railbridge.py`) imports only `signet.rail_algebra` + `signet.chain`
(kernel); the merge Policy is wired on the EVAL side (`evals/...` importing `signet.rail_algebra` is
the normal eval→signet direction). The egress authorizer already lived in the broker/rails trust
zone and gains only a `signet.rail_algebra` import. Injection is the same discipline
`evals._rail_core.role_b` uses for its gate predicates: the framework owns the control flow; the
rail supplies the field-level content.

`signet/sandbox/netns.py` is untouched — `NetworkSolePath` WRAPS the broker proxy's admission and
declares `soundness = ADVISORY` in v0 (no netns), flipping to `SOLE_PATH` only under the netns
deployment it does not edit (ONLY-DOOR-OR-DECLARE).

---

## 5. What surprised me

- **The cleanest decomposition split host identity, not host matching.** The obvious guess was
  "host is untrusted, so the egress policy reads untrusted data." The honest model is that the agent
  host string is untrusted-and-narrowing while the OWN trusted-resolution boolean is what permits —
  two features, not one. Provenance-monotonicity only holds once they are separated, and that
  separation is exactly the raw-IP-evasion defense expressed as data.
- **The merge rail's fence is not a single predicate.** It is a layered stack (universe ceiling /
  protected / allow-scope) enforced at THREE lifecycle points (the Role-B gate, the deterministic
  `target_allowed`, `MergePolicy.is_fenced`), each a slightly different projection of the same
  evaluator. "One Policy per rail" undersells it — the Policy is per *decision point*, and the
  variant cleanly captured the gate but exposed the others as distinct seams (Residue #2).
- **`recheck` being the load-bearing hook made the authorizer template the real boundary, not the
  netns.** The Bind's freshness re-check (chain_hash bound + effect == Cart) is what actually
  contains a post-auth swap; the Door's soundness is mostly an honest label. The algebra made that
  ordering explicit where it was previously implicit in each rail's hand-written hook.
```
