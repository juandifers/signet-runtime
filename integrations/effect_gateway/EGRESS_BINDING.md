# EGRESS_BINDING — the seam's first ADMISSION rail

`integrations/effect_gateway/rails_egress.py` (`EgressBinding`) adapts the EXISTING egress
admission pipeline (`signet/rails/egress/*` + `signet/broker/proxy.py:EgressBroker`) to the
orchestrator-agnostic seam (`integrations/effect_gateway/seam.py`). Same `signet_guarded_tool`,
new rail SHAPE, new door class. The seam is BYTE-IDENTICAL; the binding bends to the contract.

Deliverable for the spec §4. Acceptance lives in `tests/test_egress_binding.py` (22 tests).

---

## 1. The bend, concretely

The seam's `RailBinding` is RESOLUTION-shaped: `resolver_for(proposal) -> Role-B Resolver`, and
`submit(..., resolver)` assumes the proposal is coerced into a candidate-picker that
`resolve_task_mandate` consumes over a candidate `world`. Egress is an ADMISSION rail — the effect
is self-describing `(host, port, protocol)`, admitted or denied directly, with no candidate set and
no resume. The binding bends three seam assumptions and keeps the seam unchanged:

| Seam assumption (resolution shape) | Egress (admission) reality |
| --- | --- |
| `resolver_for(proposal)` returns a candidate-picker | VESTIGIAL — returns the proposal unchanged so `_is_resolver`/`resolver_for` plumbing is satisfied |
| `submit(..., resolver, world)` picks from `world` | `resolver`, `world`, `env`, `bridge` are IGNORED — the destination is read from `eff.args` |
| ESCALATE → human pause → `resume` | NO `resume` method; admission is binary. A seam `resume` on egress fails closed to BLOCK (NO-ESCALATE-V0) |

The `submit` admission sequence mirrors `EgressBroker.admit` (which itself mirrors
`signet_harness.decide`):

```python
effect = self._effect_from_args(eff.args)                       # {host,port,protocol} OR {url}
decision, token, req, verifier = self._broker.mint_token(effect, task_id, agent_id)  # kernel
authorizer = EgressAuthorizer(verifier, ..., mandate_provider, standing_policy, resolver)
auth = authorizer.authorize(token, req)                         # Bind+Freshness+Policy+Door @ ADMIT
ALLOW if auth.executed else BLOCK(auth.reason)
```

**The seam diff is EMPTY.** `seam.py` sha256 is unchanged (test `test_egress_seam_byte_identical`,
pinned `8761fe98…`).

A second, quieter over-fit (recorded in §8): the spec's idealized snippet used
`env.verifier.evaluate(req)`. Egress's kernel policy is EFFECT-SCOPED (`allowed_recipients ==
[this destination]`), so it cannot share the seam's single `env.verifier` the way merge does. The
binding mints through the egress core's PER-EFFECT verifier (`broker_core.mint_token`) instead; the
`env` param is accepted for signature parity and left unused.

## 2. Outcome mapping

Every BLOCK cause traces to the composition step that produced it. `escalation_source` is the
binding's label; `cause` is the verbatim composition reason (receipts + tests read it).

| Composition step | Condition | Outcome | escalation_source | example cause |
| --- | --- | --- | --- | --- |
| (binding, pre-kernel) | malformed / missing destination | BLOCK | `gate_contained` | `malformed or missing egress destination …` |
| (binding, pre-kernel) | no frozen Role-A mandate | BLOCK | `gate_contained` | `no frozen task mandate (fail closed)` |
| kernel verify | decision not approved / no token | BLOCK | `kernel_blocked` | `Replay…` → `replay` |
| Bind (`EffectKeyOneShot.recheck`) | TOCTOU: ctx dest ≠ signed Cart | BLOCK | `admission_denied` | `effect-context-mismatch` / `unbound-token` |
| MandateFreshness | no-frozen / expired | BLOCK | `admission_denied` | `no-frozen-mandate` / `mandate-expired` |
| Policy (`PatternAllowlist.decide`) | off-standing / off-mandate / raw-IP evasion | BLOCK | `admission_denied` | `out-of-standing-policy` / `out-of-mandate-destination` |
| Door (`NetworkSolePath.enforce`) | admit | ALLOW | `resolved` | `admit egress http_connect to api.allowed.test:443 (chain …)` |

Each decision appends exactly ONE signed, hash-chained receipt to the seam's `ReceiptLog` (A6),
the same contract the merge binding honors.

## 3. ADMISSION-PARITY evidence

The binding adds NO gate: its verdict equals the existing `effective_admits` (mandate ∩ standing)
decision, verdict-for-verdict, over a destination corpus (frozen mandate `api.allowed.test:443`;
standing `{api.allowed.test:80,443,22; *.allowed.test:443; evil.test:443}`):

```
destination                  binding    effective_admits   cause
api.allowed.test:443         allow      ALLOW              admit egress http_connect to api.allowed.test:443
evil.test:443                block      BLOCK              out-of-mandate-destination
api.allowed.test:22          block      BLOCK              out-of-mandate-destination
notlisted.test:443           block      BLOCK              out-of-standing-policy
sub.allowed.test:443         block      BLOCK              out-of-mandate-destination
127.0.0.1:9443               block      BLOCK              out-of-mandate-destination   (raw-IP evasion)
```

Asserted by `test_egress_binding_parity` (corpus, `binding == effective_admits`).

## 4. A1 + MONOTONIC evidence

- **A1-CONTAINMENT** (`test_egress_a1_attacker_host_contained`): the proposal is data. An
  attacker-named host (`evil.test`, even passed as the raw `proposer`) is BLOCKED because it is off
  the frozen mandate; the legit destination still passes. The proposer never decides.
- **MONOTONIC-NARROWING** (`test_egress_off_mandate_blocked`, `…_forbidden_port…`): `evil.test:443`
  and `api.allowed.test:22` are BOTH permitted by STANDING but absent from the FROZEN mandate →
  BLOCK. The mandate can only tighten the standing ceiling.

## 5. Seam-hash + kernel-hash

- `seam.py` sha256 `8761fe982239774350387cc5b58b0fcdeef6452b02fa8068ae28268ad05b879b` — unchanged
  (`test_egress_seam_byte_identical`). SEAM-BYTE-IDENTICAL.
- `kernel_edit_check()["edits"] == 0` — the 10 kernel files byte-identical
  (`test_kernel_baseline_unchanged`). K0.

## 6. Rail-agnosticism of the LangGraph adapter

`signet_guarded_tool(ic, tool_name="fetch_url", id_arg="host")` over the egress interceptor yields
the SAME control flow it does for merge: ALLOW → `status="merged"` result, BLOCK → structured
refusal (`status="blocked"`). `test_egress_through_langgraph_guarded_tool` proves a LangGraph user
guards outbound calls with the unchanged adapter — the Floor-3 payoff. The adapter was NOT
special-cased for egress (`guarded_tool.py` untouched).

## 7. Seam-generalization readiness verdict

**WAIT — do not promote yet.** This admission rail confirms the over-fit is real (`resolver_for`
vestigial, `resolver`/`world` ignored, no resume), but model-before-promote requires a SECOND
admission instance before reshaping the seam. One new instance is a data point, not a pattern; the
schedule's own lifecycle lesson (a flat abstraction over-fit to its first instance) is exactly what
this defers. Promote `resolver_for → proposal_for` (or a `shape ∈ {resolution, admission}`
declaration) only after a second admission rail (db-write / send) or the OpenAI Agents SDK adapter
independently votes. Finding logged as `SEAM-SHAPE-OVERFIT [open]` in `SEAM_CONTRACT.register.md`.

## 8. Residue / surprises

- **Per-effect verifier, not `env.verifier`.** The biggest deviation from the idealized spec
  snippet. Egress's kernel policy is destination-scoped, so the binding mints through
  `broker_core.mint_token` (the real pipeline) rather than a shared `env.verifier`. This is a second
  face of the same shape over-fit — the seam assumed one verifier per interceptor; egress needs one
  per effect. Recorded, not patched.
- **Bind.recheck is not reachable through the binding's own request construction.** The binding
  builds a self-consistent chain (Cart and RuntimeContext from the same `eff.args`), so a TOCTOU
  divergence cannot arise from `eff.args` alone — this matches `chain_adapter.py`'s "self-consistent
  by construction" note. The Bind gate is still LIVE in the path the binding drives;
  `test_egress_toctou_chain_mismatch_blocked` injects the divergence directly against the SAME
  `EgressAuthorizer` composition the binding uses and asserts the block. Honest framing: the gate
  exists and fires; it just isn't expressible from the binding's argument surface.
- **The frozen Role-A mandate is the task selector.** `submit` reads `task_id` from the seam's
  frozen `mandate` (`mandate.task_id`); MandateFreshness then re-fetches it from the provider. So
  the seam mandate is not fully ignored (its `task_id` is load-bearing), unlike `world`/`resolver`.
- **Door is advisory (v0).** `NetworkSolePath(sole_path=False)` — the netns sole-path door is
  deferred pending a CAP_NET_ADMIN host (ONLY-DOOR-OR-DECLARE). The binding inherits that posture;
  it does not claim a boundary the composition does not hold.
