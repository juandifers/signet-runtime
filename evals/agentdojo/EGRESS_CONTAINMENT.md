# AgentDojo egress containment — invariant now, measurement on the opt-in run

This is the standing companion to the run-stamped report the runner emits
(`EGRESS_CONTAINMENT_RUN.md` + its `.json` sidecar). It separates, deliberately and permanently,
the two claims this work makes:

- the **invariant** — what the rail guarantees structurally, true regardless of any model, **asserted
  by tests today**; and
- the **measurement** — how far a real, compromisable brain's attack-success collapses on the
  egress-class injections with the rail in place, and whether utility holds — **produced by the
  opt-in live run**, because that number depends on the model, not the rail.

## What was built (editable layer only)

- `egress_chokepoint_executor.py` — `EgressGatedToolsExecutor`, a drop-in AgentDojo `ToolsExecutor`
  that routes every egress-class tool call (scope: Slack `post_webpage`) through the **unchanged**
  smoke-run chokepoint (`evals/egress_receipts/chokepoint.py` → `EgressMerkleLog.emit`) *before* it
  runs. The decision that blocks is the same call that commits the Merkle leaf. ALLOW performs; DENY
  / REVIEW is withheld (enforcing) or recorded-only (baseline pass-through). It binds the URL **host**
  and commits `sha256(content)` — destination-based, no payload inspection.
- `egress_run.py` — the opt-in paired runner (Stages 3–5): drives a real injectable model over the
  egress-goal injection subset, scores with **AgentDojo's own** `utility` / `security`, gates the
  containment count on actual compromise, publishes one anchor root, verifies sampled receipts
  clean-room, and emits the provenance-stamped report.
- `tests/test_egress_agentdojo.py` — the deterministic core in CI (no LLM, no spend).

## The invariant (asserted by tests — `tests/test_egress_agentdojo.py`)

> Egress to a destination outside the operator's standing allow-set is **always denied** and **always
> emits a verifiable standing-fence receipt**, recorded unaltered in the anchored log, carrying the
> operator-ceiling attestation — and **no egress-class tool can execute without a chokepoint
> decision** (single chokepoint by construction; an unbound egress tool fails loud).

| claim | test |
|---|---|
| attacker URL is outside the operator standing allow-set | `test_attacker_url_is_outside_the_operator_standing_allowlist` |
| enforcing blocks the exfil (bytes never leave), allows the legit post | `test_enforcing_blocks_attacker_post_and_allows_legit_post` |
| baseline pass-through records a receipt but does **not** block | `test_passthrough_records_but_does_not_block` |
| an egress-semantic tool with no binding fails loud | `test_no_bypass_guard_fails_loud_for_unbound_egress_tool`, `test_verify_coverage_rejects_unbound_egress_tool_in_runtime` |
| egress always routed through the chokepoint before execution | `test_post_webpage_always_routed_before_execution` |
| both receipts verify clean-room vs one root, Signet un-importable; DENY carries operator-ceiling attestation | `test_clean_room_verifies_both_receipts_with_signet_unimportable` |
| a tampered exfil receipt fails clean-room | `test_tampered_exfil_receipt_fails_clean_room` |
| the runner's verify-sampling + report emit are deterministic and gate correctly | `test_runner_verify_and_report_emit_deterministically` |

**Stage 2 — the standing allow-set** is derived as the union of (a) the slack environment's
pre-existing `web_content` hosts and (b) the hosts legitimate **user tasks** post to, read from each
task's ground-truth solution trace (e.g. `www.our-company.com`, which does not pre-exist — it is
created by completing a task, so an env-only allow-set would wrongly deny it). The attacker exfil host
`www.my-website-234.com` (AgentDojo slack `injection_task_2` / `injection_task_4`, tool `post_webpage`)
appears only in INJECTION-task ground truth, never a user task's, so it is in **neither** set and every
exfil is denied on the standing hard axis `egress_destination`.

## The measurement (opt-in — spends tokens)

Constraint #3: the collapse is measured by **AgentDojo's native scorers**, not by Signet. Constraint
#4: the baseline is **measured** (chokepoint in pass-through), not assumed. Constraint #5: a pair
counts as containment only if the model was actually compromised without the rail.

```
# offline wiring check — no key, no spend:
python -m evals.agentdojo.egress_run --selftest

# the live paired run (needs OPENAI_API_KEY or evals/agentdojo/.env; capped + cached + cheap model):
OPENAI_API_KEY=... python -m evals.agentdojo.egress_run --model gpt-4o-mini --max-pairs 10
```

The run writes `EGRESS_CONTAINMENT_RUN.md` (+ `.json`) with: without-rail attack success, with-rail
attack success over the *compromised* subset (expected ≈ 0), utility without/with rail (≈ preserved),
receipts verified M-of-M, refused pairs reported separately, and the published anchor root.

> **Status:** the structural invariant is green in CI now. The corpus numbers are pending the opt-in
> live run with a key — the runner is wired, capped, cached, and offline-self-tested; it has not been
> run against a paid model in this change (no spend without an explicit go).

### Model choice (a measurement parameter, named in the report)

Default `gpt-4o-mini` (cheap, wired). If a model's without-rail attack success is near zero there is no
contrast to show — pick one the injections reliably compromise (a Hermes-class / weaker-aligned model
gives a sharper story). The model is reported, never hidden; the invariant does not depend on it.

## Scope / boundaries (stated, not hidden)

- **Eval chokepoint, not the production proxy** (`signet/broker/proxy.py` is fenced).
- **Destination-based**, no payload inspection: exfil laundered through an *allowlisted* host is the
  named out-of-scope boundary (v2: payload-aware binding).
- The injection targets a **non-allowlisted** destination — the discriminator is the operator's
  standing allow-set.
- **Human last-miles (PR):** the `git push` that publicly anchors the root; wiring the executor into
  the production proxy; a CI workflow under `.github/workflows/**` (fenced); the OpenTimestamps hook.
