# DESIGN — Execution-Enforcement Layer (north star)

Read this before designing any new domain adapter. It encodes the positioning
and the design constraints that keep us out of the crowded, commoditizing part
of the market and inside the defensible part.

## Thesis

We provide enforcement an agent **cannot route around** — because the rail
itself will not execute without our authorization — plus **independently
verifiable proof** of every allowed, blocked, or reviewed action.

The differentiator is **held-capability / bypass-resistance** and **anchored
receipts**, NOT tool-call interception or allow/block/review policy verdicts.
Those are already commoditizing (e.g. AEGIS, AgentTrust — both pre-execution
interceptors with policy verdicts; AEGIS even ships Ed25519-signed,
hash-chained audit). If we build "a better interception SDK with receipts," we
walk straight into them. The part those systems explicitly cannot do — AEGIS
itself disclaims defense against calls that bypass the SDK — is our wedge.

## Design principles (the adapter constitution)

**P1 — Bind the effect, not the tool.** Gate the canonical *side effect* (the
merged diff, the applied plan, the IAM change, the money movement), never the
obvious tool name. If the dangerous effect is reachable by another path, the
gate must sit on the effect or it is incomplete. Evidence: the Claude Code auto
-mode stress test found ~81% end-to-end false-negative rate because agents
reach effects via file edits the shell-oriented classifier never sees. Our own
AgentDojo run showed the same shape (a leak in the memo of an authorized
transfer passes a recipient/amount gate). Gate the effect surface, whole.

**P2 — Be the rail where you can; bridge to the hard rail where you can't.**
Two adapter archetypes, and every adapter must declare which it is:
- **Custodial enforcer** — we hold a capability the action requires (XRPL
  co-signature, sole credential custody, MPC key share). Bypass is structurally
  impossible. Use where we can actually hold it (payments/treasury).
- **Rail-bridge** — a hard rail already exists server-side (GitHub branch
  protection, CI required approvals, cloud IAM/policy-as-code, signed deploys).
  We convert policy into the token/approval that rail requires and feed it.
  Enforcement lives at the server-side rail, never at a client-side interposer.
Never ship a client-side wrapper as the *sole* gate — that is the AEGIS / Claude
Code failure mode (bypassable). A client-side gate may exist as defense-in-depth
or UX, but it is not the enforcement boundary.

**P3 — Deterministic capability membership, not intent judgment.** The verifier
checks structural membership of a typed capability ("is this action inside the
authorized envelope?"), never "does this look risky?". Derive the capability
from **trusted input only**, plan-then-execute style: extract the envelope from
the user instruction / task spec / repo policy BEFORE any untrusted tool output
is seen, freeze it, then enforce. If the extractor ever reads injected content,
the injection rewrites the envelope and we have gated nothing.

**P4 — Risk tier = authorization path, not a vibe.** Low (typed, reversible,
bounded) → auto-token. Medium (typed, meaningful side effect) → approval.
High (irreversible, privileged, external) → human co-sign. Forbidden → deny.

**P5 — Receipts must be independently verifiable.** Anchor the (capability,
policy version, decision, effect hash, approval) to an independent append-only
ledger via Merkle commitment — verifiable WITHOUT trusting our infra. A
vendor-signed hash chain (what AEGIS already has) is not differentiated; the
anchored, infra-independent proof is.

**P6 — Kernel stays domain-agnostic.** Everything domain-specific is an adapter:
a canonicalizer (extract the effect), a policy (typed-capability rules), an
effector (turn the token into the rail's required input). No kernel edits per
domain. The kernel = verifier pipeline + consume-once + context binding +
anchored receipts + the token/effector seam.

## The bypass-resistance test (acceptance bar)

Before claiming any adapter "enforces," answer in writing:
> Name every path to the dangerous effect. Does the gate sit on ALL of them,
> or can the agent reach the effect another way?

If any path is ungated, it is monitoring, not enforcement. This is exactly the
test the Claude Code classifier fails (shell gated, file-edit path open).

## Coding / DevOps adapter (the second domain) — spec

This is a **rail-bridge** adapter (P2b), stated honestly: GitHub, CI, and cloud
already own the hard enforcement. Our value is policy → required-token + the
anchored receipt, with the gate placed on the effect.

**Typed capabilities (examples):** `create_pr`, `merge_pr`, `apply_plan`,
`modify_iam`, `deploy`, `rotate_secret`, `edit_path`, `run_command`.

**Bind the EFFECT (P1), not the tool:**
- Code: the canonical action is the resulting **change set** — which paths the
  diff touches, protected-file membership (`auth/**`, `.github/workflows/**`),
  dependency/secret changes — NOT "the agent invoked the merge tool." A docs
  edit and a CI-workflow edit are different effects even via the same tool.
- Infra: the canonical action is the **plan diff** — resource types/targets,
  whether it touches IAM/security-groups/databases — NOT "ran terraform."

**Plug into the existing hard rail (not a client interposer):**
- GitHub **branch protection** + required reviewers / **required status checks**
  → the verifier's approval is delivered as a required check / signed approval
  that only passes when policy is satisfied. Gate at the server, not the agent's
  git client.
- CI/CD **environment protection rules** / required manual approval → deploy gate.
- Cloud **IAM / policy-as-code** (OPA/Sentinel) on apply → emit the condition
  the apply requires.
- **Signed commits / artifact signing** for provenance into the receipt.

**Capability derivation (P3):** the envelope ("may touch `docs/**`, `tests/**`;
may not touch `auth/**` or `.github/workflows/**`; may not merge to protected
branches; deploy requires human co-sign") comes from repo policy / task spec,
fixed before the agent runs, never rewritten by tool output.

**Receipt (P5):** anchor (capability, policy version, effect hash = diff/plan
hash, decision, approver) to the independent ledger.

**Explicit non-goal:** do NOT build a client-side wrapper around the agent's
shell/file tools as the sole gate. That is the bypassable interposer pattern.

## Sequencing (de-risk before broadening)

1. **Now — plan-then-execute intent provider, in payments/banking.** Replace the
   ground-truth oracle with an envelope extracted from trusted input only, then
   re-measure ENFORCEMENT / FALSE-POSITIVE honestly. This de-risks the universal
   intent→capability problem (P3) in the domain where our moat is strongest
   (custodial). The numbers stop being an upper bound here.
2. Refactor the kernel to `Action` + `DomainAdapter`, with the two archetypes
   (custodial / rail-bridge) as first-class.
3. Build the coding/DevOps rail-bridge adapter per the spec above; validate it
   against the bypass-resistance test (bind the diff/plan, plug a real hard rail).
4. Ship the anchored (Merkle) receipt as the cross-domain evidence layer.

## What NOT to build (so we don't drift into the crowded category)

- Another tool-call interception SDK.
- Another allow/block/review risk classifier.
- A vendor-signed-log audit trail.

All three already exist and are not the moat. The moat is: enforcement the agent
cannot bypass (held capability or server-side hard rail, on the effect surface)
+ proof you don't have to trust us to verify.