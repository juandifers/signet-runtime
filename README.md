# Signet Runtime

**A keyholder enforcement layer for autonomous agents.** Signet sits below the
model and holds the keys to every irreversible effect — moving money, merging a
PR, applying infrastructure, reaching the network, touching a database. The agent
holds nothing. To cause a privileged effect it must ask a separate broker for a
short-lived, effect-bound, single-use capability, and the broker issues that
capability only after re-checking the request against a mandate frozen *before*
the agent read any untrusted input.

The design starts from a concession most agent-security tools won't make:
**assume the model has already been compromised by prompt injection.** Signet
does not try to recognize a malicious action — it assumes it cannot. Instead it
removes the agent's ability to *perform* the action unilaterally. So the
guarantee isn't "the model won't be fooled"; it's *"when the model is fooled, the
harmful effect still can't execute, and there's a signed receipt proving it
didn't."*

> AP2 proves an action was authorized. Signet enforces that the authorized action
> — and only that action — executes once, in context, under policy, and anchors
> independently-verifiable proof that it did.

---

## The keyholder model

There are two ways to put a gate in front of a dangerous action, and only one of
them is a boundary.

- **Inspect the command.** Watch the agent's tool calls and block the bad ones.
  This can always be fooled (a malicious action described as benign) or *skipped*
  (an agent that writes code reaches the effect by a path the inspector never
  sees). It is monitoring, not enforcement.
- **Hold the key.** Don't judge the action — own the capability the action
  requires, and hand out one door at a time. The agent cannot perform the effect
  because it does not possess what the effect needs.

Signet is the second. *Stop inspecting the command; hold the only key.* (DESIGN.md
**P7**.)

The proof that inspection cannot be the boundary is in this repo: `signet
attack-me` runs a bare `git push` that reaches a protected branch **without any
command the path-inspecting gate can match** — the dangerous effect simply isn't
in the string. Capability issuance has no such gap: the effect is *in the
request*, frozen and bound before any credential exists. (Trace:
`tests/test_attack_me.py::test_act3b_bare_push_is_the_honest_gap`.)

A rail is a real boundary only where the protected resource has an **only-door** —
a sole path that passes through the broker. Where no such door exists, Signet says
so, in this README and in a test, rather than overclaiming. That honesty is the
point of the status map below.

## What exists — the honest status map

This is the scorecard discipline applied to prose. Every component carries two
labels — **maturity** (how built/verified it is) and **boundary strength** (how
strong a containment claim it actually supports) — and a test that backs it. We
publish the advisory and out-of-scope rows on purpose; most products don't.

| Component | Maturity | Boundary strength | Traceable to |
|---|---|---|---|
| Kernel verifier — 11 checks, context-binding, consume-once on `chain_hash`, signed tokens | built + CI-tested | substrate (N/A) | `tests/test_attacks.py` (21 attacks); `core_kernel_edits_zero` 0/10 |
| Authorizer template — `verify_token → recheck_against_context → produce_capability` | built + CI-tested | substrate (N/A) | `test_broker_egress.py::test_egress_authorizer_fills_only_two_hooks` |
| **Credential rail — Supabase Postgres (keyholder)** | built + CI-tested | **boundary** when zero-standing-cred holds; **advisory** if a standing credential leaks | boundary: `test_broker_supabase.py::test_07…`; advisory: `…::test_09_NEGATIVE…`; RLS scope: `…::test_06…` |
| **Broker** — multi-surface: unix-socket issuer RPC + inline egress proxy, one core | built + CI-tested | substrate; separate OS principal | `test_broker_supabase.py::test_unix_socket_refuses_to_start_when_agent_is_broker_uid` |
| **Egress rail — broker-as-proxy** (destination-bound, trusted DNS, no payload inspection) | built + CI-tested | **boundary** when the netns is present; **advisory** without it | advisory: `test_broker_egress.py::test_08_NEGATIVE…`; boundary: `test_netns_egress.py` |
| **netns sandbox — `EGRESS-SOLE-PATH`** (agent unprivileged inside; controller holds netns) | built + privilege-gated-verified (Linux, `CAP_NET_ADMIN`) | **boundary** under that deployment | `test_netns_egress.py` (skips cleanly in CI — a *measurement*, not a CI invariant) |
| Rail-bridge rails — GitHub merge / deploy / infra-apply (the origin) | built + CI-tested | boundary **via the server-side hard rail** (advisory until the required-check is configured) | `rail_conformance` 3/3; `red_team_breakout_zero` |
| Signed, hash-chained local receipts | built + CI-tested | tamper-**evident** (independently verifiable from `record + key`) | `test_broker_supabase.py::test_capability_independently_verifiable_without_broker` |
| Local gate — `signet hook` + `signet attack-me` (Stage 1/2) | built + CI-tested | **defense-in-depth — NOT a boundary** | `tests/test_local_fence.py` (14); `tests/test_attack_me.py` (7) |
| Output/emission containment (the link-preview exfil variant) | designed — out of scope | N/A | DESIGN.md egress §; `test_broker_egress.py::test_09c…` |
| Exfil through an *allowlisted* destination (binding is *where*, not *what*) | out of scope by design | N/A | `test_broker_egress.py::test_09a…` |
| Immutable receipt anchor (S3 Object-Lock / Rekor) | planned | N/A | — |
| Rootless sandbox · broker key custody · agent-sandbox launcher · onboarding | planned | N/A | — |
| Containment demo (autonomous agent in the sandbox, agent-initiated exfil blocked) | planned | N/A | — |

Reading the map: a **boundary** is enforced structurally; **advisory** means the
logic is real and tested but a precondition (zero-standing-cred, or the netns)
must hold for it to contain — and a negative test proves the bypass succeeds when
the precondition is removed (DESIGN.md **P8**, honest containment scope).

## What it looks like — the 60-second on-ramp

The fastest way to see Signet is the **local gate**, the Stage 1/2 product
surface. It is defense-in-depth and a demo on-ramp — *not* the enforcement
boundary (that is the broker). It contains a cooperating coding agent behind a
deterministic, offline, LLM-free PreToolUse fence and writes a signed,
hash-chained receipt for every decision:

```bash
pipx install signet-runtime        # or: pip install -e ".[dev]"
signet init                        # writes .signet/policy.yaml + wires the PreToolUse hook
signet attack-me                   # drive hostile tool calls through the REAL gate
```

```
ACT 1  edit signet/verifier.py        -> DENIED   (protected path)   receipt ldr_…  ✓ signed
ACT 2  write .env with a secret       -> DENIED   (protected path)   receipt ldr_…  ✓ signed
ACT 3b bare `git push` to main        -> the honest gap: a path-inspector can't see the effect
…
signet receipts --verify              -> chain + signatures intact
```

`signet attack-me` is also the proof of the keyholder thesis: ACT 3b is the
bare-push gap that no command inspector can close — which is *why* the boundary
must be a held key, not a watched command. See [`LOCAL_GATE.md`](./LOCAL_GATE.md).

## Threat model

**In scope (enforced or contained-when-fooled):** replay (same- and
cross-context), recipient/destination substitution, amount tampering, cart/plan
substitution, chain-linkage breaks, expired or revoked mandates, currency
substitution, split/structuring via velocity, caps and allow-lists,
human-approval thresholds, agent-initiated egress to non-allowlisted destinations
(incl. raw-IP and poisoned-DNS evasion), reaching a brokered resource without a
capability, and delayed (dwell-time) injection firing on a later turn.

**Out of scope by design (documented, not hidden):** a prompt injection that
produces a fully self-consistent, correctly-signed *legitimate-looking* chain
(mitigated upstream — human-present thresholds at signing time); principal key
compromise; agent–merchant collusion; **exfil through an allowlisted destination**
and the **link-preview emission variant** (the binding is *where*, not *what* —
these need an output/emission rail, see roadmap); deep DNS-label tunneling.
Overclaiming containment here would be a violation on par with a fabricated test.

## How it's organized

A rail-agnostic **kernel** decides whether an effect is authorized and mints a
signed one-time token; a **rail** turns that token into a rail-specific capability
by filling exactly two hooks of the authorizer template — the kernel never learns
what a rail is, proven by `core_kernel_edits_zero` 0/10 across every rail. The
**broker** exposes that template over a transport in two shapes: an issuer (the
DB rail mints a scoped credential the resource itself enforces — a *free*
only-door) and an inline proxy (the egress rail is issuer *and* enforcer on the
data path — an *OS-interposition* only-door). The **sandbox** is the OS layer that
makes the egress only-door real. See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for
the layer map and the two request-path shapes, and [`DESIGN.md`](./DESIGN.md) for
the principles (P1–P9), including the **free-vs-OS-interposition classifier** that
predicts, in advance, which rails are cheap boundaries and which need OS help.

## Roadmap (planned — none of this is claimed as working)

- **The containment demo** — a controlled autonomous agent running inside the
  sandbox, with an agent-*initiated* exfil attempt blocked by the egress
  boundary (this is the agent-initiated case, **not** the link-preview attack).
- **Productization** — making `EGRESS-SOLE-PATH` real beyond the privilege-gated
  test (rootless netns), broker/controller hardening and key custody (the broker
  is now the sole egress path *and* holds the keys — the highest-value target),
  the agent-sandbox launcher as a packaged deployable, and a protect-my-repo
  onboarding flow.
- **Anchored receipts** — replace the local append-only stub with a real
  immutable anchor (S3 Object-Lock / Rekor) to defeat equivocation across hosts.

## History

Signet began as a payment-mandate enforcer (an XRPL 2-of-2 / MPC co-signer
holding the enforcer's key share) and a GitHub-merge rail-bridge with a
quarantined, set-valued resolver (a CaMeL-style trusted-planner / quarantined-
worker split, with a cardinality rule that escalates on ambiguity). That work is
real and CI-tested — it is the "rail-bridge" archetype in the status map — but it
is the *origin*, not the product. The product is the keyholder broker. The
grounding it borrows: **AP2** (Agent Payments Protocol) for the mandate chain,
**CaMeL** (Debenedetti et al., 2025) for the planner/worker split, **RFC 6962**
(Certificate Transparency) for the receipt log, and selective-prediction work for
the abstain-when-not-a-singleton rule.

## Run / verify

```bash
pip install -e ".[dev]"            # kernel + broker + rails + local gate + test deps

pytest -q                          # the full suite (the tests are the spec)
python -m evals.scorecard          # invariants vs measurements; exit 1 on any invariant FAIL

python -m demos.broker_supabase_demo   # DB rail: brokered scoped JWT vs leaked-DSN bypass (P8)
python -m demos.broker_egress_demo     # egress rail: admit/refuse + the advisory-without-netns bypass

# The egress OS boundary (Linux + CAP_NET_ADMIN only; skips cleanly elsewhere):
SIGNET_NETNS_TEST=1 sudo -E python -m pytest tests/test_netns_egress.py -v
```

> **Dogfood (intended).** This repo is designed to be fenced by its own product:
> `.signet/policy.yaml` protecting `signet/**`, `evals/scorecard/**`, and the
> workflow files, with a `signet hook` PreToolUse gate wired per-developer. Run
> `signet init` to wire your copy and `signet status` to confirm it reports
> **WIRED**. *(At the time of writing the local fence is being re-wired by hand;
> treat the dogfood gate as the intended state, confirmed by `signet status`, not
> an assertion this README can make for your checkout.)*

## Status of the primitives

This is a research-grade reference implementation, labeled as one. The security
properties are real and tested; several primitives are proof-of-concept and
called out so you know what's a toy and what isn't — each is isolated to one file:

- **Crypto** is Ed25519; AP2 verifiable credentials want ECDSA P-256
  (`signet/crypto.py`).
- **Canonicalization** is sorted-keys JSON; production wants RFC 8785 JCS
  (`signet/canonical.py`).
- **State** (consume-once, velocity) is single-process SQLite; production wants a
  multi-instance atomic store (`signet/nonce.py`).
- **The receipt anchor** is a local append-only log; production wants a real
  immutable anchor (see roadmap).

The kernel stays untouched across all of it: the full suite is green, CI makes no
live LLM or network calls, and every rail runs on the same unmodified 10-file
core.
