# Architecture

Signet is layers, and the boundaries between them are the whole point. A **kernel**
decides whether an effect is authorized and, if so, mints a signed one-time token.
An **authorizer** turns that token into a rail-specific capability through a fixed
template. A **broker** exposes that template over a transport so a *separate*
process — not the agent — holds the keys. A **sandbox** supplies the OS
interposition that some rails need to be a real boundary. And a **local gate**
sits in the agent's own process as defense-in-depth, explicitly not the boundary.

The kernel never learns what a rail is. Adding a rail is filling two hooks; it has
never required touching the kernel (`core_kernel_edits_zero` 0/10 in the
scorecard, enforced against a pinned byte-baseline).

```
┌──────────────────────────────────────────────────────────────────────────┐
│  LOCAL GATE (in-agent, Stage 1/2)   signet/fence.py · signet/cli/          │
│  PreToolUse hook · deterministic · offline · signed receipts               │
│  defense-in-depth + on-ramp — NOT a boundary (the agent can write around)  │
└──────────────────────────────────────────────────────────────────────────┘
        the boundary lives below, in a process the agent does not control:
┌──────────────────────────────────────────────────────────────────────────┐
│  BROKER  (separate OS principal)            signet/broker/                 │
│   ├─ issuer surface (unix-socket RPC)   server.py · client.py · mandate.py │
│   └─ proxy  surface (inline admission)  proxy.py                           │
│            both drive ↓ the same unchanged machinery                       │
│  AUTHORIZER TEMPLATE        signet/authorizers/base.py                     │
│   verify_token → recheck_against_context → produce_capability  (2 hooks)   │
│  RAILS (fill only the 2 hooks)   signet/rails/{supabase,egress}/ · authorizers/│
│  KERNEL (10 files, 0 rail edits)   signet/verifier.py · chain · crypto …   │
│   11-step verify · context-bind · consume-once on chain_hash · signed token│
└──────────────────────────────────────────────────────────────────────────┘
        OS layer that makes the not-free only-doors real:
┌──────────────────────────────────────────────────────────────────────────┐
│  SANDBOX  signet/sandbox/netns.py   netns + veth + nft + unprivileged exec │
│  EGRESS-SOLE-PATH · AGENT-UNPRIVILEGED-IN-NETNS                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Plan before you read untrusted data

The single most important structural choice: the authorized envelope is derived
from **trusted instructions, frozen before the agent touches any untrusted runtime
data.** The operator's mandate — the criterion and the policy scope — is loaded
first and never sourced from a PR body, an issue, a plan file, or anything the
agent fetched. The effective fence is `standing_policy ∩ task_mandate`, and that
intersection only ever *narrows*: a task can add restrictions, never widen them.
This is what makes injection a containment problem rather than an authorization
problem — by the time the agent reads attacker-controlled text, the fence it has
to stay inside is already fixed.

## The kernel pipeline, and why the order matters

The verifier (`signet/verifier.py`) runs eleven checks in a deliberate order. The
order is load-bearing, not cosmetic:

1. **Signatures** — verify every mandate signature first, before anything
   stateful. This is the cheap-DoS guard: junk requests can't flood the
   consume-once registry because they're rejected before they reach it.
2. **Chain linkage** — Intent → Cart → Payment must hash-link correctly.
3. **Agent identity** — the acting agent matches the one the Intent authorized.
4. **Action allowed** — the action is in the Intent's allow-list.
5. **TTL / freshness** — checked against the *verifier's* clock, never a
   client-supplied timestamp. A client can't extend its own window.
6. **Revocation** — the mandate hasn't been revoked.
7. **Context binding** — the runtime context hash must equal the context the Cart
   committed to. This catches recipient/destination substitution and
   cross-context replay: the agent presents what it's *about* to do, and it has to
   match what was approved, field for field.
8. **Exactness** — runtime amount/currency equals the Cart, the Cart is within the
   Intent's cap, the recipient is on the allow-list. (7 catches *who/where*, 8
   catches *how much*.)
9. **Policy** — caps, allow-list, currency, velocity, human-approval thresholds.
10. **Atomic consume-once** — keyed on the `chain_hash` (the exact bound
    transaction), the *last* gate before a token is issued. Replaying the identical
    transaction is rejected; distinct carts under one Intent are still allowed.
    Keying on the chain rather than the Intent nonce is what makes multi-step
    mandates work without opening a replay hole.
11. **Record spend, sign the token** — velocity spend is recorded **per
    principal**, not per mandate, so an attacker can't structure a large transfer
    across many small mandates.

Two invariants run underneath. **Fail closed:** any check that can't be satisfied
blocks; there is no best-effort path. **Trust only the token:** nothing downstream
acts on the agent's word or the raw mandate — only on a verified `ExecutionToken`.
(The 21 attacks in `tests/test_attacks.py` are the spec for this pipeline.)

## The authorizer template — two hooks, one flow

The authorizer is the only thing that can produce a rail capability, and it's a
template, not a free function (`signet/authorizers/base.py`):

```
authorize(token, req):                      # FINAL — the rail cannot override it
    verify_token(token, enforcer_vk)        # signed, unexpired, bound to THIS chain
    recheck_against_context(req)            # ← hook 1: re-derive the effect, confirm match
    produce_capability(req)                 # ← hook 2: mint the rail-specific capability
    # fail-closed: any step that can't be satisfied → no capability
```

A rail fills **only** the two hooks; it physically cannot skip the token check or
the re-check, because the base class owns the flow. This is the second containment
layer below the kernel: even an authorizer that tried to mint unconditionally is
stopped on an invalid token or a context mismatch. The test
`test_broker_egress.py::test_egress_authorizer_fills_only_two_hooks` asserts
`EgressAuthorizer.authorize is Authorizer.authorize` — the rail did not, and
cannot, fork the flow.

**The rails today:**

| Rail | Module | Shape | Only-door |
|---|---|---|---|
| GitHub merge / deploy / infra (origin) | `evals/*_railbridge/`, `signet/authorizers/` | rail-bridge | the server-side hard rail (required check) |
| Supabase Postgres | `signet/rails/supabase/` | credential issuer | zero-standing-cred + Postgres RLS (**free**, P9) |
| Egress | `signet/rails/egress/` | broker-as-proxy | the netns (**OS-interposition**, P9) |

## The broker — multi-surface, one core

The broker (`signet/broker/`) is the authorizer template exposed over a transport
so the keys live in a *separate OS principal*, not the agent. Agent identity is
established by peer credentials (SO_PEERCRED on Linux), never a bearer secret the
agent could leak; the broker refuses to start, and refuses each connection, when
the peer shares its uid (`test_unix_socket_refuses_to_start_when_agent_is_broker_uid`).
It has two surfaces over one shared core (mandate provider, the unchanged
authorize template, the kernel verifier, shared consume-once, signed receipts):

### Shape A — issuer (the DB rail, a *free* only-door)

Here the resource itself (Postgres + RLS) is a trustworthy external enforcer, so
the broker only has to *decide* and *mint*; the agent then carries a scoped,
short-lived credential to a separate resource.

```
agent ──unix-socket RPC──▶ broker (separate uid)
  "effect: read staging.orders"     1. authenticate peer uid (≠ broker uid)
                                     2. serialize effect → AP2 chain
                                     3. kernel Verifier.evaluate → signed token
                                        (consume-once on chain_hash, verifier clock)
                                     4. SupabaseAuthorizer.authorize:
                                        recheck: effect ∈ mandate ∩ standing
                                        produce: mint scoped ES256 JWT (role/sub/exp/
                                                 signet_effect_hash) — real secret stays here
                                     5. signed receipt
  ◀──── scoped JWT (short-lived) ────
agent ──JWT──▶ Postgres ── RLS enforces the JWT's scope ──▶ rows
                          (agent has NO DSN / service_role key — zero standing cred)
```

The boundary is "the agent holds nothing it can authenticate with." Remove that
precondition — leak a DSN into the agent's env — and the broker is reduced to
advisory: `test_09_NEGATIVE_bypass_succeeds_when_standing_credential_present`
constructs a direct connection *because a DSN exists* and asserts it succeeds.
That is P8 made honest under test.

### Shape B — inline proxy (the egress rail, an *OS-interposition* only-door)

Here nothing trustworthy sits between the agent and "anywhere on the network," so
the broker must be issuer **and** enforcer, on the data path. Issuer and enforcer
collapse into one process; no bearer token is handed out — the capability is
consumed inline at admission.

```
agent ──CONNECT host:port──▶ proxy (broker surface, signet/broker/proxy.py)
                              1. resolve host with the broker's OWN trusted resolver
                                 (agent cannot pick the IP → defeats raw-IP + poisoned DNS)
                              2. serialize EgressEffect(host,port) → AP2 chain
                              3. kernel Verifier.evaluate → signed token (consume-once)
                              4. EgressAuthorizer.authorize:
                                 recheck: destination ∈ mandate ∩ standing
                                 produce: "admit + forward"  (no token to the agent)
                              5. signed receipt (pass) — or 403 + ConsideredRejected (deny)
  ◀── 200 Connection Established ──
agent ⇄⇄⇄ proxy ⇄⇄⇄ upstream    verbatim byte-splice: no TLS termination, no payload
                                 inspection (binds WHERE, never WHAT)
```

The boundary is "the agent has no network path except this proxy" —
`EGRESS-SOLE-PATH`. Without it, a direct connection bypasses the proxy entirely:
`test_08_NEGATIVE_direct_connection_bypasses_proxy` asserts that bypass *succeeds*
(advisory). The sandbox is what supplies the missing precondition.

## The sandbox — making the not-free only-door real

`signet/sandbox/netns.py` is a privileged controller that puts the agent in a
network namespace whose only route out is the broker proxy: a veth pair, a default
route via the host-side veth, `nft` dropping everything except the proxy
host:port, no NAT/forward, and no reachable resolver (so all name resolution must
go through the proxy). The load-bearing property is **not** the plumbing — it's
that the agent runs *unprivileged* inside the netns
(`AGENT-UNPRIVILEGED-IN-NETNS`): the controller execs it under `setpriv
--reuid/--regid --clear-groups --bounding-set -all --no-new-privs`, so its
capability bounding set is empty and `CAP_NET_ADMIN` is structurally unreachable —
it cannot add a route or flush `nft` to escape. Verified by `test_netns_egress.py`
(privilege-gated; a measurement, not a CI invariant, because CI cannot get
`CAP_NET_ADMIN`). It is the inverse of the advisory egress #8: same direct-bypass
move, now blocked.

## Resolution (the rail-bridge origin)

The rail-bridge rails (GitHub/deploy/infra) add a quarantined resolver in front of
the kernel for the cases where picking *which* target a criterion refers to needs
judgment ("the PR that fixes the double-charge bug"). **Role A (trusted)**
interprets the operator's criterion only and is deterministic. **Role B
(quarantined)** sees the candidates and their untrusted data and returns a *set,
not a pick* — a cardinality rule then decides: exactly one survivor resolves, two
or more (or zero) escalates to a human. Ambiguity becomes a count, not a
confidence score the model gets to fudge. Whatever Role B returns, containment
never depends on it: the set runs through the same gate and kernel, so a fully
captured resolver (proven with an adversarial stub) is contained the same as an
honest one. A conformance battery + adaptive red-team gate rail registration
(`rail_conformance` 3/3, `red_team_breakout_zero`). This machinery is real and
CI-tested but it is the *origin*; the product's boundary is the keyholder broker.

## The audit log

Every decision — allow, block, or escalate — appends a hash-chained signed receipt
bound to the `policy_hash` that decided it. An auditor verifies a single decision
from `(record, signed root, pinned key)` alone, with no access to the running
system — `test_capability_independently_verifiable_without_broker` and the
receipt-chain tests prove this. The local log is tamper-**evident**, not
tamper-proof: it is containment UX, never the enforcement boundary (LOCAL_GATE.md,
DESIGN.md P2). The immutable cross-host anchor (S3 Object-Lock / Rekor) is on the
roadmap.

## What's deliberately not in the kernel

The kernel doesn't detect prompt injection, doesn't reason about rails, and
doesn't patch the threats that belong upstream — a correctly-signed but malicious
chain (mitigated by human-present thresholds at signing time), principal key
compromise, agent–merchant collusion. Several primitives are proof-of-concept and
isolated for swapping: Ed25519 (→ ECDSA P-256), sorted-keys JSON (→ RFC 8785 JCS),
single-process SQLite consume-once (→ a multi-instance atomic store), and a local
append-only anchor (→ a real immutable log). Each is one file; none is in the
decision logic, only its primitives.
