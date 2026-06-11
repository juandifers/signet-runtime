# CLAUDE.md — Signet Runtime

Read this before changing anything. It encodes decisions already made so they
don't get re-litigated, and the invariants that must survive any refactor.

> **This repo is fenced by its own product (dogfood).** `.signet/policy.yaml` is
> live and a `signet hook` PreToolUse gate is wired (per-developer, in the
> git-ignored `.claude/settings.local.json`; run `signet init` to wire your copy).
> Future agent sessions will be **DENIED** on edit-class tools touching `.signet/**`,
> `.claude/settings*.json`, `signet/**`, `evals/scorecard/**`, `.github/workflows/**`
> and the other protected globs — **by design**. A human changes the fence by running
> the `signet` CLI, not the agent. If you hit the gate, that is the product working —
> do not try to disable, move, or route around it; ask the human to adjust the policy.
> (The local gate is containment UX + tamper-evident receipts, not the enforcement
> boundary — see LOCAL_GATE.md.)

## What this is

Runtime enforcement for AP2-style agent payment mandates. AP2 produces a signed
chain (Intent → Cart → Payment). Signet sits at the last step before
irreversible execution and ensures the action matches the signed chain, passes
policy, executes once, in context — and emits signed proof.

Positioning: **AP2 proves authorization; Signet enforces that the authorized
chain executes once, in context, under policy — and anchors proof that it did.**

## Run / verify

```bash
pip install -e ".[dev]"          # pydantic, pynacl, xrpl-py, fastapi, pytest
pytest -v                        # 21 attack tests — these are the spec
python -m demos.role2_demo       # rail-agnostic block/execute + receipt log
python -m demos.role1_xrpl_demo  # XRPL 2-of-2: agent-alone fails quorum
python -m demos.mpc_demo         # MPC 2-of-2 threshold: agent-alone can't sign
uvicorn signet.api:app --reload  # HTTP surface at /docs
```

**The tests are the specification.** Each test is one attack. Keep them green.
When adding a defense, add the attack test that proves it first.

## Architecture — the one rule

One rail-agnostic **verifier** makes the decision. Pluggable **authorizers** turn
that decision into a rail-specific *necessary input*.

- Adding a rail (EVM Safe, MPC signer, a real PSP) = write one new authorizer
  implementing `signet/authorizers/base.py`. **Do not put rail logic in the
  verifier.** The kernel stays rail-agnostic.
- An authorizer must call `verifier.verify_token(...)` and refuse to produce its
  capability unless the token is valid, unexpired, and bound to *this* exact
  transaction. Re-check destination/amount against `req.context` inside the
  authorizer (see `xrpl_cosigner.cosign`).

## Invariants that must not regress

1. **Trust only the enforcer token.** Authorizers never act on the agent's word
   or the raw mandate — only on a verified `ExecutionToken`.
2. **Signature before nonce.** The verifier checks signatures before touching the
   consume-once registry, so junk can't flood the registry (cheap DoS).
3. **Verifier-authoritative clock.** TTL/freshness uses the verifier's clock,
   never a client-supplied timestamp.
4. **Consume-once is keyed on `chain_hash`** (the exact bound transaction), and is
   the LAST gate before issuing the token. Replaying the identical transaction is
   rejected; distinct carts under one Intent are allowed (subject to velocity).
   Do not move this back to the intent nonce — that breaks multi-payment mandates.
5. **Velocity aggregates per principal**, not per mandate (each cart mints a fresh
   mandate; per-mandate would never accumulate and the structuring defense dies).
6. **Fail closed.** Any check that can't be satisfied → block. No "best effort".
7. **LOCAL-MONOTONIC.** The local PreToolUse hook (`signet hook`) never emits
   permissionDecision "allow"; it can only narrow what the user's own permission
   rules would do. An "ask" that cannot be emitted degrades to deny, never to pass.
8. **SELF-PROTECT.** `.signet/**`, `.claude/settings.json`,
   `.claude/settings.local.json` (repo-relative — the local file holds the absolute
   hook command) and the signet home dir (`~/.signet/**`) are always-deny for
   edit-class tools, hardcoded and evaluated BEFORE the user policy loads. The agent
   must not be able to move its own fence, wherever the wiring lives.
9. **GATE-PURITY.** No LLM call, network call, or evals/* import anywhere in the
   `signet hook` execution path. Deterministic, offline, <100ms warm.
10. **LOCAL-RECEIPT.** Every evaluated tool call appends exactly one signed,
    hash-chained local record bound to the policy_hash that decided it. The local
    log is tamper-EVIDENT, not tamper-proof — the local gate is containment UX,
    never the enforcement boundary (DESIGN.md P2; see LOCAL_GATE.md).

### Broker / keyholder rails (DESIGN.md P7/P8; see signet/broker/, signet/rails/)

11. **ZERO-STANDING-ELEVATED-CRED.** The agent process must hold NO secret/
    service_role key, NO JWT signing key, and NO direct DB connection string. It may
    hold the RLS-neutered publishable key. To touch a protected resource it must
    request a brokered, short-lived, effect-bound capability. This is the only-door
    *for free*; if a standing elevated credential leaks into the agent's env, the
    broker is reduced to advisory (proven by the Phase-4 #9 negative test).
12. **CAP-BOUND.** Every issued capability is bound to a single effect
    (`signet_effect_hash`), carries an `exp`, and is consume-once on `chain_hash`
    (the kernel verifier mints it — the broker never forks consume-once). Replay
    within the capability's life is refused; the captured credential is dead after
    `exp`; the frozen mandate constrains regardless of dwell time.
13. **BROKER-SEPARATE-PRINCIPAL.** The broker runs as a distinct OS user; agent
    identity is established by peer credentials (SO_PEERCRED), never a bearer secret
    the agent could leak. The broker refuses to start, and refuses each connection,
    when the peer shares the broker's uid (the only-door is void).
14. **ONLY-DOOR-OR-DECLARE.** A rail claims "boundary" only where its resource is
    unreachable without a brokered capability. Where an ambient path exists (raw
    egress, a leaked DSN), the claim is downgraded to "advisory" in docs AND a
    negative test records it (Phase-4 #9 is the template) — overclaiming containment
    is a violation on par with a fabricated result.
15. **EGRESS-SOLE-PATH.** The agent has NO network egress except the broker proxy.
    This is now **ENFORCED** under the netns deployment (`signet/sandbox/netns.py`):
    the controller puts the agent in a network namespace whose only route out is the
    proxy (default route via the host-side veth + nft drop-OUTPUT-except-proxy + no
    NAT/forward + no resolver). Where the netns is ABSENT the rail stays **advisory**,
    and `test_broker_egress.py` #8 records that state (a direct connection bypasses
    the proxy and SUCCEEDS). The two are the two halves of ONLY-DOOR-OR-DECLARE, both
    true and both kept: the deterministic #8 (advisory-WITHOUT, always-run) and
    `test_netns_egress.py` (boundary-WITH, opt-in, needs CAP_NET_ADMIN — a MEASUREMENT,
    NOT a CI invariant; CI cannot get CAP_NET_ADMIN, so it skips cleanly). The egress
    proxy is the broker's second surface (inline admission); it binds the DESTINATION
    (host+port), resolves DNS itself (trusted), and splices bytes verbatim — no TLS
    termination, no payload inspection (DESIGN.md P9: the first OS-interposition
    only-door; see signet/broker/proxy.py, signet/rails/egress/, signet/sandbox/).
16. **AGENT-UNPRIVILEGED-IN-NETNS.** The sandboxed agent has NO CAP_NET_ADMIN over its
    own network namespace; only the controller (privileged, a separate principal —
    BROKER-SEPARATE-PRINCIPAL extended) configures it. Without this the only-door is
    void: an agent that can add a route, flush nftables, or raise an interface escapes
    silently. The controller execs the agent under `setpriv --reuid/--regid
    --clear-groups --bounding-set -all --no-new-privs`, so the agent's capability
    bounding set is empty and CAP_NET_ADMIN is structurally unreachable (verified by
    `test_netns_egress.py`: in-netns `ip route add` / `nft flush` are DENIED). The
    netns plumbing is the easy part; this privilege drop is the actual boundary.

The broker IS the unchanged Role-2 authorizer template over a transport: it reuses
`signet/authorizers/base.py` (`verify_token → recheck_against_context →
produce_capability`) and the unchanged kernel `Verifier` (consume-once, signed
token). A rail fills ONLY the two content hooks (see
`signet/rails/supabase/authorizer.py`); it never edits the kernel or the template.

## The verifier pipeline order (signet/verifier.py)

signatures → chain linkage → agent identity → action allowed → TTL → revocation →
context binding → exactness (amount/currency/allowlist) → policy (caps/allowlist/
currency/velocity/human-approval) → atomic consume-once → record spend + sign token.

Order is deliberate. Cheap, attacker-unfalsifiable checks first; the single
stateful write last.

## Threat model — DO NOT scope-creep these

**In scope (enforced):** replay (same/cross-context), recipient/destination
substitution, amount tampering, Cart substitution, chain-linkage breaks, expired/
revoked mandates, currency substitution, split/structuring (velocity), caps,
allowlist, human-approval thresholds.

**Out of scope — by design, document honestly, do NOT try to "fix" here:**
- A prompt injection that produces a *fully self-consistent, correctly-signed*
  malicious chain. If the principal's signing surface authorized a bad Cart,
  every hash matches and Signet passes it. Mitigation is upstream (prompt-playback
  confirmation, signing-time review, human-present thresholds), not in the kernel.
- Principal key compromise.
- Agent–merchant collusion.

If asked to "stop prompt injection," the correct answer is upstream controls +
keeping the execution-time checks tight — not adding heuristics to the verifier.

## Environment gotcha (XRPL)

The XRPL co-signer's cryptographic path (build → agent sign → enforcer co-sign →
quorum check) runs **offline** — that's what proves the property. Live testnet
settlement needs network egress to XRPL endpoints (e.g.
`https://s.altnet.rippletest.net:51234/`). To settle for real:
1. Fund agent + enforcer + funding wallets at the testnet faucet.
2. Submit `SignerListSet` on the funding account establishing the 2-of-2
   (optionally `DisableMasterKey` so multisign is the only path).
3. `autofill` the Payment against the network, then `submit_to_testnet(combined)`
   in `signet/authorizers/xrpl_cosigner.py`.

## Production swaps (noted, not yet done)

- Crypto: AP2 mandates **ECDSA P-256** for VC signatures; PoC uses Ed25519 for
  XRPL consistency. Swap is isolated to `crypto.sign/verify`.
- Canonicalization: `canonical.py` uses sorted-keys JSON; replace with **RFC 8785
  JCS** for spec-faithful canonical form.
- State: consume-once + velocity use single-process SQLite. Back with a store
  giving atomic check-and-set across instances (Redis/Postgres).
- Receipts: anchor `receipt_hash` to an XRPL memo to defeat equivocation.

## Highest-value next step

**Done (Role 1b):** the threshold-signature / MPC authorizer — the enforcer holds
one key share, so it becomes a mandatory co-signer for *every* chain at once rather
than per-ledger. The rail-agnostic generalization of Role 1; drops into the same
`Authorizer` interface, kernel untouched. See `signet/authorizers/mpc_cosigner.py`
(2-of-2 threshold Schnorr over edwards25519) and `demos/mpc_demo.py`. Production
target is FROST(ed25519) + an MPC nonce-commitment round; the swap seam is isolated
the same way as `crypto.py` / `canonical.py`.

**Now:** the HTTP surface (`signet/api.py`) wires **only** the mock broker. Neither
the XRPL nor the MPC authorizer is reachable over the API — they run only in tests
and demos. Exposing a rail-selectable authorizer endpoint (without putting rail
logic in the kernel) is the next step.

## File map

```
signet/verifier.py     the 11-step kernel (start here)
signet/chain.py        hashing + linkage + context binding
signet/models.py       Intent/Cart/Payment + runtime/token/receipt
signet/policy.py       caps, allowlist, currency, velocity
signet/nonce.py        SQLite atomic consume-once
signet/revocation.py   execution-time mandate revocation (in-memory set)
signet/receipts.py     hash-chained signed receipts
signet/builder.py      mint signed chains + attack-variant hooks (tests/demos use this)
signet/authorizers/    base.py (the Role-2 template — FILL ONLY 2 HOOKS), mock_broker.py
                       (Role 2), xrpl_cosigner.py (Role 1), mpc_cosigner.py (Role 1b)
signet/broker/         the broker = authorizer template over a transport (separate OS
                       principal). MULTI-SURFACE: server.py/client.py (unix-socket issuer
                       RPC, the DB rail) + proxy.py (inline egress proxy); mandate.py,
                       protocol.py. Reuses base.py + kernel Verifier; forks nothing.
signet/rails/          keyholder rails, each fills ONLY base.py's two hooks:
                       supabase/ (DB — free only-door, ES256 scoped JWT, Postgres/RLS),
                       egress/   (broker-as-proxy — OS-interposition only-door)
signet/sandbox/        netns.py — the EGRESS-SOLE-PATH only-door (netns + veth + nft +
                       unprivileged exec); _agent_probe.py. Linux-only; privilege-gated.
signet/fence.py        local path/command fence + .signet/policy.yaml (Stage 1;
                       matching semantics lifted from the GitHub rail MergePolicy)
signet/cli/            the `signet` console script: hook (PreToolUse local gate),
                       init/status/receipts/explain, attack_me.py, signed local receipts.
                       NEVER import evals/* here (GATE-PURITY). See LOCAL_GATE.md.
tests/test_attacks.py            21 attacks = the kernel spec
tests/test_broker_supabase.py    DB-rail bypass battery (#9 = leaked-cred advisory)
tests/test_broker_egress.py      egress bypass battery (#8 = no-netns advisory)
tests/test_netns_egress.py       netns boundary (privilege-gated; a measurement)
tests/test_local_fence.py        the local gate + tests/test_attack_me.py (the bare-push gap)
```

## Knowledge base (second brain)

A persistent, LLM-maintained knowledge base for this project lives **outside the
repo** at `~/Documents/knowledge-bases/signet-runtime-kb` (an Obsidian vault). It
holds research-paper digests, entity/concept/decision pages, open questions, and a
design log — the accumulated "why" behind the code.

**Do not auto-load it.** It is large and grows; pulling it all in wastes context.
Read it **on demand only**:
- Start at `signet-runtime-kb/index.md` (the catalog), then open just the few pages
  you need. Recent activity: `grep "^## \[" signet-runtime-kb/log.md | tail`.
- For *how* to read/write/ingest/lint the KB, follow its own constitution at
  `signet-runtime-kb/CLAUDE.md` — that file is authoritative for KB conventions
  (page format, folders, the paper-ingest template). Read it before editing the KB.

**Trigger — "add what we've been doing to the KB" (or "ingest this", "log this
decision"):** treat it as a KB **INGEST/update**, not an ad-hoc note. Steps:
1. Read `signet-runtime-kb/CLAUDE.md` and `index.md` first.
2. Distil the session into the right page types: new mechanisms → `concepts/`,
   components → `entities/`, choices-with-rejected-alternatives → `decisions/`,
   unknowns → `questions/`, external papers → `sources/` (use the paper template).
3. Update affected existing pages + cross-links; flag contradictions, don't silently
   resolve them. Update `index.md` and append a dated `log.md` entry.
4. Report what you created/updated. Code stays ground truth; the tests are the spec.
