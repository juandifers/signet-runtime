# Signet Runtime

**AP2 proves authorization. Signet enforces that the authorized chain executes once, in context, under policy — and anchors proof that it did.**

AP2 (Google's Agent Payments Protocol) gives you a signed chain of three
credentials per transaction: an **Intent Mandate** (what the principal
authorized), a **Cart Mandate** (the specific assembled transaction, bound to
the Intent), and a **Payment Mandate** (the network-facing credential carrying
the matched hashes). What AP2 does *not* do is stop an agent from executing a
payment that doesn't match the mandate, replaying one that already ran, or
quietly redirecting the destination at the last moment. That gap is the runtime,
and that's what this is.

Signet sits at the last step before irreversible execution. The agent cannot
move money unless the action matches the signed chain, passes policy, hasn't
been executed before, and the enforcer issues a one-time, intent-bound
authorization. The enforcement isn't a check the agent could skip — it's a
*capability the agent doesn't hold*.

## The one idea

A reference monitor is only worth anything if it is **always invoked**. You
don't get that by checking the action; you get it by holding something the
action can't proceed without. So the design question is never "where do I put
the check" — it's *"what does the enforcer hold such that bypassing it makes
execution impossible, not merely non-compliant?"* The strength of the guarantee
on any rail is a function of what that held thing is.

This repo demonstrates the two ends of that spectrum:

- **Role 1 — XRPL multisign (cryptographic hard gate).** The settlement account
  is a 2-of-2 multisig: agent + enforcer. The enforcer contributes its
  signature only after the verifier approves, and only for the exact approved
  payment. Without it the transaction can't reach quorum, so the *ledger itself*
  is the fail-closed point. XRPL's per-account sequence number is the native
  on-ledger consume-once primitive. (`signet/authorizers/xrpl_cosigner.py`)

- **Role 2 — credential custody (rail-agnostic guardrail).** For rails where you
  can't be a cryptographic co-signer (cards, ACH, PSP APIs), the enforcer is the
  *sole holder* of the funding credential. The agent holds only the right to
  request. The broker mints a one-time, chain-bound credential only after the
  verifier approves, and the payment adapter refuses any call without one.
  (`signet/authorizers/mock_broker.py`)

Both plug into the *same* rail-agnostic verifier. The verifier decides; an
**Authorizer** turns that decision into a rail-specific necessary input. Adding
a rail (an EVM Safe, an MPC signer, a different PSP) means writing one
authorizer, not touching the kernel.

## What the verifier checks (in order)

Cheap, deterministic, attacker-unfalsifiable checks first; the single stateful
write (consume-once) last, so signature verification gates the nonce registry
and a flood of junk can't fill it.

1. Principal signatures on the Intent and Cart
2. Chain linkage — recompute every hash; does the Cart satisfy the Intent, does
   the Payment commit to *this* Cart (catches Cart-substitution)
3. Agent identity consistency across chain and runtime (confused-deputy)
4. Action permitted by the Intent and consistent at runtime
5. Freshness / TTL (verifier-authoritative clock, never the client's)
6. Revocation (checked at execution, not just issuance)
7. Context binding — runtime context hash must equal the Cart's committed
   context (catches recipient/destination/merchant substitution and redirects)
8. Exactness — runtime amount/currency equals the Cart, within the Intent cap
9. Policy — per-tx cap, recipient allowlist, currency, daily velocity
   (structuring), human-approval threshold
10. Atomic consume-once on the exact transaction (`chain_hash`) — replaying the
    identical bound transaction is rejected; distinct carts under one Intent are
    allowed, subject to velocity
11. Record velocity spend, issue the enforcer-signed `ExecutionToken`

Then a **hash-chained, enforcer-signed receipt** is appended. Anchoring the
receipt hash to an XRPL memo would additionally defeat equivocation without
revealing any payment detail.

## Threat model — what's in and what's out

**Caught (deterministic):** same- and cross-context replay, recipient/
destination substitution, amount tampering, Cart substitution, expired and
revoked mandates, currency substitution, chain-linkage breaks.

**Caught (stateful policy):** split/structuring via daily velocity, per-tx and
per-day caps, allowlist violations, human-approval thresholds.

**Out of scope — stated honestly.** Signet enforces that the *authorized chain*
executes faithfully. It does **not** defend against a prompt injection that
produces a fully self-consistent, legitimately-signed malicious chain (if the
principal's signing surface is tricked into authorizing a bad Cart, every hash
matches and Signet will pass it), principal key compromise, or agent–merchant
collusion. The mitigation for those lives upstream (prompt-playback
confirmation, signing-time review, human-present thresholds) — not here.
Manipulation that manifests as a recipient/amount/context change *at execution*
is caught; a malicious intent that was correctly signed is not.

## Run it

```bash
pip install -e ".[dev]"          # pydantic, pynacl, xrpl-py, fastapi, pytest

pytest -v                        # 17 attack demos
python -m demos.role2_demo       # rail-agnostic block/execute + receipt log
python -m demos.role1_xrpl_demo  # XRPL 2-of-2: agent-alone fails quorum, enforcer required
uvicorn signet.api:app --reload  # HTTP surface; docs at /docs
```

### XRPL note

The Role 1 cryptographic path (build → agent sign → enforcer co-sign → quorum
check) runs **offline** — that's what proves the property. Settling on live
testnet needs reachable XRPL endpoints; `demos/role1_xrpl_demo.py` prints the
exact faucet → `SignerListSet` → `submit_to_testnet` steps, and
`submit_to_testnet()` in `xrpl_cosigner.py` is the network call to run there.

## Layout

```
signet/
  canonical.py   deterministic JSON + hashing (JCS swap-in noted)
  crypto.py      Ed25519 (PyNaCl) + key registry
  models.py      Intent/Cart/Payment mandates, runtime, token, receipt
  chain.py       chain hashing + linkage verification + context binding
  nonce.py       SQLite atomic consume-once (sliding-window GC)
  revocation.py  revocation registry
  policy.py      caps, allowlist, currency, velocity, human-approval
  verifier.py    the 11-step kernel -> signed ExecutionToken
  receipts.py    hash-chained, enforcer-signed receipt log
  builder.py     mint signed mandate chains (+ attack-variant hooks)
  api.py         FastAPI surface
  authorizers/
    base.py          Authorizer interface
    mock_broker.py   Role 2: JIT credential custody
    xrpl_cosigner.py Role 1: XRPL multisign co-signer
demos/  role1_xrpl_demo.py, role2_demo.py
tests/  test_attacks.py
```

## Notes for production

- AP2 mandates ECDSA P-256 for the VC signatures; this PoC uses Ed25519 for
  consistency with XRPL wallets. The `crypto.sign/verify` seam is the only swap.
- `canonical.py` uses sorted-keys JSON; replace with RFC 8785 JCS for
  spec-faithful canonicalization.
- Consume-once and velocity use SQLite for a single process; back them with a
  store that gives you atomic check-and-set across instances (e.g. Redis/Postgres).
- The rail-agnostic generalization of Role 1 is **threshold signatures / MPC**:
  the enforcer holds one key share, so it becomes a mandatory co-signer for every
  chain at once rather than per-ledger. That's the next authorizer to write.
```
