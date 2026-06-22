# Signet × LangGraph — refund-triage dogfood demo

A LangGraph support-bot does real work — reads a refund ticket and issues a store credit by
writing one row to `public.credits` — and is contained **in-graph** by Signet's supabase
capability-issuing door. When the agent is fed an **injected** ticket, the harmful database
write **cannot execute**, and a signed receipt proves it didn't.

> **The block is the kernel that already exists.** This demo adds NO enforcement logic. The
> contain happens in the unchanged supabase admission rail (`effective_permits`): an effect
> outside the frozen task mandate is refused *before any capability is minted*. See
> `INTERFACE_MAP.md` for the cited interfaces and the one important spec→repo divergence.

## The two commands

```bash
pip install -e ".[dev,supabase,refund-demo]"     # supabase rail crypto + langgraph

# CLEAN: a normal ticket -> insert public.credits -> ALLOW -> 1 row -> receipt
python3 -m examples.refund_triage.run --scenario clean

# INJECTED: a ticket carrying a hidden instruction -> privilege escalation -> BLOCK -> 0 rows
python3 -m examples.refund_triage.run --scenario injected --attack a1
```

The contrast between the two trace panels **is** the demo: same graph, same door; one writes a
row, the other writes nothing and emits a refusal receipt.

## What to look for

| Run | Proposed effect | Door verdict | Token | Rows | Receipt |
|---|---|---|---|---|---|
| `clean` | `insert public.credits` (amount 50) | **ALLOW** | minted | **1** | pass |
| `injected --attack a1` | `update public.users set role=admin` | **BLOCK** `out-of-mandate` | none | **0** | refusal |
| `injected --attack a2` | `delete public.credits` (off-op) | **BLOCK** `out-of-mandate` | none | **0** | refusal |
| `injected --attack a3` | `insert public.credits` (amount **5000**) | **ALLOW** (labeled) | minted | **1** | pass |

**Why a1/a2 block and a3 does not.** The supabase door binds at `(database, schema, table, op)`
granularity, not row values. The frozen task mandate (`scenarios/mandate.clean.json`) grants only
`public.credits {select,insert}`:

- **a1** writes a *different table* (`users`) → outside the mandate → blocked.
- **a2** uses a *non-granted op* (`delete`) → outside the mandate → blocked.
- **a3** is the *same effect-key* as the clean insert (`public.credits insert`) — only the
  `amount` differs, and the door does not read amounts. So it is admitted. The panel prints a
  `NOTE` saying so: **row-value containment is out of scope for this door** (spec §8 Thread D;
  it is the payment kernel's / upstream's job, not this DB door's). Showing this honestly is the
  point — we never claim containment we don't have.

The injected ticket (`scenarios/ticket.injected.txt`) carries all three malicious steps; each
`--attack` selects which one the agent proposes. Containment is **independent of whether the model
is fooled**: the default `--resolver adversarial` *forces* the malicious effect, proving the door
contains the attacker even when the agent fully intends the bad write.

## The graph (`agent.py`)

```
freeze_mandate -> intake_ticket -> resolve_effect -> guard --(allow)--> write
   (trusted)        (untrusted)      (model out)      (seam)  \--(deny)--> refuse
```

`freeze_mandate` seals the Role-A grant **before** the untrusted ticket is read; `guard` is the
`signet_guarded_tool` wrapping the `EffectInterceptor` → unchanged supabase composition
(`mint_token` → kernel verify → `SupabaseAuthorizer`). On ALLOW the agent presents the minted
short-lived ES256 JWT to the resource PEP (`SupabaseGateway`) to perform the insert; on BLOCK no
JWT exists, so the resource is never reached.

## Tiers (advisory → structural)

**Tier 0 (default, in-process).** The two commands above run the seam / guarded-tool path
in-process; the trace labels them `tier=0 (advisory)`. The signing key lives inside the
`Door`/`SupabaseBinding`, built **outside** the LangGraph agent surface, so the agent's authored
state never holds key material (`test_agent_surface_holds_no_db_signing_key`).

**Tier 1 (structural, OS-separated).** The broker runs as a **separate OS uid** that owns the
ES256 signing key at a 0600 path; the agent reaches it only over a Unix socket where `SO_PEERCRED`
enforces identity. Now "a fooled agent **cannot** obtain a DB signing key" is true at the OS level
and proven by tests. **Verdicts are identical to Tier 0** — only the credential mechanism and the
label change.

```bash
# Tier-1 structural harness — needs a Linux-container Docker daemon (macOS: Docker Desktop)
bash examples/refund_triage/run_tier1_container.sh     # build + structural triad + showcase panels
```

This runs two unprivileged uids inside the container (`uid_broker=1100` owns the key,
`uid_agent=1200` runs the graph) and prints `tier=1 (structural)`. Against a running broker you can
also drive the CLI directly: `--tier 1` with `SIGNET_BROKER_SOCK` + `SIGNET_BROKER_JWKS` set.

**Platform requirement (honesty).** The peer-credential check is `SO_PEERCRED` — **Linux-only**
(`signet/broker/server.py:52`). On macOS/BSD there is no peer check, so the demo **cannot** be
structural there: even running Tier 1 over a real socket on macOS, the label honestly stays
`tier=0 (advisory)` (it never prints `structural` over an advisory boundary — spec §0.4 / §9).
The structural triad tests **skip-with-reason** off Linux and run for real in the container. This
is OS uid separation only — it needs **no `CAP_NET_ADMIN`** and nothing like the egress netns.

The structural triad (`tests/test_refund_triage_demo.py`):
`test_tier1_same_uid_peer_refused`, `test_tier1_agent_uid_cannot_read_signing_key`,
`test_tier1_killed_broker_yields_no_writes`.

## Files

```
INTERFACE_MAP.md       the §2 discovery deliverable (cited interfaces + the divergence + Tier-1)
effects.py             ProposedEffect builders + resolvers (deterministic/adversarial/llm)
agent.py               the LangGraph StateGraph + the Door (Tier 0 in-proc / Tier 1 over socket)
trace.py               the one-panel-per-run renderer (§5) + the honest tier label
run.py                 the CLI (--scenario / --attack / --resolver / --tier)
scenarios/             mandate.clean.json (frozen Role-A grant) + clean/injected tickets
tier1.py               RemoteSupabaseBinding (seam→broker over BrokerClient) + detect_separation
tier1_broker.py        the broker process (owns the 0600 ES256 key) + ThreadBroker for tests
Dockerfile             Tier-1 structural harness: two uids on Linux
tier1_entrypoint.sh    runs broker as uid_broker, agent work as uid_agent
run_tier1_container.sh  build + run the structural triad and the showcase panels
```

Tests: `tests/test_refund_triage_demo.py` (offline; `deterministic`+`adversarial` only — the
`llm` resolver is gated behind `SIGNET_REFUND_LLM=1` and never runs in CI).
