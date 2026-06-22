# Signet on-ramp — guard a LangGraph tool in ~5 minutes

`guard(tool, mandate)` wraps a LangGraph tool so its effects cross the Signet seam; `Mandate` is a
fluent builder for the allow-list; `SignetConfig` is the deployment knob. Three names, one import:

```python
from signet import guard, Mandate, SignetConfig
```

This is a **facade** — it adds no enforcement and changes no behavior, it just constructs and wires
the pieces the demo rails already provide. The default is **Tier 0, advisory**, and it says so.

## Install

```bash
pip install -e ".[refund-demo]"      # langgraph + the supabase rail crypto (pyjwt/cryptography)
```

## The 5-minute path — declare, wrap, run, see the block

```python
from typing import TypedDict
from signet import guard, Mandate

# 1. Declare what the agent may do.
mandate = (Mandate("support-bot", task_id="refund-001")
             .allow_db("public.credits", ops=("select", "insert"))
             .build())

# 2. Your DB tool — its body runs only if Signet ALLOWs the effect.
def db_write(**args): ...

# 3. Wrap it (Tier 0 advisory by default).
safe_db_write = guard(db_write, mandate)

# 4. Drop it into a graph and run. An injected ticket tries to escalate privileges:
from langgraph.graph import StateGraph, START, END
class S(TypedDict, total=False): verdict: object
def attempt(state):
    return {"verdict": safe_db_write(database="app", schema="public", table="users",
                                     op="update", set="role=admin")}
g = StateGraph(S); g.add_node("attempt", attempt)
g.add_edge(START, "attempt"); g.add_edge("attempt", END)
r = g.compile().invoke({})["verdict"]
print(r.outcome.upper(), r.cause)          # -> BLOCK  out-of-mandate
```

The escalation is outside the frozen mandate, so it is **BLOCKED** before any capability is minted.
Runnable: `python3 -m examples.guard_db_block`.

## Two rails, one session

Guarding two tools with the **same mandate** routes both through one interceptor — one session:

```python
mandate = (Mandate("support-bot", task_id="refund-001")
             .allow_db("public.credits", ops=("select", "insert"))
             .allow_egress("payments.internal")          # only this host may be reached
             .build())

safe_db     = guard(db_tool, mandate)                    # capability-issuing rail (mints a JWT)
safe_egress = guard(egress_tool, mandate, rail="egress") # effect-performing rail (proxy; mints nothing)

safe_egress(host="attacker.example", port=443)           # -> BLOCK (off-allowlist, advisory)
```

The DB and egress doors are different archetypes and stay distinct: the DB rail mints a scoped JWT
the agent presents to Postgres; the egress rail's proxy connects-or-refuses and the agent holds
nothing (`check_ref is None`). `guard()` never mints a token for an egress effect.

## Advisory by default; structural by config

```python
guard(tool, mandate)                                   # Tier 0 advisory (local dev) — labeled "0 (advisory)"
guard(tool, mandate, signet=SignetConfig(              # DB rail structural (OS-separated broker)
        tier=1, broker_socket="/run/signet.sock", jwks_path="/run/signet.jwks"))
```

`SignetConfig().label()` reports the requested tier; the **authoritative** structural claim is still
made at run time (`detect_separation`) — a same-uid peer or a non-Linux host honestly degrades to
advisory. The egress rail is advisory on this build (structural egress needs a netns — out of scope).

## Errors that teach

| You did | You get |
|---|---|
| `Mandate(...).allow_db("credits")` | `MalformedTargetError: db target 'credits' is malformed: expected 'schema.table' …` |
| `Mandate(...).allow_egress("https://x/y")` | `MalformedTargetError: egress host '…' is malformed: expected a bare hostname …` |
| `guard(t, m, rail="ipfs")` | `UnknownRailError: unknown rail 'ipfs': the on-ramp wires ['egress', 'supabase'] …` |
| a rail extra missing | `MissingRailExtraError: … Fix: pip install -e ".[supabase]"` |

## Examples gallery (`examples/`)

```bash
python3 -m examples.guard_db_block   # guard a DB write; out-of-mandate -> BLOCK
python3 -m examples.guard_egress     # guard egress; exfil to off-allowlist host -> BLOCK
python3 -m examples.combined         # two rails, one session (DB ALLOW + egress BLOCK)
```

## What's stable vs internal

Stable: exactly `guard`, `Mandate`, `SignetConfig` (re-exported as `signet.*`). `guarded_door` /
`build_onramp_door` are available from `examples.onramp` for door lifecycle and inspection. Everything
behind the facade — the kernel, the seam, the rails, the brokers — is internal and may change.

The on-ramp wires the repo's demo rails (`examples/refund_triage`), so it is available from the dev
checkout. `Mandate`/`SignetConfig` are import-light; `guard()` pulls the demo builders lazily and
raises a teaching error if a rail's extra is missing. See `../refund_triage/INTERFACE_MAP.md`
("On-ramp") for every interface cited `file:line`, and the design decisions recorded there.
