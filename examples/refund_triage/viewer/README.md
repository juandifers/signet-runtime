# Signet Session Viewer

A self-contained, **offline**, **read-only** HTML page that renders a Signet *session* — the frozen
mandate, every effect the agent proposed, each gate verdict with its reason, and each receipt — so a
person watching (a room, or you) can see what was allowed, what was blocked, and **why**.

It is the stage demo *and* the first cut of the product's observability layer. **It only reads
emitted data; it changes no behavior** — it makes no broker call, mints nothing, enforces nothing.

```
┌──────────────────────────────┐     emits      ┌────────────────┐    renders    ┌───────────────┐
│ examples.refund_triage.run   │  ───────────▶  │  session.json  │  ──────────▶  │  index.html   │
│ (the unchanged door + graph) │   session.py   │ (§4 contract)  │   (inlined)   │  (this page)  │
└──────────────────────────────┘                └────────────────┘               └───────────────┘
```

## Two steps

```bash
# 1. produce a session JSON from the demo (re-runs the unchanged door; writes nothing new to the run)
python3 -m examples.refund_triage.session            # -> viewer/session.json  (+ inlines it into index.html)

# 2. open the viewer — double-click the file, or:
open examples/refund_triage/viewer/index.html        # macOS  (Linux: xdg-open)
```

The page opens by **double-click** (`file://`) and renders the latest session with **zero network
requests** — the session is *inlined* into `index.html` between the `/*SIGNET_SESSION_*/` markers by
the emitter. To view a different run, use **“Load session JSON…”** (a local `FileReader` — still no
network) and pick any `session.json`. **Reset** re-renders the inlined default.

> The emitter forces the four-effect showcase (clean + a1 + a2 + a3). To emit at Tier 1 (structural),
> run it under a live broker (`SIGNET_BROKER_SOCK` + `SIGNET_BROKER_JWKS` set) with `--tier 1`; the
> tier label stays **honest** regardless (see below). `--no-inline` writes only the JSON.

## What it shows

- **Session header** — principal, frozen task/db, and the **tier badge** shown *exactly as emitted*
  (`0 (advisory)` amber / `1 (structural)` green). The viewer **never upgrades** the tier.
- **Granted scope** — the frozen Role-A allow-list as `rail · action · target` chips.
- **Effect timeline** — one card per proposed effect, in order: the proposed `rail · action · target`
  + detail, the **verdict** (ALLOW green / BLOCK red / ESCALATE amber, legible across a room), the
  reason, whether a token was minted, what was performed (rows written / blocked), the receipt id +
  `✓ signed`, and any **honest note** verbatim (e.g. the A3 “row-value containment out of scope”).
  Each card has a `▸ detail` expander (escalation source, full receipt id, verify state).

For the refund demo that reads: **clean ALLOW** (insert credits, 1 row) · **a1 BLOCK** (UPDATE
users, out-of-mandate, 0 rows) · **a2 BLOCK** (DELETE credits, out-of-mandate, 0 rows) · **a3 ALLOW**
with its granularity note.

## Honesty / safety properties

- **No secret is ever serialised or rendered.** The rail capability ref (`Decision.check_ref` — the
  short-lived ES256 JWT) is deliberately **not** written to the session JSON; the viewer sees only
  `token_minted` (a bool). (`session.py` docstring; the JWT lives at `seam.py:51`.)
- **Read-only.** The emitter re-runs `run_scenario` and serialises the result; it authors no verdict.
- **Offline.** No `fetch`/XHR, no external `src`, no CDN, no web font — verifiable by `grep` over
  `index.html`. On `file://` the only load is the document itself.
- **Session-first / multi-rail ready — and exercised.** The viewer iterates `effects[]` and renders
  per `rail` / `performed`, so an egress effect (`{"rail":"egress","performed":{"egress":"blocked"}}`)
  renders with **no viewer change** (Session Viewer spec §6). This is now real, not hypothetical:
  `python3 -m examples.refund_triage.session --combined` emits `session.combined.json` (a DB **ALLOW**
  + an egress **BLOCK** on two rails); load it via **“Load session JSON…”** to see both rails side by
  side — the DB row written, the exfil blocked, the egress effect labeled `advisory`.

## Field provenance (the emitter reads only real emitted data)

All in `examples/refund_triage/session.py`, off the `RunResult` the unchanged door produces:

| session field | source | citation |
|---|---|---|
| `mandate.principal` | `agent.AGENT_ID` | `agent.py:48` |
| `mandate.granted_scope` | `door.mandate.grants` (`DbGrant.schema/.table/.ops`) | `agent.py:163-167` |
| `effects[].proposed` | `RefundCase.proposed_effect().{tool,args}` | `effects.py:54-59` |
| `effects[].decision` | `RunResult.outcome` (seam `Outcome` value) | `agent.py:240`, `seam.py:33-37` |
| `effects[].reason` | `RunResult.cause` (`Decision.cause`) | `agent.py:242`, `seam.py:42` |
| `effects[].token_minted` | `RunResult.token_minted` | `agent.py:246` |
| `effects[].performed` | `RunResult.state["write"]` | `agent.py:192-210` |
| `effects[].receipt_id` | `RunResult.receipt_id` (`Receipt.receipt_hash`) | `agent.py:248`, `receipts.py:43` |
| `effects[].receipt_verified` | `door.receipts.verify(decision.receipt)` | `trace.py:68-74` |
| `effects[].note` | `RefundCase.note` (A3 granularity note) | `effects.py:95-96` |
| `tier` | `trace._tier_label` / `Separation.label` | `trace.py:17-23` |

## Files

```
session.py            additive emitter: runs the scenarios -> session.json -> inlines into index.html
index.html            the self-contained offline viewer (inlined session + FileReader picker)
session.json          the emitted single-rail session (4 effects; the §4 contract; regenerated each run)
session.combined.json the two-rail session (DB ALLOW + egress BLOCK); emit with `--combined`, load via picker
```
