# Spec 01 — Guarded browser spine

A [`browser-use`](https://github.com/browser-use/browser-use) agent that can act on a
web app **only** by passing each proposed action through a **frozen, default-deny
`WebMandate`**. Allowed actions perform; disallowed actions return a structured refusal
the agent re-plans around; **every decision writes a real signet receipt**; the run
emits a `session.json` in the existing refund-triage viewer shape.

This proves the core architecture end-to-end. **Scope-switching, the live sidebar, and
voice are later specs and are *not* built here.**

## How it works

```
LLM ──▶ guarded Tools()  ──▶  gate.decide(frozen WebMandate, action, target)
        (navigate/click/        │
         type/extract;          ├─ ALLOW ─▶ perform the REAL browser effect ─▶ allow receipt
         the ONLY actions)      └─ BLOCK ─▶ structured "BLOCKED: …" refusal  ─▶ block receipt
                                              (no effect runs; agent re-plans)
        every decision ─▶ signet ReceiptLog ─▶ session.json (viewer shape)
```

- **Interception = custom guarded tools, not lifecycle hooks.** `guarded_tools.build_tools`
  registers our own `navigate / click / type / extract` actions on a `Tools()` and then
  **prunes the registry down to exactly those four plus `done`**, so the agent has no
  ungated path to a browser effect. The gate runs at the front of every tool body, before
  any effect. `on_step_start` is used *only* to snapshot state into the session log.
- **Default-deny.** Anything not explicitly allowed by the frozen mandate is blocked.
- **Frozen before input.** `WebMandate(...).build()` returns an immutable `FrozenWebMandate`
  (a frozen dataclass over `frozenset`s), built before `agent.run(...)` and before the agent
  reads any page content. Nothing observed at runtime can mutate it.
- **Provenance-monotonicity.** A `navigate` target the agent supplies is treated as
  page-provenance (untrusted): it can only be *denied* against the allowlist, never *added*
  to it. This is structural — the frozen object has no mutator — and the gate states it in
  the block reason.

## Honesty labels (read these)

- **Enforcement is in-process / advisory today.** This gate is containment UX + tamper-evident
  receipts, not an enforcement boundary. A determined in-process agent could reach the browser
  by means other than these tools. The structural upgrade — exactly mirroring the egress rail's
  `ONLY-DOOR-OR-DECLARE` — is an **out-of-process performer that is the *sole path* to the
  browser** (the netns analogue). Until that exists, every decision is labelled `tier: "0
  (advisory)"`, `tier_structural: false`.
- **Receipts are real; crypto is research-grade.** Decisions are signed and hash-chained with
  the unchanged kernel `signet.receipts.ReceiptLog` (Ed25519, a local in-process keypair, no
  external anchor). The crypto is isolated to the kernel and production-swappable (see the repo
  `CLAUDE.md` "Production swaps"). The browser rail mints **no capability token**
  (`token_minted` is always `false`) — like egress, it is an effect-performing door that holds
  nothing.

## Run

```bash
pip install "browser-use==0.13.1"          # already pulls its own LLM clients + openai
echo 'OPENAI_API_KEY=sk-...' >> .env        # repo-root .env; read at startup, NEVER hardcoded
python -m examples.browser_demo.run         # live agent, headless=False, writes session.json
```

`run.py` loads the repo-root `.env` (via `python-dotenv`) so `OPENAI_API_KEY` is read from
there. It hardcodes the demo `task`, `start_url` (`https://example.com`), model
(`gpt-5.4-mini`, override with `SIGNET_DEMO_MODEL`), and the mandate — all kept easy to swap
at the top of the file. The demo grants `navigate/extract/click` on `example.com` and
deliberately withholds `type`. Expected trace:

| # | action | target | decision | why |
|---|--------|--------|----------|-----|
| 1 | navigate | example.com | **ALLOW** | in allowlist; performs |
| 2 | extract | example.com | **ALLOW** | reads the page |
| 3 | navigate | iana.org (the "More information" link) | **BLOCK** | off-allowlist; refusal, agent re-plans |

### Offline self-check (no LLM, no browser)

```bash
python -m examples.browser_demo.selfcheck
```

Exercises the gate + real receipts deterministically: in-scope ALLOW, off-allowlist BLOCK,
disallowed-action-type BLOCK, unrecognized-action default-deny, subdomain match, and proves
every receipt **verifies offline** via the real `ReceiptLog.verify` and forms a valid hash
chain. This is the CI-friendly proof of acceptance #2–#5.

## Viewing the trace

`session.json` matches the refund-triage viewer contract
(`examples/refund_triage/viewer/index.html`). Open that `index.html` and use
**"Load session JSON…"** to load `examples/browser_demo/session.json`. The checked-in
`session.json` is an **offline gate sample** (`performed` reports the gate verdict only, no
browser bytes moved); a live `run` overwrites it with real per-effect results.

## Spec 02 — Scope menu + element-level click policy

Spec 01 blocked an off-domain *navigation* but allowed the *click* that caused it — the gate
caught the consequence, not the cause. Spec 02 closes that and adds a runtime-selectable scope.

**Element-level click policy (Part A).** The guarded `click` now reads the clicked element's
navigable destination from the browser-use node (`node.attributes["href"]`, walking up
`parent_node` so a click on a `<span>` inside an `<a>` still resolves; relative hrefs are
`urljoin`'d against the current page). The gate decides on that **destination domain**, so an
off-scope link is **blocked at the click** — `ClickElementEvent` is never dispatched and the
browser never leaves the site.
*Honesty:* a JS/SPA element with no statically resolvable href is a documented gap. Such a
click falls back to the scope's `click_policy` (`in_domain_only` → deny; `allow_unresolved`
→ allow with a receipt note), and the navigate-domain gate remains the backstop. Best-effort
at the click, advisory — same framing as the egress rail.

**Two-tier mandate (Part B).** `WebMandate` now has a frozen **ceiling** (max authority ever)
and a frozen **menu of named scopes**, each validated ⊆ ceiling at `.build()` (domains within,
actions ⊆, click_policy no more permissive). Only `mandate.active` (a menu key) mutates at
runtime. A `Scope` = `{name, allowed_actions, allowed_domains, click_policy}`; the gate decides
against the active scope, read fresh each call.

```python
WebMandate("demo-agent", task_id="browse-scopes-001")
  .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate","click","extract"])
  .scope("tour",       domains=["wikipedia.org"],                   actions=["navigate","extract","click"], click_policy="in_domain_only")
  .scope("learn_more", domains=["wikipedia.org","ycombinator.com"], actions=["navigate","extract","click"], click_policy="in_domain_only")
  .default_scope("tour").build()
```

**`select_scope` (Part C).** `select_scope(mandate, request)` maps free text → exactly one
frozen menu key (a constrained LLM call reusing `OPENAI_API_KEY`, with a deterministic
keyword-match fallback), then **deterministically activates** it (sets `mandate.active`) and
writes a `scope_switch` receipt. The planner is contained: it can only ever return a frozen
menu key or `none` — it cannot author or widen a scope. `none`/unknown → REFUSE, `active`
unchanged.

**Live demo:** `python -m examples.browser_demo.run_interactive` (full OpenAI models). Arc:
start in `tour` → navigate/extract Wikipedia (ALLOW) → click the ycombinator.com link
(**BLOCK at the click**) → an `on_step_start` hook calls `select_scope("…YC…")` once (flip to
`learn_more`) → retry the same click (**ALLOW**) → navigate google.com (**BLOCK under every
scope** — the ceiling wall). The hook only snapshots state and flips the active key; it never
authors authority.

**Offline proof:** `python -m examples.browser_demo.selfcheck_scopes` verifies all of the above
deterministically (no browser, no LLM), incl. destination resolution from stub nodes and the
receipt hash chain.

> **Known deferred item:** the real `ReceiptLog`/`Receipt` schema is AP2-payment-shaped
> (`payment_status`, `payment_ref`, …). We record browser-native facts onto it (action, target,
> outcome, chain, `active_scope`); generalizing the field names beyond payments is deferred —
> not refactored here.

## Files

| file | role |
|------|------|
| `web_mandate.py` | `WebMandate` builder → frozen **ceiling + scope menu**; only `active` mutates (Spec 02) |
| `gate.py` | pure `decide(scope, action_type, target, *, provenance, click_destination=None)` (default-deny) |
| `guarded_tools.py` | `build_tools` → pruned `Tools()` of four guarded actions; `resolve_click_destination` reads a node's href |
| `scopes.py` | `select_scope` — contained planner (LLM + keyword fallback) → deterministic activation |
| `session.py` | wraps the real `signet.ReceiptLog`; one receipt per decision + `scope_switch`; writes `session.json` |
| `run.py` | Spec 01 entrypoint (single-scope spine) |
| `run_interactive.py` | Spec 02 entrypoint (two-tier + live scope switch) |
| `selfcheck.py` / `selfcheck_scopes.py` | offline gate/receipt verification (acceptance, no LLM/browser) |

## Deferred to later specs (do not build here)

- **Live sidebar** — streaming the decisions to a live UI during the run.
- **Voice.**
- **Structural enforcement** — the out-of-process sole-path performer that upgrades the
  `advisory` label to a real boundary (the netns analogue for the browser).
- **Receipt-schema generalization** — browser-native field names instead of the
  AP2-payment-shaped `ReceiptLog`/`Receipt` (see the deferred-item note above).
