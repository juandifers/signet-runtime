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

## Spec 04 — Operator control, in-page panel, voice

Three **additive, flag-gated** layers on top of the Spec 02/03 demo. Each is OFF by default
and `run_interactive.py` behaves exactly as before with every flag unset; if any layer
destabilizes the agent it simply stays off.

**Part 1 — operator-driven scope control (default ON).** Spec 02 fired the scope switch from a
hook (hands-free). Now a **real human** drives it: when the agent is BLOCKED on the YC click,
the run **halts between steps** and prompts on stdin; the typed request is fed to the unchanged
`select_scope`. Blocking inside the `await`ed `on_step_start` hook *is* the pause (browser-use
checks `state.paused` before the hook, so `agent.pause()` from a hook lands one step late — the
awaited hook is the exact, race-free barrier). The operator cannot exceed the ceiling: the
request still goes planner → frozen menu key → validated setter. `SIGNET_AUTO_GRANT=1` restores
the hands-free arc. *Proof:* `python -m examples.browser_demo.selfcheck_operator`.

**Part 2 — in-page policy panel (`SIGNET_INPAGE_PANEL=1`).** Paints the policy (ceiling, scope
lanes, decision feed) as a fixed overlay **on the agent's own page**, alongside its actions.
The Spec 03 separate-page sidebar stays as the default/fallback. The overlay is **inert**:
non-interactive elements only, `position:fixed`, `pointer-events:none`, `aria-hidden`,
`role="presentation"`; injected via CDP `addScriptToEvaluateOnNewDocument` (survives
navigation), state pushed each step via `Runtime.evaluate` (no cross-origin fetch). *Acceptance
gate* (`selfcheck_inpage.py`, real Chromium on a localhost fixture): interactive selector-map
indices are **byte-identical** with the panel on/off, the overlay never enters the selector
map, and it paints. Kept opt-in per spec.

**Part 3 — push-to-talk voice (`SIGNET_VOICE=1`).** A second front-end to the *same*
`select_scope` intake: ENTER to record, speak, ENTER to stop; mic → temp wav (`sounddevice`) →
ElevenLabs `speech_to_text` `scribe_v2` → transcript → `select_scope`. Needs `ELEVENLABS_API_KEY`
and the `elevenlabs` + `sounddevice` packages. **Total graceful degradation**: any failure
(missing libs/key, mic error, empty audio, STT/network error) prints one line and falls back to
the typed Part-1 prompt — the run never crashes or hangs. TTS speak-back was left out (optional).
*Proof:* `python -m examples.browser_demo.selfcheck_voice`.

```bash
python -m examples.browser_demo.run_interactive                      # Part 1 (operator-driven) + Spec 03 sidebar
SIGNET_INPAGE_PANEL=1 python -m examples.browser_demo.run_interactive # + in-page overlay (Part 2)
SIGNET_VOICE=1 python -m examples.browser_demo.run_interactive        # + push-to-talk (Part 3)
SIGNET_AUTO_GRANT=1 python -m examples.browser_demo.run_interactive   # legacy hands-free arc
```

## Spec 05 — Live steering (always-on) + refuse-the-operator

**Part 1 — always-on policy steering (default ON).** The operator changes the *active scope* at
**any** step (not only on a block), routed through `select_scope` and clamped to the frozen
ceiling — a spoken/typed request can only ever select a pre-authorized lane.

- *Input owner:* a single **run-owned daemon thread** blocks on the operator (voice if
  `SIGNET_VOICE=1`, else typed) and marshals each request onto the event loop via
  `run_coroutine_threadsafe`, so `select_scope` and the `mandate.active` swap run **single-writer
  on the loop the gate reads from** — a stronger guarantee than a lock (no half-applied-swap
  window; a lock is kept too). The gate reads `active` fresh, so a swap lands on the next action
  with no restart. Steering is owned by the **run**, never the page (the in-page overlay is
  `pointer-events:none` — a clickable control there would re-pollute the agent's element index).
- *One stdin owner, always:* `LIVE_STEER` mode → the channel owns stdin and the on-block path
  degrades to a printed notice; `AUTO_GRANT` → no reader; `SIGNET_LIVE_STEER=0` → the Spec 04
  on-block prompt is the sole reader. Never two readers.
- *Refuse-the-operator beat:* an unmappable / out-of-ceiling request is **REFUSED**, `active`
  unchanged, with a **signed receipt**, and rendered as a loud amber **“OPERATOR REQUEST REFUSED
  — outside ceiling: …”** row in **both** the in-page overlay and the separate-page sidebar.
- *Proofs:* `selfcheck_steer.py` (real channel thread: mid-run flip, refusal+receipt, voice/typed
  routing) and `selfcheck_refusal_ui.py` (real Chromium: the refused row shows in both panels).

**Part 2 — task steering (`SIGNET_TASK_STEER=1`, OFF by default).** The operator redirects the
agent's *goal* mid-run by prefixing a request with `task:` / `goal:` / `do:` — e.g.
`task: go to the admin panel and delete the account`. This is **untrusted instruction**: the
agent may attempt it, but **every resulting action is still gated** against `mandate.active`, so
an out-of-ceiling action is **BLOCKED on screen with a receipt**. Task steering changes *intent*,
never *authority*. Mechanism: browser-use 0.13.1's `Agent.add_new_task(goal)`, applied only at a
step boundary (`on_step_start`), fully guarded (a failure prints and is skipped — never crashes
the run). The goal is queued by the channel's `pre_apply` interceptor so it is never mistaken for
a policy steer. *Proof:* `selfcheck_task_steer.py` proves the **gating invariant** offline (any
injected goal stays clamped; out-of-ceiling BLOCKED + receipt, in-ceiling ALLOWED + receipt) and
the routing/injection units. The live agent arc (a real injected goal changing what the agent
*attempts*) is **eyeballed on the user's machine** — it needs a network page-load this sandbox's
DNS can't serve. Ships opt-in; if it fights the library on your machine, leave the flag off —
Part 1 still delivers live steering.

```bash
python -m examples.browser_demo.run_interactive                    # always-on steering (default) + sidebar
SIGNET_VOICE=1            python -m examples.browser_demo.run_interactive   # talk to steer
SIGNET_INPAGE_PANEL=1     python -m examples.browser_demo.run_interactive   # + in-page overlay
SIGNET_TASK_STEER=1       python -m examples.browser_demo.run_interactive   # + redirect the goal (gated)
SIGNET_LIVE_STEER=0       python -m examples.browser_demo.run_interactive   # revert to Spec 04 on-block prompt
```

### Environment notes (the user's machine)
- **Voice:** `pip install elevenlabs sounddevice` + `ELEVENLABS_API_KEY` in the repo `.env`, and a
  one-time macOS **microphone** permission grant to the terminal. Test mic capture alone first
  (record 2s → transcribe) before a full run.
- The steering channel is a **focused control terminal** (press ENTER to talk / type a line) — it
  deliberately avoids a global OS hotkey, which on macOS can need **Accessibility** permission and
  fail silently on an unfamiliar machine on stage.

## Files

| file | role |
|------|------|
| `web_mandate.py` | `WebMandate` builder → frozen **ceiling + scope menu**; only `active` mutates (Spec 02) |
| `gate.py` | pure `decide(scope, action_type, target, *, provenance, click_destination=None)` (default-deny) |
| `guarded_tools.py` | `build_tools` → pruned `Tools()` of four guarded actions; `resolve_click_destination` reads a node's href |
| `scopes.py` | `select_scope` — contained planner (LLM + keyword fallback) → deterministic activation |
| `session.py` | wraps the real `signet.ReceiptLog`; one receipt per decision + `scope_switch`; writes `session.json` |
| `run.py` | Spec 01 entrypoint (single-scope spine) |
| `run_interactive.py` | Spec 02/03/04 entrypoint (two-tier + operator-driven switch + flag-gated panel/voice) |
| `operator.py` | Spec 04 Part 1 — operator stdin intake (async + sync twins), unified voice-or-typed |
| `inpage_panel.py` | Spec 04 Part 2 — inert in-page overlay over CDP (survives navigation); Spec 05 REFUSED row |
| `voice.py` | Spec 04 Part 3 — push-to-talk capture (sync core + async wrapper), ElevenLabs `scribe_v2` |
| `steering.py` | Spec 05 Part 1 — always-on live steering channel (daemon thread → loop marshaling) |
| `task_steer.py` | Spec 05 Part 2 — task-redirect routing + guarded `Agent.add_new_task` injection |
| `selfcheck.py` / `selfcheck_scopes.py` | offline gate/receipt verification (acceptance, no LLM/browser) |
| `selfcheck_operator.py` / `selfcheck_voice.py` | offline proof of Spec 04 Parts 1 & 3 (no LLM/browser) |
| `selfcheck_steer.py` / `selfcheck_task_steer.py` | offline proof of Spec 05 Parts 1 & 2 (real channel thread / gating invariant) |
| `selfcheck_inpage.py` | Spec 04 Part 2 gate — index-stability measurement (real Chromium, localhost) |
| `selfcheck_refusal_ui.py` | Spec 05 Part 1 — refused row shows in BOTH panels (real Chromium) |

## Built in later specs / still deferred

- **Live sidebar** — built in Spec 03 (separate-page) and Spec 04 Part 2 (in-page overlay).
- **Voice** — built in Spec 04 Part 3 (push-to-talk via ElevenLabs `scribe_v2`).
- **Structural enforcement** *(still deferred)* — the out-of-process sole-path performer that
  upgrades the `advisory` label to a real boundary (the netns analogue for the browser). Every
  Spec 01–04 decision remains `tier: "0 (advisory)"`.
- **Receipt-schema generalization** *(still deferred)* — browser-native field names instead of
  the AP2-payment-shaped `ReceiptLog`/`Receipt` (see the deferred-item note above).
- **TTS speak-back** *(optional, not built)* — spoken confirmation of the granted scope.
