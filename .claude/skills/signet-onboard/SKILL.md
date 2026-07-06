---
name: signet-onboard
description: >-
  Turn a workflow + a target website into a ready-to-run guarded-browser-agent demo for the Signet
  browser spine, in minutes. Generates a frozen path-aware WebMandate (ceiling + default-deny lane
  menu with the irreversible step walled OUT of the ceiling), a run_<app>.py from the run_saucedemo
  template, an offline self-check, a demo runbook, and an honest talk track — all into
  examples/browser_demo/. Use when the user says "onboard <app>", "make/build a policy for <site>",
  "scaffold a guarded agent for <workflow>", "re-point the agent at <workflow>", or hands you a
  workflow + URL to demo. If the workflow is API/data/ticket-shaped (not browser-driven), it instead
  scaffolds the LangGraph guarded-tool pattern. Additive, confined to the demo dir, no kernel edits.
---

# signet-onboard — workflow + site → guarded browser demo, fast

You are being handed a real workflow at an event and must build + present a guarded agent quickly.
This skill removes the hand-editing of `run_*.py` under pressure. **Speed and not overclaiming are
the goals.** Confirm nothing with the user that you can infer — generate, then report what you chose.

## Inputs (parse from the user's natural-language request)
- **Target app / URL** (e.g. `https://www.saucedemo.com/`).
- **One-paragraph workflow** (what the agent should do).
- **Optional explicit lanes** (e.g. "look / shop / checkout"). If absent, infer them (§3).

## Outputs (all into `examples/browser_demo/`, additive, flag-off-safe)
1. `run_<app>.py` — a `RunConfig`-driven entry point (from `templates/run_app.py.tmpl`).
2. `selfcheck_<app>.py` — offline structural proof (from `templates/selfcheck_app.py.tmpl`).
3. A runbook `<App>_runbook.md` (from `templates/runbook.md.tmpl`).
4. A talk track `<App>_talk_track.md` (from `templates/talk_track.md.tmpl`).
Pick `<app>` = a short lowercase slug of the app (e.g. `saucedemo`, `acmeshop`).

---

## Step 0 — Ground in the REAL code first (don't invent shapes)
Read these before generating; conform to exactly what exists:
- `examples/browser_demo/web_mandate.py` — the real `WebMandate` builder: `.ceiling(domains=,
  actions=, click_policy=, path_allow=)`, `.scope(name, domains=, actions=, click_policy=,
  path_allow=)`, `.default_scope(name)`, `.build()`. Actions ⊆ `{navigate, click, type, extract}`.
  Click policies: `in_domain_only` (deny unresolved clicks) < `allow_unresolved`. Scope
  domains/actions are validated ⊆ ceiling at build; **paths are NOT** (the gate's dual-check is the
  guarantee). `path_allow` defaults to `("/*",)`.
- `examples/browser_demo/run_saucedemo.py` — the canonical template this mirrors (mandate, TASK,
  `BROWSER_ALLOWED_DOMAINS`, `_SCOPE_GOALS`, `config()`, `main()`).
- `examples/browser_demo/gate.py` — so your policy matches what the gate enforces: action-type →
  domain → (click destination) → **path dual-check (ceiling AND scope)** → current-page backstop;
  default-deny throughout. Note `resolve_path` drops `?query`/`#fragment` before glob-matching.
- `examples/browser_demo/run_interactive.py` — the shared loop your `RunConfig` plugs into
  (live steering default ON, `on_steer` already announces+refuses unmapped requests, `scope_goals`
  nudge, task-steer injection).

## Step 1 — Browser-shaped or not?
**Browser-shaped** = the workflow is driven by visiting URLs and clicking/typing/reading pages
(shopping, booking, form-filling, dashboards). Proceed to §2.

**NOT browser-shaped** = API calls, DB queries, ticket triage, internal RPC, message sending with no
page (e.g. "approve refunds via our API", "merge PRs", "triage Jira"). **Do not force a browser run.**
Instead:
- Emit `examples/browser_demo/<app>_guarded_tool.py` from `templates/guarded_tool_stub.py.tmpl` (a
  minimal `signet_guarded_tool` over an `EffectInterceptor`), and
- Write a short note (in your reply + a `<App>_runbook.md`) pointing at
  `integrations/langgraph/guarded_tool.py` as the path to apply Signet there (mandate + guarded tool
  + receipt; ALLOW/BLOCK/ESCALATE→`interrupt`). Then stop — skip §3–§6.

## Step 2 — (browser) Read the site's URL shape
You need the **paths** the workflow touches and, crucially, the **path of the irreversible step**.
For a known site, use what you know; otherwise infer conventional paths from the workflow and SAY
they're assumptions to verify live. Identify:
- the **landing / login** path (almost always `/`),
- the **working-area** paths (catalog/list/detail — often globbable, e.g. `/inventory*`),
- a **reversible sensitive** step if any (a form / review page, e.g. `/checkout-step-*`),
- the **irreversible / destructive** path(s) — *place order, pay, delete, transfer, publish, submit
  final* — this is **THE WALL** (e.g. `/checkout-complete.html`).

## Step 3 — Design the policy (lanes + the wall)
Infer a small default-deny menu under one ceiling. Default to **three lanes**; collapse to two if the
workflow has no read-only or no sensitive phase.

| lane (rename to fit) | actions | click_policy | paths | role |
|---|---|---|---|---|
| read-only (`look`/`browse`/`read`) | `navigate, extract` | `in_domain_only` | landing + working area | presentation / "just looking" — can't click or type |
| **operate (DEFAULT)** (`shop`/`work`/`act`) | `navigate, click, type, extract` | `allow_unresolved` | landing + working area | the main lane; **must include login/landing so first steps work** |
| sensitive (`checkout`/`submit`/`review`) | all four | `allow_unresolved` | operate paths + the reversible sensitive paths | the operator steers UP to it live |

Rules:
- **CEILING** = union of every lane's domains/actions/paths, **MINUS the irreversible path(s)**. The
  ceiling's `actions` = all four; its `path_allow` = all reachable paths *except the wall*. This is
  what makes the wall structural: absent from the ceiling ⇒ no lane can include it (paths aren't
  subset-validated, but the gate checks the ceiling too, so it's unreachable).
- **default_scope = the operate lane** (so login / first navigation are permitted out of the box).
- Use `allow_unresolved` for any lane that must click app buttons (login/add/submit are JS
  `<button>`s with no static href; `in_domain_only` would block them). Use `in_domain_only` only for
  pure read-only lanes. The **current-page path check is the real containment**, not the click policy.
- Lane **names are the operator's trigger words** — pick distinctive, natural ones (the live planner
  is an LLM; the keyword fallback matches on the name + domain label). Avoid near-synonyms that the
  planner could confuse.
- **scope_goals** (optional): if entering a lane should make the agent *do* something (a switch is
  silent to the agent), add a one-shot goal per lane. Mirror saucedemo's checkout goal ("open the
  cart, report it, walk the form, do NOT finish").

## Step 4 — Emit `run_<app>.py` (from `templates/run_app.py.tmpl`)
Fill every `{{...}}`. Conventions:
- `{{PATH_CONSTANTS}}` — module-level lists, e.g. `_CEILING_PATHS = ["/", "/items*", "/review.html"]`
  then `_LOOK_PATHS`, `_OPERATE_PATHS`, `_SENSITIVE_PATHS`. Every entry **starts with `/`**.
- `{{CEILING_DOMAINS}}` = `["example.com"]` (bare registrable host; subdomains auto-allowed).
- `{{SCOPE_LINES}}` — one `.scope(...)` per lane, indented 8 spaces, matching §3.
- `{{TASK_STRING}}` — write the agent task in terms of `navigate`/`click`/`type`/`extract`, with the
  **"if BLOCKED, report exactly what + why, then retry the SAME action on a later step"** convention
  (the operator may change the lane between steps). Tell it to await operator direction before the
  sensitive phase and to never attempt the walled action. Indent each line; it's a parenthesized
  string-concatenation like `run_saucedemo.TASK`.
- `{{BROWSER_ALLOWED_DOMAINS}}` — **a SUPERSET of the ceiling domains**, in browser-use glob form:
  for each ceiling domain `d`, include `"*.d"` and `"https://*.d"`. (Footgun #1.)
- `{{SCOPE_GOALS}}` — a dict literal, or `None`.
- `{{TASK_STEER_DEFAULT}}` = `"1"` if the demo involves the operator naming items/intents
  (shopping-like), else `"0"`; set the matching `{{TASK_STEER_COMMENT}}`.

## Step 5 — Emit `selfcheck_<app>.py`, the runbook, and the talk track
- `selfcheck_<app>.py` from `templates/selfcheck_app.py.tmpl`: set `{{WALL_NAV_TARGET}}` to a full URL
  on the walled path (e.g. `https://example.com/checkout-complete.html`) and add `{{EXTRA_CHECKS}}`
  — at minimum: an ALLOW in the operate lane on the landing path, a read-only lane action-deny
  (`_block(m, "click", "...", needle="not in scope")` after `m.active="look"`), and a sensitive-path
  scope-deny under the operate lane (`needle="not in scope"`) that flips to ALLOW after steering up.
- runbook from `templates/runbook.md.tmpl`; talk track from `templates/talk_track.md.tmpl`. Fill the
  `{{...}}`; the `{{ITEM_STEER_SECTION}}` block is only for shopping-like demos (else delete it).
  `{{REFUSE_PHRASES}}` lists the irreversible phrasings ("place the order / pay / finish") that must
  map to `none`.

## Step 6 — Footgun checklist (verify before reporting — these bit us)
1. **`BROWSER_ALLOWED_DOMAINS` ⊇ ceiling domains.** Missing a ceiling domain ⇒ the page never loads
   and the gate never decides. Generate as a superset; say so.
2. **Default-deny.** Only list what each lane needs; never emit an allow-list wider than intended.
   The ceiling is a *ceiling*, not a convenience — the wall path must be absent from it.
3. **Path globs rooted at `/`.** And remember `resolve_path` strips `?query`/`#fragment`, so glob the
   path only (`/items*` already covers `/items?id=4` and `/item.html?id=4`). Don't put query strings
   in `path_allow`.
4. **Don't hardcode a lane-name trigger.** Generated demos run under **live steering (default ON)**,
   where the operator channel is lane-agnostic. The legacy `SIGNET_LIVE_STEER=0` on-block prompt in
   `run_interactive.py` keys on the *starting* lane (`mandate.active != "tour"`) and is **not used by
   generated demos** — do not edit that shared file; just run with live steering (the default) and
   say so in the runbook. (Don't copy the literal `"tour"` anywhere.)
5. **Unmapped request → announce + refuse, never silent no-op.** `run_interactive.on_steer` already
   prints the loud ⛔ banner + writes a refusal receipt. Your job is to keep lane names distinctive so
   the planner maps cleanly, and to ensure irreversible phrasing maps to `none` (it has no lane).
6. **click_policy matches the lane.** `allow_unresolved` for lanes that click app buttons,
   `in_domain_only` for read-only. The current-page path check is the backstop — note it honestly.
7. **scope_goals when a switch must drive action**; otherwise the agent sits re-reading after a steer.
8. **`SIGNET_TASK_STEER` default** set in `main()` to match whether item/intent steering is part of
   the demo.

## Step 7 — Acceptance smoke test (run it; paste results in your report)
```bash
# parses + the mandate builds + lanes/ceiling print:
python3 -c "import ast,pathlib; ast.parse(pathlib.Path('examples/browser_demo/run_<app>.py').read_text()); print('parse OK')"
python3 -c "from examples.browser_demo.run_<app> import build_mandate, BROWSER_ALLOWED_DOMAINS as B; m=build_mandate(); cd=sorted(m.ceiling.allowed_domains); print('lanes',list(m.menu),'default',m.active,'ceiling',cd); assert all(any(d in b for b in B) for d in cd), 'BROWSER_ALLOWED_DOMAINS must cover ceiling domains'; print('superset OK')"
python3 -m examples.browser_demo.selfcheck_<app>            # offline structural proof -> PASS
```
Also confirm confinement: `git status --porcelain` shows only `examples/browser_demo/**` (the
generated demo) and `.claude/skills/signet-onboard/**` (this skill) — nothing else. Re-running the
existing demos (`selfcheck`, `selfcheck_saucedemo`, …) must be unaffected (your files are new, not
edits to shared ones). **Never** hardcode API keys — the run reads `OPENAI_API_KEY` from `.env`.

## Report back
The skill layout, how it triggered, the lanes you inferred + **why the wall path is what it is**, the
smoke-test output, and anything that fought the real `WebMandate`/template shapes. Offer to commit;
do not commit unless asked.
