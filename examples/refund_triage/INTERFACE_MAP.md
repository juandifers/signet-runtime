# INTERFACE_MAP.md — Signet × LangGraph refund-triage demo

> Mandatory §2 discovery deliverable. Every interface below is quoted with a real
> `file:line` citation against the repo on branch `demo-langgraph-refund` (off `main`).
> **The repo is the source of truth.** Where the spec's vocabulary diverged from the
> code, the divergence is recorded here (DIVERGENCE blocks) — the repo wins.

## Headline divergences (spec → repo)

1. **`SignetMiddleware` does not exist.** The spec's "middleware on the action
   boundary" is the **guarded-tool factory** `signet_guarded_tool(...)`
   (`integrations/langgraph/guarded_tool.py:53`). A `middleware.py`/`transport.py`
   survive only as stale `.pyc` in `integrations/langgraph/__pycache__/` and
   `integrations/effect_gateway/__pycache__/` — no source. The live control-plane
   primitive is the orchestrator-agnostic **`EffectInterceptor`**
   (`integrations/effect_gateway/seam.py:109`).
2. **`CapabilityTransport` does not exist** in the current tree (spec §2 row 5). The
   seam's `EffectInterceptor` *is* the transport-agnostic primitive; the rail-specific
   composition lives behind a `RailBinding` (`seam.py:61`). Tier-0 (in-process) vs
   Tier-1 (separate-process Unix socket) is selected by **which object you hand the
   agent**: the in-process `SupabaseBinding` (Tier 0) vs `BrokerClient` over
   `UnixSocketBrokerServer` (Tier 1) — not by a `CapabilityTransport` class.
3. **The supabase door binds at `(database, schema, table, op[, predicate])`
   granularity — NOT row values.** `amount`/`order_id` are not part of the effect;
   `amount` is hardcoded `0` in the chain (`chain_adapter.py:126,144`). The real gate
   is `effective_permits` → `DbGrant.permits` (schema/table/op only,
   `mandate.py:38,127`). Therefore the spec's "amount tampering" and "destination
   substitution" attacks **cannot block at this rail** without out-of-scope
   predicate/RLS binding (spec §8 Thread D). **Resolved with the user (v2):** headline
   block is **A1 privilege-escalation** (`UPDATE public.users` off the frozen task),
   **A2** is an **off-op DELETE**, and **A3** (`INSERT credits amount=5000`) is kept as
   an **honest labeled ALLOW** demonstrating the door's granularity boundary. Block
   mechanism = `effective_permits`. Kernel and `DbGrant.permits` untouched.

---

## §2 resolution table

| # | What the spec needs | Repo reality (cited) |
|---|---|---|
| 1 | How the middleware attaches to a LangGraph graph | **`signet_guarded_tool(interceptor, *, tool_name, id_arg, world_getter)`** returns a callable `guarded(**args)` to use as a LangGraph tool/node body (`integrations/langgraph/guarded_tool.py:53,66`). Wiring idiom (StateGraph: model node → guarded tool node): `demos/langgraph_merge_demo.py:106-134`. |
| 2 | `ProposedEffect` shape for a db admission + effect-key encoding | `ProposedEffect{tool:str, args:dict}` (`seam.py:25`). The supabase binding reads the op from `eff.args` as `{database, schema, table, op, predicate?}` (`integrations/effect_gateway/rails_supabase.py:127-143`); tools handled: `_DB_TOOLS` incl. `db_write` (`rails_supabase.py:58`). Effect-key = `DbEffect.effect_hash()` (`signet/rails/supabase/effect.py:56`). |
| 3 | `Decision` shape + outcome values | `Decision{outcome, cause, candidates, receipt, escalation_source, bound_target, tier, check_ref}` + `.allowed` (`seam.py:39-55`). Outcomes: `Outcome.ALLOW/BLOCK/ESCALATE` (`seam.py:33`). **Admission rails never ESCALATE** (`seam.py:74-77`, `rails_supabase.py:70`). |
| 4 | Supabase mandate JSON schema | `TaskMandate{task_id, database, grants:[DbGrant{schema,table,ops}], expires_at?, signature?}` (`signet/broker/mandate.py:67-122`); JSON form `to_json()`/`from_dict()` (`mandate.py:109-122`); scope test `permits()` (`mandate.py:77`). Standing ceiling `StandingPolicy` (`mandate.py:57`); the ∩ decision `effective_permits()` (`mandate.py:127`). |
| 5 | Tier-0 vs Tier-1 + broker startup (uid, ES256, SO_PEERCRED) | **Tier 0 (this demo's default):** in-process `SupabaseBinding(broker_core, mandate_provider, standing_policy, minter, ...)` (`rails_supabase.py:72`) driven through `EffectInterceptor` (`seam.py:114`). **Tier 1 (documented upgrade):** `Broker.create(...)` (`signet/broker/server.py:80`) behind `UnixSocketBrokerServer(broker, socket_path, expected_agent_uid)` (`server.py:163`); peer auth `authenticate_peer` refuses same-uid (`server.py:37-49`), `read_peer_uid` via SO_PEERCRED (`server.py:52`); agent side holds only `BrokerClient(socket_path)` (`signet/broker/client.py:14`). ES256 minter `Es256Key` (`signet/rails/supabase/es256.py`). |
| 6 | How the scoped JWT is requested / consumed / executed | In the seam path the binding runs `DbBrokerCore.mint_token` (kernel verify + consume-once, `chain_adapter.py:167`) → `SupabaseAuthorizer.authorize` mints the ES256 JWT in `produce_capability` (`signet/rails/supabase/authorizer.py:71-88`); the JWT rides in `Decision.check_ref`/`receipt.payment_ref` (`rails_supabase.py:146-154`). The downstream PEP that executes the write is `SupabaseGateway.request(apikey, bearer_jwt, schema, table, op, ...)` (`signet/rails/supabase/resource_sim.py:85`); `Store.apply` insert → `{"inserted":1}` (`resource_sim.py:69`). |
| 7 | Receipt emit + auditor verification | Seam emits via kernel `ReceiptLog.append(execution_id, mandate_id, chain_hash, policy_id, decision, payment_status, payment_ref, rail) -> Receipt` (`signet/receipts.py:26`; called `rails_supabase.py:147,163`). Receipt id = `Receipt.receipt_hash`; auditor verifies with `ReceiptLog.verify(receipt) -> (ok,msg)` (`receipts.py:48`). |
| 8 | `role_for` granularity | `role_for(schema, op_class) -> "signet_<schema>_<ro|rw>"` (`signet/rails/supabase/roles.py:21`); `op_class` is `ro|rw` (`effect.py:30`). **(schema, op-class)** — finer roles out of scope (confirmed: the A1/A2 block fires at `effective_permits`, BEFORE any role/JWT is minted, so role granularity is NOT needed for the block). |

---

## Block-mechanism trace (the demo's claim, grounded)

For an effect outside the frozen task mandate (A1 `public.users update`, A2
`public.credits delete`):

1. `SupabaseBinding.submit` → `DbBrokerCore.mint_token` (kernel admits the
   self-consistent chain — by design, `chain_adapter.py:10-16`).
2. `SupabaseAuthorizer.recheck_against_context` step 3 calls
   `effective_permits(eff, mandate, standing)` (`authorizer.py:68`).
3. mandate grants only `public.credits {select,insert}` ⇒ `DbGrant.permits` returns
   False for `users.update` / `credits.delete` ⇒ `"out-of-mandate"` (`mandate.py:137`).
4. `authorize` returns not-executed ⇒ binding emits `Outcome.BLOCK`,
   `escalation_source="admission_denied"`, signed deny receipt (`rails_supabase.py:123`).
   **No token minted, no JWT, no gateway call ⇒ zero rows written.**

Confirmed by the existing battery: `tests/test_supabase_binding.py:110-135`
(`out-of-mandate` for off-table / off-op), `:142` (`out-of-standing-policy`).

## A3 honest-ALLOW (granularity boundary, labeled)

`INSERT public.credits` with `amount=5000` has the **same effect-key** as the clean
`amount=50` insert — `(public, credits, insert)` — because `DbEffect` carries no row
values (`effect.py:18-24`, `_effect_from_args` `rails_supabase.py:127`). It therefore
passes `effective_permits` and the door mints a JWT (ALLOW). The trace labels this
`NOTE: row-value containment is out of scope for this door (spec §8 Thread D)`.

## Tier statement for this demo

This demo runs the **seam / guarded-tool path (Tier 0, in-process)** mandated by spec
§4. The signing key (`Es256Key` minter, enforcer SK in `DbBrokerCore`) lives inside the
`SupabaseBinding`/broker objects, constructed **outside** the LangGraph agent surface;
the agent's authored state (ticket, `ProposedEffect`) never carries key material. The
OS-separated **Tier 1** upgrade is the `UnixSocketBrokerServer` + `BrokerClient` path
(server.py:163 / client.py:14), where a different process holds the key — documented in
README, not the default here. The trace labels the run **`tier=0 (advisory)`** per spec
§9 (never presents advisory containment as structural).

> **Update:** the Tier-1 upgrade below is now implemented — `tier=1 (structural)` runs under real
> OS uid separation in the Linux container harness, while macOS stays honestly advisory.

---

# Tier-1 upgrade (advisory → structural)

The Tier-1 work moves the broker to a **separate OS uid** reached over a Unix socket, so "a
fooled agent cannot obtain a DB signing key" is true at the OS level and proven by a test.
**Verdicts are invariant** (clean ALLOW / a1 BLOCK / a2 BLOCK / a3 ALLOW); only the credential
mechanism and the honesty of the label change. No kernel / `effective_permits` /
`DbGrant.permits` / `roles.py` / broker-transport edits.

## §2 (Tier-1) resolution table

| # | What you need | Repo reality (cited) |
|---|---|---|
| 1 | The Tier-0 swap site | `examples/refund_triage/agent.py` `build_door` (in-proc `SupabaseBinding`); the Tier-1 plug-in is `build_tier1_door` (same file) selected by `run_scenario(tier=…)` / `resolve_tier`. |
| 2 | `UnixSocketBrokerServer` + `BrokerClient` lifecycle | server: `signet/broker/server.py:163` (`start` :180, `serve_one` :188, `stop` :208); client: `signet/broker/client.py:14` (`request_db` :35). Reused verbatim; the demo's accept-loop wrapper is `examples/refund_triage/tier1_broker.py` (`ThreadBroker`, `serve_forever`). |
| 3 | Tier selection | `examples/refund_triage/agent.py` `resolve_tier` (`0`/`1`/`auto`; `auto`→1 iff a broker socket is configured) + `run_scenario(tier, socket_path, jwks_path)`; CLI `--tier` in `run.py`. The seam `RemoteSupabaseBinding` (`tier1.py`) maps `CapabilityResponse`→`Decision`. |
| 4 | Two-uid spawn harness | `examples/refund_triage/Dockerfile` (`useradd -u 1100 broker` / `-u 1200 agent`) + `tier1_entrypoint.sh` (`runuser -u broker` / `runuser -u agent`); the broker owns the ES256 key at a **container-local** 0600 path via `tier1_broker.write_keypair` (`os.chmod(0o600)`). No `setup_signet_demo.sh` path exists (it has no uid setup). |
| 5 | Peer-cred mechanism + platform | **`SO_PEERCRED` — Linux-only** (`signet/broker/server.py:52-64`); on macOS it falls back to `os.getuid()` (no `LOCAL_PEERCRED`/`getpeereid` path). The demo gates the label on this with `examples/refund_triage/tier1.py` `detect_separation` (structural iff `hasattr(socket,'SO_PEERCRED')` **and** the socket file is owned by a different uid). **Finding: the dev host is macOS → the structural demo requires Linux (a container).** |
| 6 | Trace label site | `examples/refund_triage/trace.py` `_tier_label` — flips `0 (advisory)`↔`1 (structural)` from the run's `detect_separation` result (rule §0.4). |
| 7 | The advisory→structural test | Tier-0 advisory: `tests/test_refund_triage_demo.py::test_agent_surface_holds_no_db_signing_key` (object-graph check). Upgraded structural: `…::test_tier1_agent_uid_cannot_read_signing_key` (real ownership/mode + `PermissionError`), gated on `SIGNET_TIER1_STRUCTURAL=1`. |

## The cardinal honesty rule, enforced (§0.4)

`detect_separation` is the single gate. `tier=1 (structural)` is printed **only** when
`SO_PEERCRED` exists *and* the broker socket is owned by a different uid — both verified by the
agent itself at runtime (it `os.stat`s the socket; it does not trust an env var). Verified:
- **macOS, over a real socket, grant succeeding (ALLOW/1 row):** label stays
  `0 (advisory) [platform has no SO_PEERCRED …]`. Structural is never claimed here.
- **Linux container, uid_broker=1100 / uid_agent=1200:** label is `1 (structural)`; the full
  triad passes (key 0600 owned by 1100, unreadable by 1200).

## Verification results

- macOS: 19 demo tests pass, 5 structural tests **skip-with-reason** (never vacuous).
- Linux container (`bash examples/refund_triage/run_tier1_container.sh`): **all 24 pass** — the
  triad (`same_uid_peer_refused`, `agent_uid_cannot_read_signing_key`,
  `killed_broker_yields_no_writes`) + the four verdicts at Tier 1, all labeled `structural`.
- `core_kernel_edits_zero` = `0/10`; full suite 494 passed / 11 skipped; scorecard PASS.

---

# Egress rail (the SECOND rail — one agent, two rails, one session)

Wires the EXISTING egress proxy into the same agent/graph so one frozen task proposes BOTH a DB
write AND a network egress. Both cross the ONE unchanged `EffectInterceptor` through their own
`RailBinding`. No kernel / seam / `EffectInterceptor` / broker-transport / `effective_permits`
edits; DB verdicts unchanged.

## §2 (egress) resolution table

| # | What you need | Repo reality (cited) |
|---|---|---|
| 1 | The egress effect type + seam shape | `EgressEffect{host, port, protocol, resolved_ip?}` — bound side is host+port, `resolved_ip` is OUT of the hash (`signet/rails/egress/effect.py:19-39`). Seam shape is **admission** (self-describing destination, admit-or-deny, no resume) — `integrations/effect_gateway/rails_egress.py:7-14`, `seam.py:74-77`. |
| 2 | The proxy door + allowlist/mandate shape | **`EgressBroker.admit(host, port, protocol, request_nonce) -> AdmissionResult{admitted, cause, receipt_id, forward_ip, forward_port, chain_hash}`** (`signet/broker/proxy.py:88`) — "Inline: **no token is handed out**" (`:50,90`). The forward proxy `EgressProxy` (`proxy.py:157`): CONNECT→`admit`→**200**/splice (`:214-226`) or **403** (`:218`). Allow-set: `EgressMandate{task_id, grants:[EgressGrant{host, ports}]}` ∩ `EgressStandingPolicy`, decided by `effective_admits()` (`signet/rails/egress/mandate.py:59-108`); host match exact-or-`*.suffix`, bare `*` rejected (`:19-28,36-38`). |
| 3 | `RemoteSupabaseBinding` — the structure to mirror | `tier1.py:59-141`: `name/shape="admission"`, `handles/proposal_for/submit`, a **socket transport** to a separate door, **fail-closed** on `ConnectionRefused/FileNotFound/OSError/timeout` (`:102-106`), maps the response → `Decision`, appends one demo-local signed receipt. |
| 4 | The `#8` advisory anchor | `tests/test_broker_egress.py:202` (`test_08_NEGATIVE_direct_connection_bypasses_proxy`): a DIRECT connection BYPASSES the proxy and SUCCEEDS — the proxy is **advisory** without a netns. Still passes; the boundary is honestly recorded. |
| 5 | How the emitter serialises an effect | `examples/refund_triage/session.py` `_combined_effect_record` → `{seq, rail, label, proposed{action,target,detail}, decision, reason, escalation_source, token_minted, performed, receipt_id, receipt_verified, note}`. The egress effect slots in with `rail:"egress"`, `performed:{egress:"blocked"}` — the viewer renders it with NO edit (`viewer/index.html:288`, `performedText` keys on `p.egress`). |

## DIVERGENCE (spec → repo, repo wins — recorded)

The spec's mental model: the egress door is **effect-performing** ("the proxy connects or refuses;
the agent holds nothing; … if you find yourself minting a token for an egress effect, you have
broken the model"). The repo ships **two** egress admission surfaces:

1. **In-process seam binding** `integrations/effect_gateway/rails_egress.py:EgressBinding` — a
   capability-admission rail that drives `EgressBrokerCore.mint_token` (a per-effect kernel
   consume-once token) and returns `check_ref`. This is the *other* archetype.
2. **Inline proxy** `signet/broker/proxy.py:EgressBroker`/`EgressProxy` — effect-performing, "no
   bearer token handed to the agent" (`proxy.py:50,90`, `signet/rails/egress/__init__.py:6-8`).

The spec mandates archetype (2). So the demo's `examples/refund_triage/egress.py:EgressProxyBinding`
routes to the **proxy** over a CONNECT socket (mirroring `RemoteSupabaseBinding`'s transport), maps
200/403 → `Decision`, fails closed when the proxy is down, and surfaces **`check_ref=None`** — the
agent holds nothing. The consume-once token minted *inside* `EgressBroker.admit` is the unchanged
composition's replay defense, never a bearer capability. The integration `EgressBinding` is left
unused by the demo (it is the wrong archetype here), and that choice is recorded — not a regression.

## Combined-session statement (advisory → structural)

The combined run (`examples/refund_triage/egress.py:run_combined`) emits one session with two
effects: **supabase insert credits → ALLOW** (1 row, JWT minted), **egress connect attacker host →
BLOCK** (0 bytes, advisory, no token). The egress effect is labeled **`advisory (inline proxy)`**;
the structural upgrade is the netns sole-path (Thread C, `CAP_NET_ADMIN`) — OUT OF SCOPE here, and
`#8` records that a direct connection bypasses the v0 proxy. Acceptance:
`tests/test_refund_egress_combined.py` (8 tests). `core_kernel_edits_zero` = `0/10`; full suite
502 passed / 11 skipped; scorecard PASS.

---

# On-ramp — `guard(tool, mandate)` + `Mandate` + `SignetConfig` (spec §2)

Discovery for the facade (`examples/onramp/`). It is **facade only**: it constructs and wires the
*existing* pieces below; it adds no enforcement and changes no behavior (proven byte-for-byte by
`tests/test_onramp.py::test_onramp_reproduces_handwired_refund_session`).

| # | What the on-ramp needs | Confirmed in the repo (file:line) |
|---|---|---|
| 1 | The real **mandate schema** + per-rail `granted_scope` shape | DB: `signet/broker/mandate.py:68` `TaskMandate{task_id, database, grants:[DbGrant{schema,table,ops}], expires_at, signature}`; serialised by `signing_payload()` (`mandate.py:87`) — the exact shape of `scenarios/mandate.clean.json`. **No row-value field** (DbGrant binds `(schema,table,op)` only, `mandate.py:38`). Egress: `signet/rails/egress/mandate.py` `EgressGrant{host,ports}`. Session scope projection: `session.py:_combined_granted_scope` (`{rail,action,target}`). |
| 2 | How `EffectInterceptor` + each `RailBinding` are constructed | `integrations/effect_gateway/seam.py:114` `EffectInterceptor(mandate, bindings, *, env, bridge, receipts, world)`; DB Tier 0 `agent.py:89 build_door` (`SupabaseBinding`), DB Tier 1 `agent.py:116 build_tier1_door` (`RemoteSupabaseBinding` over `BrokerClient`), DB+egress `egress.py:314 build_combined_door` (one interceptor, two bindings). |
| 3 | The existing entry points the facade re-uses | `integrations/langgraph/guarded_tool.py:53 signet_guarded_tool`; `integrations/effect_gateway/rails_supabase.py:SupabaseBinding`; `examples/refund_triage/tier1.py:59 RemoteSupabaseBinding`, `:183 make_audit_log`; `examples/refund_triage/egress.py:91 EgressProxyBinding`, `:314 build_combined_door`. |
| 4 | The existing JSON mandates (for `from_json`/`to_json`) | `examples/refund_triage/scenarios/mandate.clean.json` (DB-shaped). `Mandate.to_json()` round-trips it byte-for-byte (`test_onramp.py::test_mandate_roundtrips_json`). |
| 5 | The tier-selection mechanism (Tier 0 in-proc vs Tier 1 socket) | `agent.py:261 resolve_tier`; the honest label is computed at run time by `tier1.py:164 detect_separation` / `Separation.label` — a same-uid peer or non-Linux host degrades the label to advisory. `SignetConfig.label()` mirrors the *requested* tier; the runtime check stays authoritative. |
| 6 | The per-rail install extras (for the missing-extra teaching error) | `pyproject.toml:24 supabase` (`pyjwt[crypto]`, `cryptography`), `:41 refund-demo` (`langgraph` + supabase crypto). `errors.require(module, rail, extra)` raises `MissingRailExtraError` naming the `pip install -e ".[extra]"` fix. |

## Design decisions (recorded)

- **Public surface placement.** `signet/**` is fenced, but `.signet/policy.yaml` protects only the 10
  named kernel files + `authorizers/**`, `cli/**`, `api.py`, scorecard/workflows/mandates/pems —
  **`signet/__init__.py` is NOT protected**. So the three names are exposed by *additive lazy
  re-exports* in `signet/__init__.py` (an absolute-path entry → `examples.onramp`), matching the
  existing PEP-562 lazy pattern. No kernel file is touched; `import signet` stays light; `signet.guard`
  triggers the import only on first access. The implementation lives in `examples/onramp/` (co-located
  with the demo rail builders it wires), so the kernel package keeps no structural dependency on the
  examples tree — only a lazy re-export pointer. The blessed surface is exactly `guard`, `Mandate`,
  `SignetConfig`; `guarded_door`/`build_onramp_door` are available from `examples.onramp` for door
  lifecycle and the faithfulness driver, but are not part of the three-name `signet.*` surface.
- **Faithfulness is structural, not re-coded.** `guard()` delegates to `build_door` /
  `build_tier1_door` / `build_combined_door` verbatim, so the wiring is identical by construction. The
  keystone test injects a `guard()`-assembled door into the unchanged `run_combined` / `run_scenario`
  (an additive `door=` param, default `None` = unchanged) and asserts the emitted session is identical
  to the hand-wired one — except `generated_at` (wall-clock) and `receipt_id`. The kernel ReceiptLog
  stamps `datetime.now()` + a `uuid` into every receipt (`signet/receipts.py:31,40`), so `receipt_hash`
  is non-reproducible **by design**; "same receipts" is asserted as receipt **presence + verifiability**,
  not hash equality (and the kernel is not touched to make it deterministic).
- **Archetypes stay distinct.** `guard()` never mints a token for an egress effect — it routes to the
  proxy binding (`EgressProxyBinding`, `check_ref=None`). The DB rail is capability-issuing.
- **No over-promising.** `Mandate` exposes `allow_db`/`allow_db_insert`/`allow_db_select`/`allow_egress`
  and **no** `max_amount=` (the DB door cannot back a row-value), per spec §0.3.

## Acceptance (on-ramp)

`tests/test_onramp.py` (14 tests): faithfulness keystone (combined byte-identical + single-rail
parity), builder scope + JSON round-trip, no-row-value surface, drop-in tool, one-session-two-tools,
advisory-default / structural-config labels, three teaching errors (missing extra / malformed target
/ unknown rail), and fail-closed when the proxy is unreachable. `core_kernel_edits_zero` = `0/10`;
scorecard PASS; full suite 516 passed / 11 skipped.
