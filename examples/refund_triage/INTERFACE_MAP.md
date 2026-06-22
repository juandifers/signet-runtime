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
