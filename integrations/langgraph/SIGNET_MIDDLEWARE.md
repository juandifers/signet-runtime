# `SignetMiddleware` + the broker-client wire — implementation report (RECONCILED against `origin/main`)

> Tier-1 DB rail for LangGraph: native (`wrap_tool_call`, one line in `create_agent`) AND physically
> separated (the agent holds no key; it obtains a short-lived, effect-bound, scoped JWT through the
> existing out-of-process broker over a Unix socket). The middleware holds ZERO authority — capture +
> UX. The boundary is the broker.
>
> **This report was reconciled against a clean checkout of `origin/main` (`a8b226a`).** An earlier
> draft of §1 asserted a git history that source contradicts (see the NO-FAKE note, §4). Every repo
> claim below now cites the command + output that proves it.

Status: **complete and green on clean `origin/main`.** Verified in a fresh `git worktree` at
`a8b226a` (§1). `tests/test_signet_middleware.py` — 11 tests, 0 skips. Full suite on clean main +
middleware: **486 passed, 6 skipped** (= clean-main baseline 475 + exactly 11). The reshaped seam,
the broker server/client/protocol, the supabase authorizer, and the 10 kernel files are unedited by
this change (§6).

New files (all OUTSIDE the dogfood fence; all purely additive — no tracked file is edited):

| File | Role |
|---|---|
| `integrations/effect_gateway/transport.py` | `CapabilityTransport` protocol, `CapabilityOutcome`, `BrokerTransport` (Tier 1), `InProcessTransport` (Tier 0) |
| `integrations/langgraph/middleware.py` | `SignetMiddleware` (`wrap_tool_call`), `_capability_scope` / `current_capability`, `GuardedToolSpec` |
| `tests/test_signet_middleware.py` | the 11 acceptance gates |
| `demos/langgraph_db_broker_demo.py` | runnable Tier-1 demo (ALLOW / BLOCK / kill-broker, live socket) |

---

## §0 GROUND TRUTH — what is actually on `origin/main` (the earlier premise was FALSE)

The earlier §1 claimed `rails_supabase.py` "was removed in commit `092c2b4`." **Source contradicts
this.** Verbatim verification:

```
$ git ls-remote origin refs/heads/main
a8b226a10258a403a0579184b3e27f513aaf266f	refs/heads/main      # origin/main tip = a8b226a (NOT 83edc67)

$ git show --stat 092c2b4 -- integrations/effect_gateway/rails_supabase.py
    seam restructuring for rail abstraction
 integrations/effect_gateway/rails_supabase.py | 169 ++++++++++++++++++++++++++
 1 file changed, 169 insertions(+)                # 092c2b4 ADDED the file (+169), did NOT remove it

$ git cat-file -e origin/main:integrations/effect_gateway/rails_supabase.py && echo PRESENT-AT-TIP
PRESENT-AT-TIP                                     # present at the tip of origin/main

$ git log --oneline --follow --diff-filter=D origin/main -- integrations/effect_gateway/rails_supabase.py
                                                   # EMPTY — no deletion commit anywhere

$ git merge-base --is-ancestor 092c2b4 origin/main && echo YES-ON-ORIGIN-MAIN
YES-ON-ORIGIN-MAIN
```

**Conclusion (G0).** `rails_supabase.py` is present on `origin/main`, **added** by `092c2b4`, never
removed. The earlier "removed in `092c2b4`" claim was false.

**Why the earlier draft was wrong — the divergent local tree (recorded, not softened):**

```
$ git rev-parse --short HEAD ; git log -1 --format=%s
83edc67  "policy rail abstraction, pending"

$ git rev-list --left-right --count HEAD...origin/main
0	4                                              # local HEAD is 0 ahead, 4 BEHIND origin/main

$ git merge-base --is-ancestor 092c2b4 83edc67 && echo ANC || echo NOT-ANC
NOT-ANC                                            # 092c2b4 is NOT in the local HEAD's history

$ ls integrations/effect_gateway/rails_supabase.py
ls: ... No such file or directory                  # absent in the local working tree
```

The middleware was built on a stale local checkout (`83edc67`, **4 commits behind** `origin/main`)
that predates the merge of the supabase admission binding and its tests. The file's absence locally
led the earlier draft to *infer* a removal — without running `git show`. That inference was the
fabrication.

---

## §1 CLEAN REBUILD — middleware onto a fresh `origin/main` worktree

```
$ git worktree add -f /tmp/reconcile origin/main           # detached HEAD a8b226a
$ ls /tmp/reconcile/integrations/effect_gateway/rails_supabase.py   # 10205 B — present on clean main
$ ls /tmp/reconcile/tests | grep -iE 'supabase|binding'
test_broker_supabase.py
test_egress_binding.py
test_supabase_binding.py                                   # the admission-binding suites the stale tree lacked
# the 4 additive middleware files copied in (they touch no tracked file: all `??` in git status)
```

**G1a — REBUILDS-CLEAN.** All 11 middleware gates pass on clean main:

```
$ python3 -m pytest -q tests/test_signet_middleware.py
11 passed, 2 warnings in 2.35s
```

One gate (`test_downstream_hashes_unchanged`) FAILED on the first clean-main run — a genuine finding,
not re-greened by narrative. Cause: its pinned baseline hashes were computed on the **stale tree**, so
one of them (`seam.py`) didn't match clean main. Of the 15 pinned downstream files, **exactly one
differs** between the stale tree and clean main — `seam.py`
(`8761fe98…` → `653afde9…`), which `092c2b4` restructured ("seam restructuring for rail abstraction").
The broker trio, the supabase authorizer, and all 10 kernel files are **byte-identical** between the
two trees. The middleware imports from `signet.broker`, never from `seam`, so it has zero coupling to
that restructure — only the stale baseline constant was wrong. Corrected to clean-main's `seam.py`
hash; re-run → 11/11. (What the stale tree concealed here: that `seam.py` had been restructured
upstream. It did not conceal any middleware defect.)

**G1b — FULL-COUNT-RECONCILED.**

```
$ python3 -m pytest -q --ignore=tests/test_signet_middleware.py    # clean main, no middleware
475 passed, 6 skipped in 22.12s

$ python3 -m pytest -q                                             # clean main + middleware
486 passed, 6 skipped, 2 warnings in 22.12s                        # 475 + exactly 11
```

The earlier report claimed **421** passed (→ 410 pre-middleware on the stale tree). Clean-main
pre-middleware is **475**. **Delta = 475 − 410 = 65 tests** the stale tree was missing — the admission
binding suites (`test_supabase_binding.py`, `test_egress_binding.py`, and the rail-algebra tests merged
in the 4 commits the local HEAD was behind). The correct middleware-inclusive count is **486**, not
421.

---

## §2 RECONCILE THE PREMISE — Broker vs. EffectInterceptor is a deliberate CHOICE

On clean `main`, BOTH DB decision paths exist:

```
$ grep -nE 'class EffectInterceptor' integrations/effect_gateway/seam.py   # -> present
$ grep -nE 'class .*Binding'        integrations/effect_gateway/rails_supabase.py
66:class SupabaseBinding:                                                   # the in-process admission rail
$ grep -nE 'handle_request|class Broker' signet/broker/server.py           # -> the out-of-process path
$ grep -nE 'handle_request|Broker'      integrations/effect_gateway/transport.py
114:            resp = self._broker.handle_request(req, self._peer_uid)     # InProcessTransport wraps the Broker
```

**Decision.** Both tiers route through the **`Broker`** deliberately, so INVARIANT-INTERFACE holds *by
construction* — identical decision code, in-process (Tier 0) vs. over-socket (Tier 1) — rather than by
a parallel `EffectInterceptor` reimplementation. `rails_supabase.py` (the `SupabaseBinding`) **is
present on `main`**; the `EffectInterceptor` + supabase-binding path **is available and was not chosen,
for that reason.** Both paths in fact drive the *same* underlying composition
(`DbBrokerCore.mint_token → kernel verify → SupabaseAuthorizer.authorize`), so the choice does not
change the security properties — it only removes a second, divergent code path from the
tier-equivalence argument. The alternative is explicitly available; the choice stands on
construction-simplicity, not on any unavailability.

(The `SupabaseBinding` docstring on `main` confirms the shared composition and the same residual
surface this report records: role-granularity at the resource PEP, `signet_effect_hash` bound at mint
but not re-checked at the resource in v0 — `SEAM-EFFECT-PHASE`.)

---

## §3 RE-VERIFY THE FLAGGED GATES BY MUTATION — a gate that can't fail isn't a gate

Each gate confirmed to BITE: it passes when intact and goes RED / flips when the guarded thing is
broken. Run on clean main.

**1. Capability clears (gate #5).**
```
intact:  test_allowed_db_write_runs_with_scoped_cap -> 1 passed
mutate:  replace `_CAP.reset(reset)` with `pass` (cap never clears)
         -> FAILED  (the post-call `current_capability() is None` assertion fires)
```
The clear is genuinely tested.

**2. KILL-BROKER (gate #2).** A real dead socket (`ConnectionRefusedError`/`FileNotFoundError`), not a
mock returning block:
```
(a) dead broker -> granted=False  cause='broker-unreachable'
(b) SAME transport API at a LIVE broker, same effect
                -> granted=True   role=signet_staging_rw   (ALLOW)
VERDICT: the block was caused by the dead broker (flips to ALLOW when live).
```

**3. SAME-UID (gate #3).** Real `authenticate_peer`:
```
(a) allow_same_uid=False -> ok=False  why='same-uid-as-broker (only-door void: ... separate OS user)'
(b) allow_same_uid=True  -> ok=True   why='peer-authenticated'
VERDICT: the refusal IS the uid check (flips to admit when allow_same_uid=True); cause carries 'only-door void'.
```

**G3 — GATES-BITE:** all three mutations flip as stated.

---

## §4 CORRECTED §1 + NO-FAKE note + updated counts

**The wire (`wrap_tool_call` → broker), file/line-exact** (line numbers from clean main):

```
SignetMiddleware.wrap_tool_call            integrations/langgraph/middleware.py:112
  │  reads request.tool_call {name,args,id}     (LangChain v1 ToolCallRequest)
  │  spec = guarded_tools[name]  (ungated -> handler(request), untouched)
  │  effect_params = spec.effect_from_args(args)   (None -> FAIL-CLOSED refuse)
  ▼
CapabilityTransport.request(...)           integrations/effect_gateway/transport.py:61
  ▼  (Tier 1) BrokerTransport.request      integrations/effect_gateway/transport.py:79
       BrokerClient.request_capability     signet/broker/client.py:18      [UNCHANGED on main]
         Unix socket sendall/recv (SO_PEERCRED peer auth by the OS)
  ▼
Broker.handle_request(req, peer_uid)       signet/broker/server.py:116     [UNCHANGED on main]
  authenticate_peer (same-uid -> refuse)   signet/broker/server.py:37
  core.mint_token  (kernel verify: bind+sign+consume-once on chain_hash)   [UNCHANGED]
  SupabaseAuthorizer.authorize             signet/rails/supabase/authorizer.py:31  [UNCHANGED on main]
     verify_token -> recheck (mandate ∩ policy) -> produce_capability (mint scoped ES256 JWT)
  ▼  CapabilityResponse{granted, capability(JWT), expires_at, receipt_id, extra{role,chain_hash}}
CapabilityOutcome.from_response            integrations/effect_gateway/transport.py:46
  ▼
back in wrap_tool_call:
  not granted  -> _refuse(...) -> structured ToolMessage(status="error")   (tool NEVER runs)
  granted      -> with _capability_scope(cap, exp): handler(request)       (tool runs; clears)
```

> **NO-FAKE note.** The original §1 asserted a git history — that `092c2b4` *removed*
> `rails_supabase.py` and that "only `rails_github.py` remains / the Broker is the canonical DB path
> because the binding was removed" — that source contradicts: `git show --stat 092c2b4` shows the
> commit **added** the file (+169 insertions), and it is present at the tip of `origin/main`
> (`a8b226a`), never deleted (`--diff-filter=D` empty). The error arose from building on a divergent
> local tree (`83edc67`, 4 commits behind `main`) where the file is absent, and *inferring* a removal
> instead of running `git show`. Corrected after verification against `origin/main`. The full-suite
> count delta (§1b: 410 → 475, **65 tests** the stale tree was missing) quantifies the divergence. The
> Broker-vs-interceptor decision is re-stated in §2 as a deliberate choice with the alternative
> explicitly available — NOT as a forced consequence of any removal.

**Updated counts (clean `origin/main`, supersede the earlier 421/410):**
- Clean-main baseline (no middleware): **475 passed, 6 skipped**
- Clean-main + middleware: **486 passed, 6 skipped** (= 475 + 11)
- Middleware suite: **11 passed, 0 skips**

---

## §5 AGENT-HOLDS-NO-KEY (gate #1)

`test_agent_holds_no_key` greps the two agent-side modules for key material and finds none
(`Es256Key, minter, service_role, private_pem, DATABASE_URL, SUPABASE_SECRET, mint_jwt, enforcer_sk,
principal_sk` → CLEAN in both `transport.py` and `middleware.py`). The Tier-1 transport's instance
state is a `BrokerClient` (a socket path) + a float timeout — nothing else. The only authority in the
agent process is "the ability to ask the broker."

---

## §6 NO-DOWNSTREAM-EDITS (gate #9) — pinned to CLEAN MAIN

`test_downstream_hashes_unchanged` pins sha256 of `seam.py`, the broker trio
(`server/client/protocol`), `supabase/authorizer.py`, and the 10 kernel files
(`verifier, chain, models, policy, nonce, revocation, receipts, builder, crypto, canonical`) **to their
`origin/main` (`a8b226a`) values**. The middleware edits none of them; the change is purely additive
(the 4 new files are untracked — they touch no tracked file). The one baseline that changed from the
earlier draft is `seam.py` (stale-tree `8761fe98…` → clean-main `653afde9…`), because `092c2b4`
restructured `seam.py` upstream — unrelated to this middleware, which never imports `seam`.

---

## §7 SCOPED-SHORT-TTL evidence (gate #4)

`test_scoped_short_ttl`: a granted `staging.analytics_events / select` yields
`role=signet_staging_ro` (least-privilege; NEVER `service_role`/root), `expires_at = T0 + 60s`
(verifier-authoritative clock; `exp − iat == 60`), a real ES256 JWT verifiable against the broker JWKS
with no broker in the loop.

**Residual surface (honest, unchanged by the reconcile).** The supabase resource enforces at **role**
granularity (`signet_<schema>_{ro|rw}`), so within the 60s TTL the role-scoped cap is reusable for
*same-role* ops at the resource — narrowed by TTL + role + effect-binding (`signet_effect_hash` in the
JWT), but **not yet effect-granular** at the resource (`SEAM-EFFECT-PHASE`; the same gap the on-`main`
`SupabaseBinding` docstring records). "Never the root key" is delivered; "never wider than the
approved effect" needs the parked resource-PEP hardening.

---

## §8 INVARIANT-INTERFACE evidence (gate #7)

`test_tier0_tier1_invariant_interface`: the SAME `SignetMiddleware`, with `InProcessTransport(broker)`
(Tier 0) vs. `BrokerTransport(sock)` over a real threaded `UnixSocketBrokerServer` (Tier 1), produces
**identical** control flow — `(handler ran, not error)` on ALLOW; `(handler skipped, error)` on BLOCK —
for the same two effects. Security is the transport choice (where the key lives) + the process topology
(separate uids), never the agent code.

---

## §9 Ergonomics — the line a user writes

```python
from langchain.agents import create_agent
from integrations.effect_gateway.transport import BrokerTransport
from integrations.langgraph.middleware import SignetMiddleware, GuardedToolSpec

db_spec = GuardedToolSpec(effect_from_args=lambda a: {
    "database": "app", "schema": a["schema"], "table": a["table"], "op": a["op"]})

agent = create_agent(
    model, tools=[db_write, db_read],
    middleware=[SignetMiddleware(
        transport=BrokerTransport("/run/signet/broker.sock"),   # Tier 1: no key here
        task_id="task-001",
        guarded_tools={"db_write": db_spec, "db_read": db_spec})],
)
```

`test_drop_in_create_agent` drives a scripted model through `create_agent` end-to-end (no provider
package / API key): the model emits an off-mandate `db_write`, the middleware contains it, the tool
never runs, and a `{"signet":"blocked","cause":"out-of-mandate"}` `ToolMessage` lands in the
transcript.

**Deployment shape** (the topology is the security):

```
 agent process  (uid A):  create_agent(middleware=[SignetMiddleware(BrokerTransport(sock), ...)])
                          NO key-issuing core, NO service-role key, NO direct DB route — only the socket
        │ Unix socket (SO_PEERCRED; broker refuses a same-uid peer)
        ▼
 broker process (uid B):  UnixSocketBrokerServer(Broker)  — holds the key, the policy, the mandates
        │ scoped ≤60s JWT
        ▼
 database/resource:       accepts only broker-issued scoped JWTs; rejects broad/expired creds
```

Run the demo: `python -m demos.langgraph_db_broker_demo` (single-process over a real socket = the
advisory granted-path measurement; the structural boundary is the separate uid).

---

## §10 Residue / surprises

- **Built on a stale tree (the headline finding).** See §0/§1: local HEAD `83edc67` was 4 commits
  behind `origin/main` and missing `rails_supabase.py` + ~65 tests. The reconcile was done in a clean
  `origin/main` worktree; all numbers and hashes in this report are clean-main numbers.
- **Capability injection = a `contextvar`, not request mutation.** LangChain's `ToolCallRequest` warns
  on direct attribute assignment; the cap rides a per-call `_capability_scope` contextvar
  (`current_capability()` reads it), concurrency-correct and cleared deterministically after each call
  (proven to bite, §3.1).
- **`wrap_tool_call` version drift.** `langchain==1.3.2` exposes `request.tool_call` (a `ToolCall` dict
  with `name`/`args`/`id`), not `request.tool_name`/`request.args`. The middleware reads the real shape
  (`middleware.py` lines 113/141).
- **`request_nonce` is fresh per call by default** (`GuardedToolSpec.nonce` = `uuid4().hex`); override
  with a deterministic nonce to make a tool idempotent (identical calls collide on `chain_hash` →
  consume-once refuses the replay).
- **No test skips in the middleware suite.** A scripted `BaseChatModel` (supports `bind_tools`) stands
  in for a provider, so the drop-in gate runs for real rather than skipping.

---

## §11 The tier model

```
 Tier 0  middleware -> InProcessTransport -> Broker (in-process)        advisory   dev / low-stakes
 Tier 1  middleware -> BrokerTransport   -> UnixSocketBrokerServer      structural prod DB  (THIS)
 Tier 2  agent in netns -> EgressProxy (sole route)                     structural prod egress (deferred)
```

One middleware interface, three backends. The engineer writes the same line at every tier; security is
the transport + the process topology, never the agent code. The middleware is capture + UX; the broker
is the boundary; the agent holds no key.
