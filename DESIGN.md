# DESIGN — Execution-Enforcement Layer (north star)

Read this before designing any new domain adapter. It encodes the positioning
and the design constraints that keep us out of the crowded, commoditizing part
of the market and inside the defensible part.

## Thesis

We provide enforcement an agent **cannot route around** — because the rail
itself will not execute without our authorization — plus **independently
verifiable proof** of every allowed, blocked, or reviewed action.

The differentiator is **held-capability / bypass-resistance** and **anchored
receipts**, NOT tool-call interception or allow/block/review policy verdicts.
Those are already commoditizing (e.g. AEGIS, AgentTrust — both pre-execution
interceptors with policy verdicts; AEGIS even ships Ed25519-signed,
hash-chained audit). If we build "a better interception SDK with receipts," we
walk straight into them. The part those systems explicitly cannot do — AEGIS
itself disclaims defense against calls that bypass the SDK — is our wedge.

## Design principles (the adapter constitution)

**P1 — Bind the effect, not the tool.** Gate the canonical *side effect* (the
merged diff, the applied plan, the IAM change, the money movement), never the
obvious tool name. If the dangerous effect is reachable by another path, the
gate must sit on the effect or it is incomplete. Evidence: the Claude Code auto
-mode stress test found ~81% end-to-end false-negative rate because agents
reach effects via file edits the shell-oriented classifier never sees. Our own
AgentDojo run showed the same shape (a leak in the memo of an authorized
transfer passes a recipient/amount gate). Gate the effect surface, whole.

**P2 — Be the rail where you can; bridge to the hard rail where you can't.**
Two adapter archetypes, and every adapter must declare which it is:
- **Custodial enforcer** — we hold a capability the action requires (XRPL
  co-signature, sole credential custody, MPC key share). Bypass is structurally
  impossible. Use where we can actually hold it (payments/treasury).
- **Rail-bridge** — a hard rail already exists server-side (GitHub branch
  protection, CI required approvals, cloud IAM/policy-as-code, signed deploys).
  We convert policy into the token/approval that rail requires and feed it.
  Enforcement lives at the server-side rail, never at a client-side interposer.
Never ship a client-side wrapper as the *sole* gate — that is the AEGIS / Claude
Code failure mode (bypassable). A client-side gate may exist as defense-in-depth
or UX, but it is not the enforcement boundary. (The shipped local `signet hook`
gate IS exactly that defense-in-depth layer, by design — containment UX +
tamper-evident receipts, never the boundary. See LOCAL_GATE.md and CLAUDE.md
invariants 7–10. P7/P8 below make explicit *why* it was never the boundary.)

**P3 — Deterministic capability membership, not intent judgment.** The verifier
checks structural membership of a typed capability ("is this action inside the
authorized envelope?"), never "does this look risky?". Derive the capability
from **trusted input only**, plan-then-execute style: extract the envelope from
the user instruction / task spec / repo policy BEFORE any untrusted tool output
is seen, freeze it, then enforce. If the extractor ever reads injected content,
the injection rewrites the envelope and we have gated nothing.

**P4 — Risk tier = authorization path, not a vibe.** Low (typed, reversible,
bounded) → auto-token. Medium (typed, meaningful side effect) → approval.
High (irreversible, privileged, external) → human co-sign. Forbidden → deny.

**P5 — Receipts must be independently verifiable.** Anchor the (capability,
policy version, decision, effect hash, approval) to an independent append-only
ledger via Merkle commitment — verifiable WITHOUT trusting our infra. A
vendor-signed hash chain (what AEGIS already has) is not differentiated; the
anchored, infra-independent proof is.

**P6 — Kernel stays domain-agnostic.** Everything domain-specific is an adapter:
a canonicalizer (extract the effect), a policy (typed-capability rules), an
effector (turn the token into the rail's required input). No kernel edits per
domain. The kernel = verifier pipeline + consume-once + context binding +
anchored receipts + the token/effector seam.

**P7 — The gate is the keyholder, not the command inspector** (the sharpened
form of P2). Enforcement strength on any rail equals the degree to which the
protected resource is **unreachable without a brokered capability**. A rail is a
genuine boundary iff its resource has an *only-door*: the sole path to it passes
through the broker. Where the agent simply holds no standing secret,
zero-standing-credentials **is** the only-door, for free. Where the ambient path
must instead be forbidden by the OS/network (raw sockets, files readable as the
agent's user), that OS dependency is **stated in the rail spec as a precondition**
for the boundary claim — never assumed, never hand-waved. The reframe in one
line: *stop inspecting the command; hold the only key.* Proof it must be this
way: the bare-`git push` gap (Stage 2 ACT 3b) shows command inspection is
*structurally* unable to be a boundary — the effect isn't in the string.
Capability issuance has no such gap: the effect is in the request, frozen and
bound before any credential exists. This subsumes P2's "be the rail" — the
GitHub required-check is already a keyholder (a merge cannot occur unless GitHub
admits `signet/enforced`, and we hold whether it passes).

**P8 — Honest containment scope.** A compromised agent process retains its
**ambient authority**. The broker contains exactly what is gated behind an
only-door and nothing more — never the agent process itself; only the OS layer
does that (Hermes's own admission: "the only security boundary against an
adversarial LLM is the OS"). Every rail spec must carry an explicit
**"contains / does NOT contain"** statement. Overclaiming containment is a
principle violation on par with a fabricated result.

**P9 — The only-door classifier: free vs. OS-interposition** (the predictive
form of ONLY-DOOR-OR-DECLARE — apply it BEFORE scoping any rail). Ask one
question: *does the resource itself enforce scope when handed a scoped
credential?*
- **Yes → the only-door is FREE** (the DB-rail pattern). A trustworthy external
  enforcer already sits between the agent and the resource: Postgres/RLS, cloud
  STS, most credentialed APIs. Signet only has to **decide** — mint the scoped
  credential — and zero-standing-credentials is the boundary. No OS dependency.
- **No → the only-door needs OS INTERPOSITION** (the egress-rail pattern). Raw
  network, the filesystem, the shell, an arbitrary subprocess — nothing
  trustworthy sits between agent and resource, so Signet must both **decide AND
  interpose**: supply the enforcer (a proxy) *and* force the agent through it
  (a netns/firewall). Here the OS dependency is real; per P8 + ONLY-DOOR-OR-
  DECLARE it is declared, simulated in v0, and a negative test proves the gate
  is merely advisory without it.

This classifier tells you, in advance, which rails are cheap and which are hard:
DBs/STS/APIs are free; egress, filesystem, and shell are the OS-interposition
class and must carry a declared, separately-tested OS precondition.

## The only-door classifier — ONLY-DOOR-OR-DECLARE (the reusable test)

The most portable idea in the codebase: a one-question test that tells you, before
you scope a rail, whether it can be a boundary cheaply, expensively, or not at all
— and a discipline that forbids overclaiming when it can't. P7–P9 state it as
principles; this section is the worked, settled form to apply directly.

**The question (P9).** *Does the resource itself enforce scope when handed a
scoped credential?*
- **Yes → the only-door is FREE** (DB-rail pattern). A trustworthy enforcer
  already sits between agent and resource — Postgres/RLS, cloud STS, most
  credentialed APIs. Signet only has to *decide* and *mint*; zero-standing-
  credentials is the boundary, no OS dependency. Worked example:
  `signet/rails/supabase/` — the agent holds no DSN, Postgres enforces the scoped
  JWT (`test_broker_supabase.py::test_06`, `::test_07`).
- **No → the only-door needs OS INTERPOSITION** (egress-rail pattern). Raw
  network, the filesystem, the shell — nothing trustworthy sits between agent and
  resource, so Signet must *decide AND interpose*: supply the enforcer (a proxy)
  and force the agent through it (a netns). Worked example: `signet/rails/egress/`
  + `signet/sandbox/` — the proxy decides, the netns forces the path.

**The discipline (ONLY-DOOR-OR-DECLARE).** A rail may claim "boundary" only where
the resource is genuinely unreachable without a brokered capability. Where an
ambient path exists (a leaked DSN, raw egress without the netns), the claim is
downgraded to "advisory" in the docs **and** a negative test records that the
bypass *succeeds* — the limit is proven, not asserted. Both halves are kept and
both are true: DB `test_07` (boundary) ↔ `test_09_NEGATIVE` (advisory-when-leaked);
egress `test_netns_egress` (boundary-with-netns) ↔ `test_08_NEGATIVE`
(advisory-without). Overclaiming containment is a violation on par with a
fabricated result (P8).

The long-form derivations are the two adapter sections below — *Self-hosted agent
adapter* (the free case) and *Egress adapter* (the OS-interposition case): the
principle is settled here, the reasoning is there. The runtime invariants this
maps to are CLAUDE.md 11–16.

## The bypass-resistance test (acceptance bar)

Before claiming any adapter "enforces," answer in writing:
> Name every path to the dangerous effect. Does the gate sit on ALL of them,
> or can the agent reach the effect another way?

If any path is ungated, it is monitoring, not enforcement. This is exactly the
test the Claude Code classifier fails (shell gated, file-edit path open).

## Coding / DevOps adapter (the second domain) — spec

This is a **rail-bridge** adapter (P2b), stated honestly: GitHub, CI, and cloud
already own the hard enforcement. Our value is policy → required-token + the
anchored receipt, with the gate placed on the effect.

**Typed capabilities (examples):** `create_pr`, `merge_pr`, `apply_plan`,
`modify_iam`, `deploy`, `rotate_secret`, `edit_path`, `run_command`.

**Bind the EFFECT (P1), not the tool:**
- Code: the canonical action is the resulting **change set** — which paths the
  diff touches, protected-file membership (`auth/**`, `.github/workflows/**`),
  dependency/secret changes — NOT "the agent invoked the merge tool." A docs
  edit and a CI-workflow edit are different effects even via the same tool.
- Infra: the canonical action is the **plan diff** — resource types/targets,
  whether it touches IAM/security-groups/databases — NOT "ran terraform."

**Plug into the existing hard rail (not a client interposer):**
- GitHub **branch protection** + required reviewers / **required status checks**
  → the verifier's approval is delivered as a required check / signed approval
  that only passes when policy is satisfied. Gate at the server, not the agent's
  git client.
- CI/CD **environment protection rules** / required manual approval → deploy gate.
- Cloud **IAM / policy-as-code** (OPA/Sentinel) on apply → emit the condition
  the apply requires.
- **Signed commits / artifact signing** for provenance into the receipt.

**Capability derivation (P3):** the envelope ("may touch `docs/**`, `tests/**`;
may not touch `auth/**` or `.github/workflows/**`; may not merge to protected
branches; deploy requires human co-sign") comes from repo policy / task spec,
fixed before the agent runs, never rewritten by tool output.

**Receipt (P5):** anchor (capability, policy version, effect hash = diff/plan
hash, decision, approver) to the independent ledger.

**Explicit non-goal:** do NOT build a client-side wrapper around the agent's
shell/file tools as the sole gate. That is the bypassable interposer pattern.

## Self-hosted agent adapter (the third domain) — the credential/effect broker

**STATUS: proposed.** Settles the fork raised after Stage 2 — in-agent hook vs.
credential/effect broker vs. OS-level enforcement — and is what motivated P7/P8
above. No kernel change implied: this is a transport/hosting + framing decision,
not a verifier change.

**Decision.** For self-hosted, long-running agents (Hermes/OpenClaw class),
Signet enforces by being the **sole issuer of the capabilities that privileged
actions require** — not by recognizing dangerous actions. The agent holds **zero
standing credentials** for any protected resource. Each privileged effect
requires a short-lived, effect-bound capability the broker issues only after
re-checking *frozen task mandate ∩ standing policy*, consume-once, with a receipt.
We adopt the **credential/effect broker** as the enforcement position (P2's
custodial archetype, generalized off-payments). The in-agent hook (Stage 1/2 —
the `signet attack-me` gate) is retained as **defense-in-depth and the demo
on-ramp only**, never the boundary — P7/P8 make explicit *why* it never was.
OS-level "only-door" enforcement is named as a **per-rail dependency** where the
resource is otherwise reachable without a capability (e.g. raw egress), not as a
competing layer to build separately.

**Threat model (the regime this defends).** Assume the LLM is compromised
(indirect prompt injection is unsolved); the agent authors and runs code, spawns
subprocesses, writes its own skills, ingests untrusted content continuously; it
is long-running, so an injection's dwell time is unbounded and standing authority
accrues over weeks.
- *Trusted:* the broker, running as a **separate OS principal** from the agent;
  the pinned standing policy; the receipt signing key (broker-held, never in the
  agent's environment); the operator who issues the task mandate out-of-band. The
  frozen mandate is captured **before** the agent reads any untrusted input
  (plan-then-execute, P3), so mandate capture is in the trusted window.
- *Not trusted:* the agent process, its config, its self-written skills, its
  memory store — anything it can influence or author.
- *The load-bearing consequence:* secrets for protected resources MUST NOT live
  in the agent's environment, env vars, config, or memory. If they do, no broker
  helps — the agent already holds the key. **Zero-standing-credentials is the
  precondition, not a feature.**

**Why the broker, not the other two positions.**
- *In-agent hook (Stage 1/2):* best UX, deterministic veto on a cooperating
  agent, great demo on-ramp — but the agent can author code that bypasses the
  hooked path. Not a boundary. Keep as defense-in-depth.
- *Credential/effect broker (CHOSEN):* "agent holds nothing to steal"; reuses the
  Role-2 authorizer contract verbatim; no syscall interception; binds the
  **effect**, not the command string; buildable from current code. For the
  resources that matter, zero-standing-creds is the only-door *for free*; OS help
  is needed only where noted per rail.
- *OS-level only-door (seccomp, separate user, egress proxy):* the only true
  boundary against an adversarial LLM with code-exec — hardest, per-rail,
  partnership-shaped. Build as a per-rail dependency, not a product yet.

The broker wins because it is the held-capability property (commoditized in
payments à la Fireblocks, **unbuilt** for infra/DevOps) and requires almost no
new kernel: the broker **is** the existing Role-2 authorizer
(`verify_token → recheck_against_context → produce_capability`) exposed as a
service over a transport instead of called in-process. The work is hosting, the
capability-request client, and per-rail credential custody — not new
verification logic.

**The broker contract (what every rail inherits):**
1. Operator issues a **task mandate** out-of-band at task start (frozen,
   plan-then-execute). For a long-running agent this is a per-task *session
   grant*, not a standing grant.
2. Agent, needing a privileged effect, sends a **capability request** (effect
   kind + bound parameters: destination, resource id, amount, target ref —
   whatever the rail binds).
3. Broker runs the **unchanged authorizer template**: authenticate the agent as
   an OS principal (not a bearer secret it could leak — Fork B);
   `recheck_against_context` — the effect must lie within *frozen mandate ∩
   standing policy*, re-checked against live context at issue time (TOCTOU
   defense, exactly as the kernel does today); `produce_capability` — mint a
   short-lived, narrowly-scoped, effect-bound credential (the real key never
   leaves the broker); consume-once on the `chain_hash`; emit a signed receipt.
4. Agent uses the capability for exactly that effect; it expires; the next effect
   needs a fresh request.

This is monotonic (cf. the local gate's LOCAL-MONOTONIC): the per-task mandate
can only narrow standing policy, so even a maximally hostile task grant cannot
widen the fence.

**Per-rail "only-door" map (drives rail-spec priority — boundary-strength per
effort):**

| Rail | Only-door (what makes it a boundary) | OS dep? |
|------|--------------------------------------|---------|
| **Credential** (DB, deploy, cloud API, payment) | agent has NO standing secret; the resource requires a brokered short-lived cred — it literally cannot authenticate without the broker | none — free. **The wedge.** |
| **Egress / network** | agent cannot make raw outbound connections; all egress forced through a broker-controlled proxy demanding a capability bound to the destination | **yes** — net ns / proxy. State it. |
| **Shell / exec** | do NOT string-match commands; dangerous shell ops are dangerous because they touch protected resources, which now require brokered creds — shell collapses into the credential/egress rails | partial — only for non-cred effects |
| **Skill-write** (Hermes-unique) | a self-authored skill IS a fence change; SELF-PROTECT says the agent can't move its own fence. New/edited skills are quarantined and need human approval before they can obtain ANY capability | none, if skills run via brokered caps |
| **MCP / tool** | the tool's privileged backend requires a brokered cred; Signet binds the effect regardless of which tool | none, if backend gated |

Priority: **credential rail first** (free only-door, biggest enterprise pain —
"tool invocations trusted by default"), then **egress** (answers the documented
link-preview exfil; needs the proxy), then **skill-write** (novel,
Hermes-unique, high demo value), then MCP, then the shell reframe folds in for
free.

**What changes / what doesn't.**
- *Unchanged:* the 10 kernel files; the verifier pipeline; the Role-2 authorizer
  template; the receipt/transparency machinery; the local hook (Stage 1/2) and
  its honest framing — now with P7/P8 making explicit why it was never the
  boundary.
- *New:* a broker service hosting the authorizer over a transport; a
  capability-request client the agent calls; per-rail credential custody (broker
  holds the real secret, mints scoped short-lived ones); the per-task
  session-grant mechanism for long-running agents.

**Acceptance — the broker-bypass battery** (the muscle-layer analogue of the 21
kernel attack tests; each must be contained-or-fail-loud): forge a capability
the broker never issued; replay a consumed capability (consume-once); request an
effect outside *mandate ∩ policy*; **reach the resource without a capability**
(the only-door test — and the test that *proves* the OS dependency where one
exists: with ambient authority not removed, this MUST show the broker is
advisory, and that result is documented per P8, not hidden); escalate via a
self-written skill that tries to obtain a capability it wasn't granted;
**persistence/dwell test** — an injection on turn 1 plants a payload that fires
on turn N; assert per-task mandate + consume-once prevent the delayed effect.

**Forks for the rail specs to settle (flag, don't block):**
- **A — capability format:** reuse the existing signed-token + `chain_hash`
  machinery (preferred — same verifier discipline) vs. a standard (biscuit/
  macaroons, OAuth-scoped tokens, cloud STS). Lean: reuse internally, wrap a
  standard at the edge where a backend demands it.
- **B — agent→broker auth without a leakable bearer secret:** unix-socket peer
  credentials (separate OS user, simplest, single-host) vs. mTLS with a
  non-exportable key vs. SPIFFE/workload identity. Lean: peer-creds for
  single-host v0; SPIFFE-shaped later for fleets.
- **C — credential custody backend for v0:** which real secret does the broker
  mint scoped versions of (cloud STS / DB proxy / signed deploy token)? Pick ONE
  for the first credential rail; don't generalize prematurely.
- **D — operator mandate delivery for a long-running agent:** how the human
  injects the per-task frozen grant out-of-band (CLI sidecar? approval in the
  messaging channel? signed task file?).

**Out of scope (now):** full syscall sandboxing / the OS wrapper as a standalone
product; multi-agent fan-out and cross-agent capability delegation; building more
than one rail before the credential rail + broker-bypass battery prove the
position.

**Status update — the credential rail is BUILT.** The Supabase DB rail ships the
above: `signet/broker/` (the broker, Unix-socket peer-cred auth, signed receipts)
and `signet/rails/supabase/` (the `SupabaseAuthorizer` filling only the two hooks,
ES256 scoped-JWT minting, role→GRANT resource sim). The broker-bypass battery is
green (`tests/test_broker_supabase.py`) including the P8 negative test (a leaked
DSN bypasses the broker → advisory-without-only-door). It is a FREE only-door per
P9: Postgres/RLS enforces scope on the minted JWT; zero-standing-elevated-creds is
the boundary.

## Egress adapter (the fourth domain — the FIRST not-free only-door)

**STATUS: BUILT** — the egress rail (`signet/rails/egress/`, `signet/broker/proxy.py`)
and the netns sandbox (`signet/sandbox/`) ship the below. Settles the egress
architecture, as the gate-position note preceded the DB spec. Inherits P7/P8/P9
and ONLY-DOOR-OR-DECLARE. Egress is the first rail where the only-door is **not
free** (P9: OS-interposition class), so this section's job is to settle the OS
dependency — what it is, how it's declared and tested honestly, and what egress
does and does NOT contain.

**Decision — BROKER-AS-PROXY.** The agent has no network path except a proxy the
broker operates. The proxy admits each outbound connection only after re-checking
the destination against frozen mandate ∩ standing policy, consume-once per
connection, with a receipt. The capability is consumed **inline at admission** —
issuer and enforcer are the SAME process — so there is no bearer token handed to
the agent. The bound effect is the **destination (host + port)**; the proxy does
its own DNS resolution, so the agent cannot reach a forbidden host by raw IP or
poisoned local DNS (the egress analogue of the DB search_path trick). The
only-door is a **network namespace** (or nftables egress block / transparent
redirect) making the proxy the sole egress.

**Why issuer and enforcer collapse (the structural difference from the DB rail).**
In the DB rail the enforcer (Postgres) is external and trusted, so the broker
could be issuer-only and the agent carried a scoped JWT to a separate resource.
In egress there is **no separate trusted enforcer** — the network connects the
agent to anywhere — so the broker IS the enforcer, on the data path. On each new
connection the proxy runs the UNCHANGED authorize flow (serialize an `EgressEffect`
into the AP2 chain → kernel `Verifier.evaluate` for the signed token + TTL +
consume-once on `chain_hash` → `EgressAuthorizer.authorize`:
`recheck_against_context` (destination ∈ mandate ∩ policy) → `produce_capability`
== "admit and forward to the bound destination"). A refused connection writes a
ConsideredRejected receipt (cause `out-of-mandate-destination`) and is dropped.
The kernel and the authorizer template stay unedited; a new `EgressAuthorizer`
fills only the two content hooks, exactly as `SupabaseAuthorizer` did.

**What egress binds.** Destination = host + port; the proxy resolves the hostname
itself (trusted resolution) and connects only if the host is in the effective
allow-set and the port is permitted. A raw-IP request is checked against the
resolved allow-set; an IP not corresponding to an allowlisted host is refused
(closes raw-IP + poisoned-DNS evasion). v0 granularity: host+port allow-set,
monotonic (a per-task grant only narrows the standing set). **No TLS termination,
no payload inspection** — the proxy is a destination gate, not a content filter
(content inspection needs TLS MITM and drifts into the detection camp Signet
avoids).

**The only-door (OS dependency — declared, and now ENFORCED by the netns).** The
boundary holds iff the agent has no egress except the proxy (invariant
**EGRESS-SOLE-PATH**). The deterministic suite runs offline against a proxy sim +
destination sim; its NEGATIVE test (the egress analogue of DB #9) removes the
netns assumption and shows a DIRECT connection to the attacker host SUCCEEDS —
the proxy is advisory without the OS layer. Green because the bypass works; if it
ever flips to "blocked" without the netns, a silent gate is hiding. The other half
is now built: `signet/sandbox/netns.py` puts the agent in a network namespace
whose only route out is the proxy, and `tests/test_netns_egress.py` (privilege-
gated, CAP_NET_ADMIN) verifies the same direct-bypass move is BLOCKED there —
boundary-with-netns. Both halves are kept (ONLY-DOOR-OR-DECLARE). The
load-bearing property is **AGENT-UNPRIVILEGED-IN-NETNS** (CLAUDE.md 16): the
controller configures the netns, the agent runs with an empty capability bounding
set and cannot reconfigure its way out. Remaining productization: rootless
operation and broker/controller hardening (the netns enforcement is a
privilege-gated *measurement*, not yet a CI invariant — CI can't get
CAP_NET_ADMIN).

**Contains / does NOT contain (P8).** Contains: agent-initiated outbound
connections to non-allowlisted destinations (incl. raw-IP and poisoned-DNS
evasions, and forbidden ports on allowed hosts). Does **NOT** contain:
1. **The link-preview variant** — the agent EMITS an attacker URL into a channel
   and the *messaging platform's* link-preview fetcher retrieves it; that request
   originates off the agent process, so an egress proxy never sees it. Needs an
   output/emission rail. Do NOT claim egress stops link-preview; claim it stops
   agent-initiated exfil/C2.
2. **Exfil through an allowlisted destination** — binding is WHERE, not WHAT;
   secrets POSTed to a permitted API or allowlisted pastebin are not stopped.
3. **Covert channels / DNS-label tunneling** — data encoded in subdomain labels
   of an allowlisted domain can leak via the resolver. Known limit; deep DNS
   defense is out of scope.
Naming these is what keeps the Hermes demo credible rather than a lie.

**Forks (defaults).** A — admission: inline, no bearer token (DEFAULT). B —
consume-once granularity: per-connection (DEFAULT; keep-alive/pooled HTTP reuses
one connection for many requests — per-request would need HTTP parsing, edging
toward content inspection, so keep per-connection for v0). C — DNS: proxy resolves
trusted, binds host→resolved-IP (DEFAULT). D — protocol: HTTP/HTTPS via CONNECT +
raw TCP to host:port, no UDP, no TLS termination (DEFAULT). E — netns mechanism:
deferred to productization, v0 simulates (DEFAULT).

**Productization handoff (what the next phase inherits).** Make EGRESS-SOLE-PATH
real (netns/firewall forcing the agent through the proxy — turns advisory v0 into
a boundary); broker hardening + key custody (the broker is now the sole egress
path AND holds signing+secret keys — the highest-value target); and the
agent-sandbox packaging (agent-in-netns + broker proxy + task-grant delivery as a
deployable, not a research setup).

**Out of scope (now):** the output/emission rail (link-preview / content exfil);
TLS interception / payload inspection; deep DNS-tunnel defense; UDP; multi-host /
fleet egress.

## Sequencing (de-risk before broadening)

1. **Now — plan-then-execute intent provider, in payments/banking.** Replace the
   ground-truth oracle with an envelope extracted from trusted input only, then
   re-measure ENFORCEMENT / FALSE-POSITIVE honestly. This de-risks the universal
   intent→capability problem (P3) in the domain where our moat is strongest
   (custodial). The numbers stop being an upper bound here.
2. Refactor the kernel to `Action` + `DomainAdapter`, with the two archetypes
   (custodial / rail-bridge) as first-class.
3. Build the coding/DevOps rail-bridge adapter per the spec above; validate it
   against the bypass-resistance test (bind the diff/plan, plug a real hard rail).
4. **[DONE] Self-hosted-agent broker — the credential rail** (per the third-domain
   spec above): the broker hosts the Role-2 authorizer, the agent holds zero
   standing elevated creds, and the broker-bypass battery is green. The P7/P9
   FREE only-door made concrete (Supabase/Postgres enforces the scoped JWT).
5. **[DONE] Egress rail — the first OS-interposition only-door** (per the
   egress-adapter spec above): broker-as-proxy with inline admission,
   destination-binding with proxy-side resolution, a proxy+destination sim, and
   the bypass battery INCLUDING the advisory-without-netns negative test. This is
   where the only-door stops being free (P9). **EGRESS-SOLE-PATH is now enforced**
   by `signet/sandbox/netns.py` (the agent runs unprivileged in a netns whose only
   route out is the proxy), verified by the privilege-gated `test_netns_egress.py`;
   the deterministic advisory #8 persists where the netns is absent.
6. **Productization** (next) — opens by hardening the netns path from a
   privilege-gated measurement into a deployable: rootless operation (no root),
   broker/controller hardening + key custody (the broker is now the sole egress
   path AND holds the keys — the highest-value target), and the agent-sandbox
   launcher as a packaged deployable. Enables the real Hermes exfil-containment
   demo (agent-initiated exfil blocked — not the link-preview variant).
7. Ship the anchored (Merkle) receipt as the cross-domain evidence layer.

## What NOT to build (so we don't drift into the crowded category)

- Another tool-call interception SDK.
- Another allow/block/review risk classifier.
- A vendor-signed-log audit trail.

All three already exist and are not the moat. The moat is: enforcement the agent
cannot bypass (held capability or server-side hard rail, on the effect surface)
+ proof you don't have to trust us to verify.