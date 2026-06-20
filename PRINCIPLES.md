# Agentic control planes — what Signet taught

A distilled map of the principles, failure modes, and open questions earned building Signet.
Status tags: **[proven]** = backed by a passing test / trace · **[designed]** = built, not yet load-bearing ·
**[open]** = not yet built. Keep the distinction; it's the difference between an invariant and a hope.

> **Where this sits.** `DESIGN.md` is the principle constitution (P1–P9); `ARCHITECTURE.md` is the
> component map; `signet/rail_algebra/IMPLEMENTATION.md` and `signet/rail_algebra/SCHEDULE.md` are the
> two reports this synthesis consolidates. This file is the cross-project distillation — the lessons
> that transfer beyond Signet. The code is ground truth; the tests are the spec.

---

## The thesis (the one load-bearing idea)

Enforcement must be **structural** and live **below the layer you assume is compromised**. The agent and
its orchestrator are in the untrusted zone — so any safety property that depends on their cooperation is
not a safety property. Detection is not enforcement. The gate holds the key; the agent never does.

Everything below is a consequence of taking that seriously.

---

## The field, as seven concepts (your own pipeline is one instance of each)

| # | Concept | The question it answers | In Signet |
|---|---|---|---|
| A | **Trust boundary** | what do you refuse to trust? | the proposal is *data*, never a command; Role A/B split |
| B | **Mediation / only-door** | what makes the policy unbypassable? | Check-Run keyholder; netns sole-path; advisory ≠ boundary |
| C | **Policy expression** | how is "allowed" stated? | fence as typed data over a provenanced schema |
| D | **Binding & freshness** | what is an approval bound to, for how long? | effect-key, consume-once; TOCTOU re-check |
| E | **Evidence** | non-repudiation under a compromised runtime | signed, hash-chained, externally-anchored receipts |
| F | **Identity & delegation** | what authority does the agent carry? | a strict subset of the principal's; monotonic narrowing |
| G | **Orchestrator integration** | where do you intercept? | LangGraph tool-wrap / interrupt; the Claude Code hook |

Mastery = deriving each from principles, naming its failure mode, knowing which choices are forced vs contingent.

---

## The refinements this project earned

- **Policy × Bind × Door = PDP / capability / PEP.** You rediscovered access control's PDP/PEP split (the
  decision point vs the enforcement point) plus a capability tying them — for *agent actions* instead of
  human requests. "Declarative" is not the abstraction; it is one Policy *variant*, beside pattern-allowlist,
  quantitative, and content. **[proven]** (merge + egress compose the axes, verdicts preserved vs golden)

- **Provenance-monotonicity — the single most transferable rule.** Untrusted features may only **tighten
  (deny)**, never loosen (allow). "Fence on OWN attributes only" is the special case; DLP fits as the
  deny-side; and the egress host-identity split (untrusted `agent_host` narrows, OWN `raw_ip_resolved_match`
  permits) turned out to be the raw-IP-evasion defense *expressed as a type*. **[proven]**

- **The lifecycle dimension — the abstraction's hidden axis.** The three strategies are not co-located in
  time. **Resolution rails** (merge) fire Policy@RESOLVE, then Bind+Door@AUTHORIZE; **admission rails**
  (egress) fire all three @ADMIT. The flat triple silently assumed the admission shape. Minimal phase set:
  `{RESOLVE, ADMIT, AUTHORIZE}` — `CLOSE` evaporated on contact with the trace, because a phase is *where an
  axis executes*, not where the narrative says something matters. **[proven]**

- **Some effects don't fit the declarative fence, and a good framework says so.** Egress (open destination
  universe, continuous stream, adversarially-named identity) needs a bespoke shape: pattern-allowlist +
  trusted resolution + a network only-door. A good abstraction provides the escape hatch instead of
  contorting the fence. **The abstraction is taught by the effect that doesn't fit.**

- **Structural vs mitigatable risks.** A post-approval force-push is *structurally closeable* (the effect-key
  bind blocks it). Exfil to an allowed host is a *covert channel* — only mitigatable. **Narrowing the channel
  beats inspecting it.** Knowing which class a risk is in is the whole skill.

- **Model before you promote.** Don't drive an incomplete abstraction into the trusted base. The schedule was
  modeled and validated in the algebra layer *before* touching `base.Authorizer`, precisely so the
  egress-shaped "all-fire-together" assumption never got hardened into the kernel. **[designed]**

---

## Failure modes caught (the discipline, earned empirically)

These are the lessons that transfer to *any* system, not just this one:

- **A green that doesn't trace is worse than a red.** The vacuous `HONEST`: a snapshot step errored, so the
  diff compared a file to its own copy and "passed." A verification is only as good as the evidence that it
  *executed* (the snapshot printed `wrote …`; the failed one printed nothing).
- **A characterization baseline is only honest if generated from pre-change code** — and the only proof is
  regeneration from a clean tree plus git ordering. Same-session goldens prove the code matches itself.
- **Agent (Claude Code) reports are claims; source is truth.** Caught across the arc: a phantom-missing
  `hook.py` (false negative), a 206-vs-401 mislabeled partial run, and a cross-report contradiction
  (`in_scope` "at close" vs "at resolve") settled by one `grep`.
- **Declarations must be validated against execution.** The schedule isn't trusted metadata — a faithfulness
  test asserts declared phases == observed invocation phases. With the honest stated limit: it catches code
  drift, not a coordinated mis-declaration.
- **Don't develop on the publish branch.** Dev work on `demo` is one `git push` away from deploying WIP live.
- **A guarantee you can't reconstruct from a clean commit isn't a guarantee** — which is the project's own
  thesis turned on its own process.

---

## Open horizon (status: [open] unless noted)

- **Per-phase template promotion** — make the schedule *drive* `base.Authorizer` (`run_phase(RESOLVE)` /
  `run_phase(AUTHORIZE)`), the first deliberate trusted-base edit. Shape is validated; this is the next
  human-gated step. **[designed, deferred]**
- **Quantitative policy + metered bind** — payment velocity / egress rate. Unexercised axis ends; forces the
  atomic multi-instance store (the single-process SQLite limit bites here).
- **Content policy as deny-side** — DLP for exfil, bounded by the covert-channel limit (mitigation, not boundary).
- **The framework-agnostic control plane** — more orchestrator adapters (CrewAI, Agents SDK) on the same seam;
  the seam multiplies adapters × rails for free. (LangGraph adapter exists today: `integrations/langgraph/`.)
- **Merge's other two fence seams** (`GitHubDomain.within_fence`, `MergePolicy.is_fenced`) — not yet on the algebra.

---

## The one-paragraph version

A control plane is the composition of *what you refuse to trust* (the boundary), *how you state what's
allowed* (typed, provenanced policy where untrusted data can only deny), *what an approval is bound to and
for how long* (effect-keyed, fresh-checked capabilities), and *the mechanism that makes it unbypassable*
(the only-door). Those four are independent axes scheduled across a lifecycle, not a single check — and the
whole thing is only as trustworthy as your ability to prove, from a clean state, that every green light
traces to something that actually ran.

---

## Where this lives in the code

| Principle | Code |
|---|---|
| Policy × Bind × Door axes | `signet/rail_algebra/{policy,bind,door}.py`; `types.Composition` |
| Provenance-monotonicity | `rail_algebra/types.provenance_audit`; `policy.PatternAllowlist` (the `agent_host`/`raw_ip_resolved_match` split) |
| Lifecycle schedule | `rail_algebra/schedule.py`; `MERGE_SCHEDULE` / `EGRESS_SCHEDULE`; faithfulness in `tests/test_rail_schedule.py` |
| Structural bind (force-push closed) | `signet/chain.py` context-binding; `verifier.py` step 7 |
| Only-door (mediation) | `authorizers/github_railbridge.py` (Check-Run, EXTERNAL); `signet/sandbox/netns.py` (SOLE_PATH); `door.NetworkSolePath` advisory-vs-sole-path |
| Evidence | `signet/receipts.py`; `evals/github_railbridge/transparency.py` |
| Orchestrator integration | `integrations/langgraph/guarded_tool.py`; `signet/cli/` (the PreToolUse hook) |
| Verification discipline | `evals/scorecard/`; `tests/_golden/` (the committed corpus) |
