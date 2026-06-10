# LOCAL_GATE — the `signet` CLI and the Claude Code PreToolUse gate (Stage 1)

Two-minute onboarding: contain a coding agent's auto mode behind a deterministic
path/command fence, with a signed receipt for every decision. No account, no GitHub
App, no LLM call anywhere in the gate path.

```bash
pipx install signet-runtime     # exposes the `signet` console script
cd your-repo
signet init                     # propose + confirm .signet/policy.yaml, wire the hook
```

From then on, every Edit/Write/MultiEdit/NotebookEdit/Bash tool call Claude Code makes
in that repo passes through `signet hook` before it executes.

## Read this first: what this gate is, and is not

**This local hook is containment UX and tamper-EVIDENT logging — it is NOT the
enforcement boundary.** This is DESIGN.md P2 stated plainly: a client-side gate is
defense-in-depth, never the boundary, because an agent with raw shell access can
bypass any client-side hook (disable it, spawn a process the hook never sees, etc.).
The enforcement boundary is the server-side rail — GitHub branch protection fed by a
Signet required check (Stage 3). Stage 1 buys you:

* **Containment of the common path.** Claude Code auto mode reaches effects through
  its tool calls; those are gated, deterministically, in <100ms (measured ~50ms warm).
* **Tamper-evidence, not tamper-proofness.** Every decision appends a signed,
  hash-chained receipt under `~/.signet/` — outside the repo worktree, so outside the
  agent's default reach. Anyone who edits or deletes records breaks the chain, and
  `signet receipts --verify` reports the first break. A motivated human (or an agent
  with unrestricted shell) can still destroy the log; making the record non-falsifiable
  is what the server-side rail's anchored transparency log is for.

**Bash gating is heuristic pattern containment, not effect binding.** A bash command's
*effect* cannot be deduced from its text by globbing (P1: bind the effect, not the
tool). The bash patterns catch the obvious dangerous shapes (`*git push*--force*`,
redirects into `.signet/`); they will not catch an adversarially-obfuscated command.
The file-edit path is the precisely gated one: paths are normalized (cwd-relative,
`..`-traversal, symlink resolution at the deepest existing ancestor) and evaluated on
both the literal and resolved forms, stricter verdict wins.

## The fence — .signet/policy.yaml (schema v1)

```yaml
version: 1                      # required, must equal 1
repo: owner/name                # optional; warn if a git remote disagrees
protect:                        # deny globs -> tiers.protected_edit
  - "auth/**"
  - "infra/**"
  - ".github/workflows/**"
  - "db/migrations/**"
allow:                          # allow globs; default ["**"]
  - "**"
branches:
  protected: ["main", "release/*"]   # informational in Stage 1 (feeds bash deny
                                     # patterns + later the server rail)
bash:
  deny:                         # fnmatch patterns over the raw command string
    - "*git push*--force*"
    - "*gh pr merge*"
    - "*terraform apply*"
    - "*git push*origin*main*"
  ask: []                       # patterns escalated to a human
tiers:
  protected_edit: deny          # deny | ask — edits touching `protect`
  out_of_allow_edit: ask        # edits outside `allow`
```

Matching semantics are identical to the server rail's `MergePolicy` (lifted, not
reinvented — proven by a parity test): case-insensitive, backslash-normalized, a
glob's literal prefix before `**` matches as a directory prefix, deny wins over allow,
extra allow layers are conjunctive. Unknown keys are an **error** (a typo'd key
silently ignored would be a fail-open fence). Note fnmatch's `*` crosses `/` — use
`*.pem`, not `**/*.pem`, to cover top-level files.

### Self-protection (not configurable)

`.signet/**`, `.claude/settings.json`, `.claude/settings.local.json` (repo-relative —
the latter now holds the hook command) and the signet home dir (`~/.signet/**`) are
**always-deny for edit-class tools**, hardcoded in the hook and evaluated *before* the
user policy loads. The agent must not be able to move its own
fence. `signet init` additionally offers native `permissions.deny` rules for exactly
this set — Claude Code evaluates those even if the hook crashes. Project protect-globs
deliberately do *not* get native deny rules (that would make `ask` tiers unreachable).

## How `signet init` wires the hook (and why it can't silently fail)

A hook command that fails to launch is a **non-blocking** error in Claude Code: the
tool call proceeds *unguarded*. If `init` wrote a bare `"signet"` and the hook shell's
PATH lacked the pipx/venv shim, you'd believe the fence was up while it wasn't — the
worst possible outcome. So:

* **The hook entry carries an absolute, resolved command** (`shutil.which("signet")`, or
  `<python> -m signet.cli.main hook` as a fallback) and goes to
  **`.claude/settings.local.json`** — personal, machine-specific, git-ignored (init
  offers to add the ignore line if your repo's `.gitignore` doesn't already cover it).
* **The portable always-deny rules go to the shared `.claude/settings.json`** — those
  are exactly what a team should inherit.
* **`signet status` reports reachability**, not just presence: `WIRED` (command
  resolves here), `UNWIRED` (no entry), or **`BROKEN`** (entry present but the command
  does not resolve on this machine — printed loudly, and `status` **exits 2** so it's
  scriptable in CI). The fix is always `signet init` again.
* `signet init --shared` opts into the old bare-`signet hook` form in the shared file
  for teams that manage PATH deliberately; it prints the PATH assumption it's making.
* Re-running `init` on a repo with the Stage 1 layout (bare `signet hook` in the shared
  file) **detects and offers to migrate** it to the split layout; idempotent thereafter.

## The hook contract

* stdin: the PreToolUse JSON payload (fields used: `tool_name`, `tool_input`, `cwd`).
* deny/ask: exit 0 + `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": "deny"|"ask", "permissionDecisionReason": "signet: ... —
  receipt <id>"}}`.
* pass / out-of-scope tool: exit 0, **empty stdout** — the normal permission flow
  proceeds. The hook **never emits "allow"**: it can only narrow what your own
  permission rules would do (LOCAL-MONOTONIC).
* Internal error, unparseable stdin, invalid policy: **ask** with
  `signet hook error: ... — escalating` (fail toward the human, never silently open).
  If stdout emission itself fails, the fallback is exit 2 with the reason on stderr —
  which blocks the tool; an un-emittable "ask" degrades to deny, never to pass.
* A repo with **no `.signet/policy.yaml` is a silent no-op** — uninitialized means
  unprotected; `signet init` is the consent step.

## Receipts

Every evaluated call — deny, ask, *and* pass — appends one record
(`signet.local_decision.v1`) to `~/.signet/<repo-slug>/receipts.jsonl`, signed with a
local Ed25519 key (`~/.signet/keys/local_ed25519.json`, mode 0600) and chained by
`prev_hash`. Each record carries the `policy_hash` (sha256 of the canonical parsed
policy) that decided it. File contents and bash command text are never logged — a
command appears only as its sha256.

```bash
signet receipts            # the activity record
signet receipts --verify   # recompute chain + signatures; reports the first break
signet explain <path>      # which rule fires, same code path as the hook
signet explain --bash "git push --force"
signet status              # effective fence, policy_hash, hook wiring, receipt count
```

## Stage 3 — the actual enforcement boundary

When you want enforcement an agent cannot route around, the upgrade path is the
server-side rail: the same policy.yaml semantics evaluated where the agent has no
hands — a required GitHub check that only passes when the diff is inside the fence,
with anchored, independently verifiable receipts. The local gate keeps its role as
the fast, low-friction containment layer in front of it.
