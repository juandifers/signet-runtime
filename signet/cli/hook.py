"""`signet hook` — the Claude Code PreToolUse local gate.

Contract (verified against Claude Code 2.1.170 with REAL captured payloads —
tests/fixtures/hook_payloads/):
  stdin   one JSON object; we read tool_name, tool_input, cwd.
  stdout  on deny/ask: exit 0 +
          {"hookSpecificOutput": {"hookEventName": "PreToolUse",
            "permissionDecision": "deny"|"ask", "permissionDecisionReason": ...}}
          on pass: exit 0, EMPTY stdout — the normal permission flow proceeds.
  exit 2  fallback only, when stdout emission fails: reason on stderr (blocks the tool).

INVARIANTS (see CLAUDE.md):
  LOCAL-MONOTONIC  this hook NEVER emits permissionDecision "allow". It can only narrow
                   what the user's own permission rules would do. An "ask" that cannot be
                   emitted degrades to DENY (stricter), never to pass.
  SELF-PROTECT     .signet/**, .claude/settings.json (repo-relative) and the signet home
                   dir are always-deny for edit-class tools, evaluated BEFORE the user
                   policy loads. The agent must not be able to move its own fence.
  GATE-PURITY      no LLM call, no network call, no evals/* import anywhere in this path.
                   Deterministic; <100ms warm.
  LOCAL-RECEIPT    every evaluated tool call appends exactly one signed, hash-chained
                   record bound to the policy_hash that decided it.

Fail-closed posture: internal error / unparseable stdin / invalid policy -> ASK with
"signet hook error: ... — escalating" (fail toward the human, never silently open).
EXCEPTION (by design): a repo with NO .signet/policy.yaml is a silent no-op —
uninitialized == unprotected; `signet init` is the consent step.

HONESTY (DESIGN.md P2): this is the client-side containment layer — defense-in-depth and
UX, tamper-EVIDENT via local receipts, NOT the enforcement boundary. An agent with raw
shell access can bypass any client-side hook; the server-side rail (Stage 3) is the
boundary. Bash gating in particular is heuristic PATTERN containment over the command
string, not effect binding — the file-edit path is the precisely gated one.
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from ..fence import (DISP_DENIED, DISP_IN_FENCE, DISP_OUT_OF_ALLOW, POLICY_RELPATH,
                     PolicyError, PolicyFile, matches_any)

EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
BASH_TOOL = "Bash"

# SELF-PROTECT: repo-relative globs that are always-deny for edit-class tools,
# hardcoded, evaluated before the user policy loads. NOT configurable in yaml.
# `.claude/settings*.json` covers BOTH settings.json (shared) and settings.local.json
# (which now holds the absolute hook command) — the agent must not be able to delete
# its own wiring (SELF-PROTECT) regardless of which file the wiring lives in.
SELF_PROTECT_GLOBS = (".signet/**", ".claude/settings.json", ".claude/settings.local.json")

# SELF-PROTECT for Bash: heuristic patterns over the raw command string catching
# writes/redirects/moves referencing the fence's own config or the signet home.
# (".signet" also covers "~/.signet" / "$HOME/.signet" as substrings.)
_SELF_PROTECT_BASH = tuple(
    pat.replace("{t}", t)
    for t in (".signet", ".claude/settings")
    for pat in ("*>*{t}*", "*rm *{t}*", "*rm -*{t}*", "*mv *{t}*", "*cp *{t}*",
                "*tee *{t}*", "*sed *-i*{t}*", "*truncate *{t}*", "*chmod *{t}*",
                "*ln *{t}*", "*dd *of=*{t}*", "*unlink *{t}*")
)

_DISP_SEVERITY = {DISP_IN_FENCE: 0, DISP_OUT_OF_ALLOW: 1, DISP_DENIED: 2}


@dataclass
class Verdict:
    """The gate's decision for one tool call (shared by `signet hook` and `signet explain`)."""
    decision: str                 # "deny" | "ask" | "pass" | "none"  (none = out of scope)
    cause: str = ""               # glob / pattern / "in-fence" / error summary
    reason: str = ""              # human-facing permissionDecisionReason (receipt id appended later)
    effect: Optional[dict] = None  # receipt effect payload
    policy_hash: Optional[str] = None
    repo_root: Optional[str] = None
    record_receipt: bool = False  # LOCAL-RECEIPT: True for every *evaluated* call
    rel_paths: List[str] = field(default_factory=list)


# ----------------------------------------------------------------------------
# repo / path resolution
# ----------------------------------------------------------------------------
def find_repo_root(cwd: str) -> Optional[Path]:
    """Nearest ancestor of cwd containing .signet/policy.yaml, else git toplevel, else None."""
    p = Path(cwd)
    for anc in (p, *p.parents):
        if (anc / POLICY_RELPATH).is_file():
            return anc
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd,
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _signet_home_real() -> str:
    from .local_receipts import signet_home
    return os.path.realpath(str(signet_home()))


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _rel_posix(path: str, root: str) -> Optional[str]:
    """Repo-relative POSIX form of `path` if it is under `root`, else None."""
    if not _under(path, root):
        return None
    rel = os.path.relpath(path, root)
    return rel.replace(os.sep, "/")


def normalize_candidates(raw_path: str, cwd: str) -> Tuple[str, str]:
    """(literal_normalized, realpath_resolved) absolute forms of the target path.

    The literal form keeps symlink components as written; realpath resolves symlinks at
    the deepest EXISTING ancestor (os.path.realpath is non-strict, so a new file under a
    symlinked dir still resolves the dir). The fence is evaluated on BOTH and the
    stricter verdict wins — this closes the symlink-into-protected-dir escape."""
    p = os.path.expanduser(raw_path)
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)   # payload cwd, NOT the hook process cwd
    literal = os.path.normpath(p)
    real = os.path.realpath(literal)
    return literal, real


# ----------------------------------------------------------------------------
# evaluation (pure, deterministic — `signet explain` calls these too)
# ----------------------------------------------------------------------------
def _load_policy(repo_root: Path) -> PolicyFile:
    return PolicyFile.load(repo_root / POLICY_RELPATH)


def _policy_hash_or_none(repo_root: Optional[Path]) -> Optional[str]:
    if repo_root is None:
        return None
    try:
        return _load_policy(repo_root).policy_hash
    except PolicyError:
        return None


def evaluate_edit(raw_path: str, cwd: str) -> Verdict:
    literal, real = normalize_candidates(raw_path, cwd)

    # SELF-PROTECT (1/2): the signet home dir (keys + receipts) is always-deny,
    # even with no repo / no policy in sight.
    home = _signet_home_real()
    if _under(real, home):
        return Verdict("deny", cause="self-protect:signet-home",
                       reason=f"signet: {raw_path} is inside the signet home dir "
                              "(keys/receipts) — always denied",
                       effect={"kind": "edit", "paths": [raw_path]},
                       record_receipt=True)

    repo_root = find_repo_root(cwd)
    if repo_root is None:
        return Verdict("none")                      # out of scope
    policy_path = repo_root / POLICY_RELPATH
    if not policy_path.is_file():
        return Verdict("none")                      # uninitialized == unprotected; init is consent

    root = str(repo_root)
    root_real = os.path.realpath(root)
    candidates = [c for c in {_rel_posix(literal, root), _rel_posix(real, root_real)}
                  if c is not None]

    if not candidates:
        return Verdict("none", repo_root=root)      # resolves outside the repo: out of scope

    # SELF-PROTECT (2/2): fence config + hook wiring, BEFORE the user policy loads.
    for rel in candidates:
        if matches_any(rel, SELF_PROTECT_GLOBS):
            return Verdict("deny", cause=f"self-protect:{rel}",
                           reason=f"signet: {rel} is signet self-protected "
                                  "(the agent cannot move its own fence)",
                           effect={"kind": "edit", "paths": sorted(candidates)},
                           policy_hash=_policy_hash_or_none(repo_root),
                           repo_root=root, record_receipt=True,
                           rel_paths=sorted(candidates))

    try:
        policy = _load_policy(repo_root)
    except PolicyError as e:
        return Verdict("ask", cause="policy-error",
                       reason=f"signet hook error: {e} — escalating",
                       effect={"kind": "edit", "paths": sorted(candidates)},
                       repo_root=root, record_receipt=True, rel_paths=sorted(candidates))

    fence = policy.fence
    # Stricter verdict wins across the literal/realpath candidates (symlink escape).
    worst_rel, worst_disp = max(((rel, fence.disposition(rel)) for rel in sorted(candidates)),
                                key=lambda t: _DISP_SEVERITY[t[1]])

    common = dict(effect={"kind": "edit", "paths": sorted(candidates)},
                  policy_hash=policy.policy_hash, repo_root=root,
                  record_receipt=True, rel_paths=sorted(candidates))
    if worst_disp == DISP_DENIED:
        rule = fence.matched_deny_glob(worst_rel) or "protect"
        return Verdict(policy.tier_protected_edit, cause=rule,
                       reason=f"signet: {worst_rel} is protected by .signet/policy.yaml "
                              f"(rule: {rule})", **common)
    if worst_disp == DISP_OUT_OF_ALLOW:
        return Verdict(policy.tier_out_of_allow_edit, cause="out-of-allow",
                       reason=f"signet: {worst_rel} is outside the allow fence of "
                              ".signet/policy.yaml (rule: out-of-allow)", **common)
    return Verdict("pass", cause="in-fence", **common)


def evaluate_bash(command: str, cwd: str) -> Verdict:
    repo_root = find_repo_root(cwd)
    if repo_root is None or not (repo_root / POLICY_RELPATH).is_file():
        return Verdict("none")
    root = str(repo_root)
    cmd = str(command)
    low = cmd.lower()

    def _effect() -> dict:
        from ..canonical import sha256_hex
        return {"kind": "bash", "command_sha256": sha256_hex(cmd.encode())}

    # SELF-PROTECT first, before the user policy loads.
    for pat in _SELF_PROTECT_BASH:
        if fnmatch.fnmatch(low, pat):
            return Verdict("deny", cause=f"self-protect:{pat}",
                           reason="signet: command matches signet self-protect pattern "
                                  f"(rule: {pat}) — the agent cannot move its own fence",
                           effect=_effect(), policy_hash=_policy_hash_or_none(repo_root),
                           repo_root=root, record_receipt=True)

    try:
        policy = _load_policy(repo_root)
    except PolicyError as e:
        return Verdict("ask", cause="policy-error",
                       reason=f"signet hook error: {e} — escalating",
                       effect=_effect(), repo_root=root, record_receipt=True)

    common = dict(effect=_effect(), policy_hash=policy.policy_hash,
                  repo_root=root, record_receipt=True)
    for pat in policy.bash_deny:
        if fnmatch.fnmatch(low, pat.lower()):
            return Verdict("deny", cause=pat,
                           reason="signet: command is protected by .signet/policy.yaml "
                                  f"(rule: {pat})", **common)
    for pat in policy.bash_ask:
        if fnmatch.fnmatch(low, pat.lower()):
            return Verdict("ask", cause=pat,
                           reason="signet: command requires human approval per "
                                  f".signet/policy.yaml (rule: {pat})", **common)
    return Verdict("pass", cause="in-fence", **common)


# ----------------------------------------------------------------------------
# the hook entrypoint: stdin -> (exit_code, stdout, stderr)
# ----------------------------------------------------------------------------
def _decide(stdin_text: str) -> Verdict:
    try:
        payload = json.loads(stdin_text)
        if not isinstance(payload, dict):
            raise ValueError("stdin is not a JSON object")
    except ValueError as e:
        return Verdict("ask", cause="stdin-error",
                       reason=f"signet hook error: unparseable stdin ({e}) — escalating")

    tool = payload.get("tool_name")
    if tool not in EDIT_TOOLS and tool != BASH_TOOL:
        return Verdict("none")                      # any other tool: no decision, no output

    tool_input = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()

    try:
        if tool == BASH_TOOL:
            command = tool_input.get("command")
            if not isinstance(command, str):
                return Verdict("ask", cause="payload-error",
                               reason="signet hook error: Bash payload has no command "
                                      "string — escalating")
            v = evaluate_bash(command, cwd)
        else:
            raw_path = tool_input.get("file_path") or tool_input.get("notebook_path")
            if not isinstance(raw_path, str) or not raw_path:
                return Verdict("ask", cause="payload-error",
                               reason=f"signet hook error: {tool} payload has no "
                                      "file_path/notebook_path — escalating")
            v = evaluate_edit(raw_path, cwd)
        v.effect = v.effect or {"kind": "bash" if tool == BASH_TOOL else "edit"}
        return v
    except Exception as e:   # never crash with a traceback on stdout; fail toward the human
        return Verdict("ask", cause="internal-error",
                       reason=f"signet hook error: {type(e).__name__}: {e} — escalating")


def _append_receipt(verdict: Verdict, tool: str) -> Optional[str]:
    from .local_receipts import LocalReceiptLog
    root = verdict.repo_root or "_global"
    root_real = os.path.realpath(root) if root != "_global" else "_global"
    log = LocalReceiptLog(root_real, repo_label=root)
    rec = log.append(repo=verdict.repo_root, tool_name=tool,
                     effect=verdict.effect or {}, verdict=verdict.decision,
                     cause=verdict.cause, policy_hash=verdict.policy_hash)
    return rec["id"]


def run_hook(stdin_text: str) -> Tuple[int, str, str]:
    """Pure-ish core (only filesystem receipts as a side effect); main() does the IO."""
    verdict = _decide(stdin_text)

    tool = ""
    try:
        tool = json.loads(stdin_text).get("tool_name", "")
    except Exception:
        pass

    if verdict.decision == "none":
        return 0, "", ""

    reason = verdict.reason
    if verdict.record_receipt:
        try:
            receipt_id = _append_receipt(verdict, tool)
            reason = f"{reason} — receipt {receipt_id}"
        except Exception as e:
            # LOCAL-RECEIPT failed: never silently open. A pass without its receipt
            # escalates; a deny stays a deny (monotonic).
            if verdict.decision != "deny":
                verdict.decision = "ask"
            reason = (f"{verdict.reason} — signet hook error: receipt write failed "
                      f"({type(e).__name__}) — escalating")

    if verdict.decision == "pass":
        return 0, "", ""                            # never print "allow" (LOCAL-MONOTONIC)

    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                  "permissionDecision": verdict.decision,
                                  "permissionDecisionReason": reason}}
    return 0, json.dumps(out), ""


def main() -> int:
    stdin_text = sys.stdin.read()
    code, out, err = run_hook(stdin_text)
    if out:
        try:
            sys.stdout.write(out)
            sys.stdout.flush()
        except OSError:
            # Emission failed. deny AND ask both fall back to exit 2 (blocks the tool):
            # an "ask" that cannot be emitted degrades to deny, never to pass.
            try:
                reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
            except Exception:
                reason = "signet hook: decision emission failed"
            sys.stderr.write(reason + "\n")
            return 2
    if err:
        sys.stderr.write(err)
    return code
