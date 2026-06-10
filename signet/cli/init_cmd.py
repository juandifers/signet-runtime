"""`signet init` / `status` / `receipts` / `explain` — the two-minute local onboarding.

`init` is the CONSENT step: a repo without .signet/policy.yaml is deliberately
unprotected (the hook no-ops there). Everything proposed is shown as a diff and
confirmed before writing; --yes takes the defaults, --force overwrites.

Honest boundary statement (printed by init, repeated in --help and LOCAL_GATE.md):
the local hook is containment UX with tamper-EVIDENT receipts — defense-in-depth,
not the enforcement boundary. The server-side rail (Stage 3) is the boundary.
"""
from __future__ import annotations

import difflib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from ..fence import POLICY_RELPATH, PolicyError, PolicyFile, render_policy_yaml

HOOK_MATCHER = "Edit|Write|MultiEdit|NotebookEdit|Bash"
HOOK_COMMAND = "signet hook"          # bare form (Stage 1 / --shared); needs `signet` on PATH

# Wiring split (Stage 1 hardening):
#  * the PreToolUse hook entry carries a user-specific ABSOLUTE command and goes to
#    .claude/settings.local.json (personal overrides, git-ignored — does not travel).
#  * the native ALWAYS-DENY rules are portable path patterns and go to the shared
#    .claude/settings.json (a team should inherit them).
SETTINGS_SHARED = "settings.json"
SETTINGS_LOCAL = "settings.local.json"
GITIGNORE_LINE = ".claude/settings.local.json"

# Native belt-and-braces deny rules for the ALWAYS-DENY set ONLY. Claude Code evaluates
# permissions.deny regardless of hook output, so self-protection survives even a crashed
# hook. Project protect-globs deliberately do NOT get native rules — that would make the
# `ask` tiers unreachable.
NATIVE_DENY_RULES = (
    "Edit(.signet/**)", "Write(.signet/**)",
    "Edit(.claude/settings.json)", "Write(.claude/settings.json)",
    # settings.local.json now holds the absolute hook command — protect it too, so the
    # agent cannot delete its own wiring even if the hook itself crashes.
    "Edit(.claude/settings.local.json)", "Write(.claude/settings.local.json)",
)

_AUTH_DIRS = {"auth", "authn", "authz", "iam", "oauth"}
_INFRA_DIRS = {"infra", "infrastructure", "terraform", "deploy", "deployment",
               "deployments", "charts", "helm", "k8s", "kubernetes", "ansible"}
_MIGRATION_DIRS = {"migrations", "migrate"}
_CI_FILES = (".gitlab-ci.yml", ".circleci", "Jenkinsfile", "azure-pipelines.yml",
             ".travis.yml")


def git_repo_root(cwd: str = ".") -> Optional[Path]:
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd,
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _git_tracked_files(repo_root: Path) -> List[str]:
    """Worktree files, .gitignore respected (tracked + untracked-but-not-ignored)."""
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=str(repo_root), capture_output=True, text=True, timeout=30)
    return [l for l in out.stdout.splitlines() if l.strip()] if out.returncode == 0 else []


def _git_remote_repo(repo_root: Path) -> Optional[str]:
    try:
        out = subprocess.run(["git", "remote", "get-url", "origin"], cwd=str(repo_root),
                             capture_output=True, text=True, timeout=10)
        url = out.stdout.strip()
        if out.returncode != 0 or not url:
            return None
        tail = url.rstrip("/").removesuffix(".git")
        parts = tail.replace(":", "/").split("/")
        return "/".join(parts[-2:]) if len(parts) >= 2 else None
    except (OSError, subprocess.SubprocessError):
        return None


def propose_protect_globs(repo_root: Path) -> List[str]:
    """Heuristic protect-glob proposal from the tree (shown to the user, never silently applied)."""
    files = _git_tracked_files(repo_root)
    globs: List[str] = []

    def add(g: str) -> None:
        if g not in globs:
            globs.append(g)

    dirs = set()
    for f in files:
        parts = f.replace("\\", "/").split("/")
        for i in range(len(parts) - 1):
            dirs.add("/".join(parts[: i + 1]))
    for d in sorted(dirs):
        name = d.rsplit("/", 1)[-1].lower()
        if name in _AUTH_DIRS or name in _INFRA_DIRS or name in _MIGRATION_DIRS:
            add(f"{d}/**")
    if any(f.startswith(".github/workflows/") for f in files):
        add(".github/workflows/**")
    names = {f.replace("\\", "/") for f in files}
    # fnmatch semantics: "*" crosses "/" so "*.pem" covers nested paths too, while
    # "**/*.pem" would MISS a top-level secrets.pem (it requires a slash).
    if any(f.endswith(".pem") for f in names):
        add("*.pem")
    if any(f.endswith(".key") for f in names):
        add("*.key")
    if any(Path(f).name.startswith(".env") for f in names):
        add(".env*")        # top-level
        add("**/.env*")     # nested
    for ci in _CI_FILES:
        if any(f == ci or f.startswith(ci + "/") for f in names):
            add(ci + ("/**" if any(f.startswith(ci + "/") for f in names) else ""))
    return globs


def default_bash_deny(protected_branches) -> List[str]:
    out = ["*git push*--force*", "*gh pr merge*", "*terraform apply*"]
    out += [f"*git push*origin*{b}*" for b in protected_branches if "*" not in b]
    return out


def render_proposed_policy(repo_root: Path) -> str:
    protected = ("main",)
    return render_policy_yaml(
        repo=_git_remote_repo(repo_root),
        protect=propose_protect_globs(repo_root),
        protected_branches=protected,
        bash_deny=default_bash_deny(protected),
    )


# ----------------------------------------------------------------------------
# the gate command (resolved at init time so it does not depend on the hook
# shell's PATH — the Stage 1 silent-failure mode)
# ----------------------------------------------------------------------------
def resolve_gate_command() -> str:
    """An ABSOLUTE, PATH-independent `signet hook` command string.

    Prefer the installed console script; fall back to `<python> -m signet.cli.main hook`
    so a venv/pipx install whose shim is not on the hook shell's PATH still launches."""
    exe = shutil.which("signet")
    if exe:
        return f"{shlex.quote(exe)} hook"
    return f"{shlex.quote(sys.executable)} -m signet.cli.main hook"


def _is_signet_hook_command(cmd: Optional[str]) -> bool:
    """True if `cmd` is any form of our gate: bare `signet hook`, `<abs>/signet hook`,
    or `<python> -m signet.cli.main hook`."""
    cmd = (cmd or "").strip()
    if not cmd:
        return False
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return False
    if "signet.cli.main" in parts and parts[-1:] == ["hook"]:
        return True
    return len(parts) >= 2 and parts[-1] == "hook" and Path(parts[0]).name == "signet"


def command_resolves(cmd: str) -> bool:
    """Does the gate command actually launch on THIS machine? (status reachability check.)"""
    try:
        parts = shlex.split(cmd or "")
    except ValueError:
        return False
    if not parts:
        return False
    binary = parts[0]
    if os.path.isabs(binary) or os.sep in binary:
        return os.path.exists(binary)
    return shutil.which(binary) is not None


# ----------------------------------------------------------------------------
# settings file wiring (MERGE — unrelated keys must survive; proven by test)
# ----------------------------------------------------------------------------
def _settings_path(repo_root: Path, filename: str) -> Path:
    return repo_root / ".claude" / filename


def _load_settings(path: Path) -> dict:
    if path.is_file():
        text = path.read_text().strip()
        return json.loads(text) if text else {}
    return {}


def _write_settings(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def find_signet_hook(repo_root: Path, filename: str) -> Optional[str]:
    """The command string of the signet PreToolUse hook in `filename`, or None."""
    try:
        data = _load_settings(_settings_path(repo_root, filename))
    except (OSError, ValueError):
        return None
    for group in data.get("hooks", {}).get("PreToolUse", []):
        for h in group.get("hooks", []):
            if _is_signet_hook_command(h.get("command")):
                return h.get("command")
    return None


def wire_hook(repo_root: Path, filename: str, command: str) -> str:
    """MERGE a PreToolUse signet hook with `command` into `filename`.
    Returns 'added' | 'updated' | 'unchanged'."""
    path = _settings_path(repo_root, filename)
    data = _load_settings(path)
    pre = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    for group in pre:
        for h in group.get("hooks", []):
            if _is_signet_hook_command(h.get("command")):
                if h.get("command") == command:
                    return "unchanged"
                h["command"] = command                          # refresh the path in place
                _write_settings(path, data)
                return "updated"
    pre.append({"matcher": HOOK_MATCHER,
                "hooks": [{"type": "command", "command": command}]})
    _write_settings(path, data)
    return "added"


def remove_signet_hook(repo_root: Path, filename: str) -> bool:
    """Strip any signet PreToolUse hook from `filename`, pruning emptied groups/keys.
    Returns True if something was removed."""
    path = _settings_path(repo_root, filename)
    if not path.is_file():
        return False
    try:
        data = _load_settings(path)
    except (OSError, ValueError):
        return False
    section = data.get("hooks", {})
    pre = section.get("PreToolUse", [])
    new_pre, removed = [], False
    for group in pre:
        kept = [h for h in group.get("hooks", []) if not _is_signet_hook_command(h.get("command"))]
        if len(kept) != len(group.get("hooks", [])):
            removed = True
        if kept:
            new_pre.append({**group, "hooks": kept})
    if not removed:
        return False
    if new_pre:
        section["PreToolUse"] = new_pre
    else:
        section.pop("PreToolUse", None)
        if not section:
            data.pop("hooks", None)
    _write_settings(path, data)
    return True


def add_native_deny_rules(repo_root: Path) -> int:
    """Add the ALWAYS-DENY rules to the SHARED settings.json (a team inherits them)."""
    path = _settings_path(repo_root, SETTINGS_SHARED)
    data = _load_settings(path)
    deny = data.setdefault("permissions", {}).setdefault("deny", [])
    added = 0
    for rule in NATIVE_DENY_RULES:
        if rule not in deny:
            deny.append(rule)
            added += 1
    if added:
        _write_settings(path, data)
    return added


def hook_wired(repo_root: Path) -> bool:
    """True if a signet hook is present in EITHER settings file (presence, not reachability)."""
    return any(find_signet_hook(repo_root, f) for f in (SETTINGS_LOCAL, SETTINGS_SHARED))


# ----------------------------------------------------------------------------
# wiring state for `signet status`: WIRED (resolves) | BROKEN (present, unresolvable) | UNWIRED
# ----------------------------------------------------------------------------
def hook_wiring_state(repo_root: Path) -> Tuple[str, Optional[str], Optional[str]]:
    """(state, filename, command). Local overrides shared; BROKEN if the entry's command
    does not resolve on this machine (the Stage 1 silent-failure mode, surfaced)."""
    for filename in (SETTINGS_LOCAL, SETTINGS_SHARED):
        cmd = find_signet_hook(repo_root, filename)
        if cmd:
            return ("WIRED" if command_resolves(cmd) else "BROKEN", filename, cmd)
    return ("UNWIRED", None, None)


# ----------------------------------------------------------------------------
# .gitignore coverage for settings.local.json (must not travel — it is user-specific)
# ----------------------------------------------------------------------------
def repo_gitignore_covers(repo_root: Path, relpath: str) -> bool:
    """True only if the repo's OWN tracked .gitignore ignores `relpath` — a global/system
    excludes file does NOT count (teammates won't have it)."""
    try:
        out = subprocess.run(["git", "check-ignore", "-v", relpath], cwd=str(repo_root),
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    if out.returncode != 0 or not out.stdout.strip():
        return False
    source = out.stdout.split(":", 1)[0].strip()
    src_abs = source if os.path.isabs(source) else os.path.join(str(repo_root), source)
    try:
        root_real = os.path.realpath(str(repo_root))
        return os.path.realpath(src_abs).startswith(root_real + os.sep)
    except OSError:
        return False


def append_gitignore(repo_root: Path, line: str) -> bool:
    gi = repo_root / ".gitignore"
    existing = gi.read_text() if gi.is_file() else ""
    if line in existing.splitlines():
        return False
    sep = "" if (not existing or existing.endswith("\n")) else "\n"
    gi.write_text(existing + sep + line + "\n")
    return True


# ----------------------------------------------------------------------------
# commands
# ----------------------------------------------------------------------------
def _confirm(prompt: str, assume_yes: bool, default_yes: bool = False) -> bool:
    hint = "[Y/n]" if default_yes else "[y/N]"
    if assume_yes:
        print(f"{prompt} {hint} y   (--yes)")
        return True
    try:
        ans = input(f"{prompt} {hint} ").strip().lower()
    except EOFError:
        return default_yes
    if not ans:
        return default_yes
    return ans in ("y", "yes")


def _diff(old: str, new: str, name: str) -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"{name} (current)", tofile=f"{name} (proposed)"))


def _wire_hook_step(repo_root: Path, args) -> str:
    """Run the wiring step (split layout + migration). Returns a one-line summary."""
    shared = getattr(args, "shared", False)
    legacy = find_signet_hook(repo_root, SETTINGS_SHARED)

    # --- migration: Stage 1 layout = a signet hook entry living in the SHARED file ---
    if legacy and not shared:
        print(f"\nMigration: found a signet hook in {SETTINGS_SHARED} (Stage 1 layout: "
              f"{legacy!r}).")
        print(f"  New layout puts the user-specific hook command in {SETTINGS_LOCAL} "
              "(git-ignored) and keeps only the portable deny rules shared.")
        if _confirm(f"Migrate the hook entry to {SETTINGS_LOCAL} with an absolute "
                    "command?", args.yes):
            command = resolve_gate_command()
            remove_signet_hook(repo_root, SETTINGS_SHARED)
            state = wire_hook(repo_root, SETTINGS_LOCAL, command)
            _offer_gitignore(repo_root, args)
            return f"hook MIGRATED {SETTINGS_SHARED} -> {SETTINGS_LOCAL} ({state}: {command})"
        return f"hook left in {SETTINGS_SHARED} (migration declined; still bare-PATH)"

    if shared:
        if not _confirm(f"Wire `signet hook` (bare command) into the SHARED "
                        f"{SETTINGS_SHARED}?", args.yes):
            return "hook NOT wired (you declined)"
        state = wire_hook(repo_root, SETTINGS_SHARED, HOOK_COMMAND)
        print("  note: --shared wires the bare command \"signet hook\" — every machine "
              "that runs this repo MUST have `signet` on the hook shell's PATH, or the "
              "gate silently no-ops there. `signet status` reports BROKEN where it can't "
              "resolve.")
        return f"hook wired into SHARED {SETTINGS_SHARED} ({state}: bare `signet hook`)"

    if not _confirm(f"Wire `signet hook` into {SETTINGS_LOCAL} (PreToolUse, absolute "
                    "command)?", args.yes):
        return "hook NOT wired (you declined)"
    command = resolve_gate_command()
    state = wire_hook(repo_root, SETTINGS_LOCAL, command)
    _offer_gitignore(repo_root, args)
    return f"hook wired into {SETTINGS_LOCAL} ({state}: {command})"


def _offer_gitignore(repo_root: Path, args) -> None:
    if repo_gitignore_covers(repo_root, GITIGNORE_LINE):
        return
    if _confirm(f"{GITIGNORE_LINE} is not covered by this repo's .gitignore (it is "
                "user-specific and must not be committed). Append it?", args.yes,
                default_yes=True):
        if append_gitignore(repo_root, GITIGNORE_LINE):
            print(f"  appended {GITIGNORE_LINE!r} to .gitignore")


def cmd_init(args) -> int:
    repo_root = git_repo_root(os.getcwd())
    if repo_root is None:
        print("signet init: not inside a git repository — nothing to protect yet.\n"
              "Run it from your project root (git init first if needed).")
        return 1

    policy_path = repo_root / POLICY_RELPATH
    proposed = render_proposed_policy(repo_root)
    current = policy_path.read_text() if policy_path.is_file() else ""

    # --- policy (gated by --force; wiring/migration still run on re-init) ---
    if current and not args.force:
        d = _diff(current, proposed, str(POLICY_RELPATH))
        print(f"signet: {policy_path} already exists — repo is initialized "
              "(use --force to rewrite the policy).")
        print(d if d else "(current policy matches what init would propose)")
    else:
        print(_diff(current, proposed, str(POLICY_RELPATH)) or proposed)
        if not _confirm(f"Write {policy_path}?", args.yes):
            print("aborted — nothing written.")
            return 1
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(proposed)
    policy = PolicyFile.load(policy_path)

    # --- wiring (split layout + migration) ---
    wire_summary = _wire_hook_step(repo_root, args)

    native = 0
    if _confirm(f"Add native always-deny rules for .signet/** and "
                f".claude/settings.json to the SHARED {SETTINGS_SHARED}? (deny rules "
                "are evaluated even if the hook crashes)", args.yes):
        native = add_native_deny_rules(repo_root)

    from .local_receipts import LocalReceiptLog, load_or_create_key, signet_home
    load_or_create_key()
    log = LocalReceiptLog(os.path.realpath(str(repo_root)), repo_label=str(repo_root))
    log._ensure_dir()

    state, fname, _cmd = hook_wiring_state(repo_root)
    print(f"""
signet is on for this repo. What just happened:
  1. {policy_path} written — {len(policy.protect)} protected glob(s), policy_hash {policy.policy_hash[:16]}…
  2. {wire_summary}.
     hook wiring resolves on this machine: {state}{f" (in {fname})" if fname else ""}.
     native self-protect deny rules (shared {SETTINGS_SHARED}): {"added" if native else "unchanged"}.
  3. Local signing key + receipts live in {signet_home()} (outside the worktree); every gate decision appends a signed, hash-chained receipt.
  4. Honest boundary: this local gate is containment UX and tamper-EVIDENT logging — an agent with raw shell access can bypass any client-side hook. It is NOT the enforcement boundary.
  5. The enforcement boundary is the server-side rail (Stage 3) — when you're ready, that is the upgrade path. Try: signet explain <path> | signet status | signet receipts --verify
""")
    return 0


def cmd_status(args) -> int:
    repo_root = git_repo_root(os.getcwd())
    if repo_root is None:
        print("not inside a git repository")
        return 1
    policy_path = repo_root / POLICY_RELPATH
    if not policy_path.is_file():
        print(f"uninitialized: no {POLICY_RELPATH} — run `signet init` (the hook no-ops here)")
        return 0
    try:
        policy = PolicyFile.load(policy_path)
    except PolicyError as e:
        print(f"policy INVALID (hook escalates everything to ask): {e}")
        return 1

    n = 6
    print(f"repo            : {repo_root}" + (f"   ({policy.repo})" if policy.repo else ""))
    remote = _git_remote_repo(repo_root)
    if policy.repo and remote and policy.repo != remote:
        print(f"WARNING         : policy says repo {policy.repo!r} but git remote is "
              f"{remote!r} — is this policy for this repo?")
    print(f"policy_hash     : {policy.policy_hash}")
    print(f"protect ({len(policy.protect):3d})   : " + ", ".join(policy.protect[:n])
          + (" …" if len(policy.protect) > n else ""))
    print(f"allow   ({len(policy.allow):3d})   : " + ", ".join(policy.allow[:n]))
    print(f"bash deny ({len(policy.bash_deny):3d}) : " + ", ".join(policy.bash_deny[:n])
          + (" …" if len(policy.bash_deny) > n else ""))
    print(f"tiers           : protected_edit={policy.tier_protected_edit} "
          f"out_of_allow_edit={policy.tier_out_of_allow_edit}")

    state, fname, cmd = hook_wiring_state(repo_root)
    if state == "WIRED":
        print(f"hook            : WIRED ({fname}: {cmd})")
    elif state == "UNWIRED":
        print("hook            : UNWIRED (no signet PreToolUse hook — run `signet init`; "
              "the gate is OFF for this repo)")
    else:  # BROKEN
        print(f"hook            : BROKEN — entry in {fname} is {cmd!r} but that command "
              "does NOT resolve on this machine.")
        print("                  THE FENCE IS NOT ENFORCED: Claude Code treats a hook "
              "that fails to launch as a non-blocking error, so tool calls PROCEED "
              "unguarded.")
        print("                  Fix: re-run `signet init` to rewrite the hook with a "
              "resolvable absolute command.")

    from .local_receipts import LocalReceiptLog
    log = LocalReceiptLog(os.path.realpath(str(repo_root)))
    recs = list(log.records())
    last = f"{recs[-1]['verdict']} ({recs[-1]['cause']}, {recs[-1]['ts']})" if recs else "—"
    print(f"receipts        : {len(recs)} in {log.path}   last: {last}")
    print("boundary        : local gate = containment UX + tamper-evident receipts; "
          "the server-side rail (Stage 3) is the enforcement boundary")
    # BROKEN (present-but-unresolvable) is a safety failure and must be scriptable.
    return 2 if state == "BROKEN" else 0


def cmd_receipts(args) -> int:
    repo_root = git_repo_root(os.getcwd())
    if repo_root is None:
        print("not inside a git repository")
        return 1
    from .local_receipts import LocalReceiptLog
    log = LocalReceiptLog(os.path.realpath(str(repo_root)))
    recs = list(log.records())
    if args.verify:
        ok, msg, idx = log.verify()
        print(("OK: " if ok else "TAMPER-EVIDENT BREAK: ") + msg)
        return 0 if ok else 1
    for r in recs[-args.n:]:
        eff = r.get("effect", {})
        what = ",".join(eff.get("paths", [])) or eff.get("command_sha256", "")[:16] or "-"
        print(f"{r['ts']}  {r['verdict']:<5} {r.get('tool_name', ''):<12} {what}  "
              f"cause={r['cause']}  id={r['id']}")
    if not recs:
        print(f"no receipts yet ({log.path})")
    return 0


def cmd_explain(args) -> int:
    from .hook import evaluate_bash, evaluate_edit
    cwd = os.getcwd()
    if args.bash is not None:
        v = evaluate_bash(args.bash, cwd)
        subject = "(bash command)"
    else:
        v = evaluate_edit(args.path, cwd)
        subject = args.path
    decision = {"none": "no decision (out of signet scope or repo uninitialized)",
                "pass": "pass (in-fence; normal permission flow proceeds)"}.get(
                    v.decision, v.decision.upper())
    print(f"subject : {subject}")
    print(f"verdict : {decision}")
    print(f"rule    : {v.cause or '—'}")
    if v.reason:
        print(f"reason  : {v.reason}")
    if v.policy_hash:
        print(f"policy  : {v.policy_hash[:16]}…")
    print("note    : same evaluation code path as `signet hook`; bash gating is heuristic "
          "pattern containment, not effect binding — the file-edit path is the precisely "
          "gated one.")
    return 0
