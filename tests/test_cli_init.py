"""`signet init` scaffolding, settings.json MERGE preservation, idempotency, packaging."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from signet.cli import init_cmd
from signet.fence import POLICY_RELPATH, PolicyFile


def _git_repo(tmp_path, files):
    root = tmp_path / "proj"
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


FIXTURE_TREE = [
    "auth/login.py", "src/app.py", "docs/readme.md",
    "terraform/main.tf", "db/migrations/001.sql",
    ".github/workflows/ci.yml", "secrets.pem", ".env",
]


def test_propose_protect_globs_from_fixture_tree(tmp_path):
    root = _git_repo(tmp_path, FIXTURE_TREE)
    globs = init_cmd.propose_protect_globs(root)
    assert set(globs) == {"auth/**", "terraform/**", "db/migrations/**",
                          ".github/workflows/**", "*.pem", ".env*", "**/.env*"}
    # and every proposed glob actually fences the file that motivated it
    from signet.fence import matches_any
    for f in ("auth/login.py", "terraform/main.tf", "db/migrations/001.sql",
              ".github/workflows/ci.yml", "secrets.pem", ".env"):
        assert matches_any(f, globs), f
    assert not matches_any("src/app.py", globs)
    assert not matches_any("docs/readme.md", globs)


def _init(**over):
    base = dict(yes=True, force=False, shared=False)
    base.update(over)
    return SimpleNamespace(**base)


def test_init_yes_writes_valid_policy_and_wires_hook(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, FIXTURE_TREE)
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    rc = init_cmd.cmd_init(_init())
    assert rc == 0
    policy = PolicyFile.load(root / POLICY_RELPATH)
    assert "auth/**" in policy.protect
    assert "*git push*--force*" in policy.bash_deny

    # the hook goes to the LOCAL file with an ABSOLUTE, resolvable command (not bare)
    local = json.loads((root / ".claude" / "settings.local.json").read_text())
    cmd = local["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd != "signet hook" and cmd.endswith("hook")
    assert init_cmd.command_resolves(cmd)
    state, fname, _ = init_cmd.hook_wiring_state(root)
    assert state == "WIRED" and fname == "settings.local.json"
    # the hook is NOT in the shared file; the deny rules ARE
    assert init_cmd.find_signet_hook(root, "settings.json") is None
    shared = json.loads((root / ".claude" / "settings.json").read_text())
    assert set(init_cmd.NATIVE_DENY_RULES) <= set(shared["permissions"]["deny"])
    # settings.local.json got ignored (it must not travel)
    assert init_cmd.repo_gitignore_covers(root, ".claude/settings.local.json")

    out = capsys.readouterr().out
    assert "NOT the enforcement boundary" in out            # the honest statement


def test_init_is_idempotent_without_force(tmp_path, monkeypatch):
    root = _git_repo(tmp_path, FIXTURE_TREE)
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    assert init_cmd.cmd_init(_init()) == 0
    written = (root / POLICY_RELPATH).read_text()
    local1 = (root / ".claude" / "settings.local.json").read_text()
    assert init_cmd.cmd_init(_init()) == 0
    assert (root / POLICY_RELPATH).read_text() == written   # policy untouched without --force
    # wiring is idempotent too: no duplicate hook entry
    local2 = (root / ".claude" / "settings.local.json").read_text()
    assert local1 == local2
    pre = json.loads(local2)["hooks"]["PreToolUse"]
    assert sum(len(g["hooks"]) for g in pre) == 1


def test_init_refuses_outside_git_repo(tmp_path, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)
    monkeypatch.setattr(init_cmd, "git_repo_root", lambda *a, **k: None)
    assert init_cmd.cmd_init(_init()) == 1


def test_wire_hook_merge_preserves_unrelated_keys_in_both_files(tmp_path):
    root = _git_repo(tmp_path, ["src/app.py"])
    cs = root / ".claude"
    cs.mkdir()
    # LOCAL file already has a personal override that must survive the hook merge
    (cs / "settings.local.json").write_text(json.dumps(
        {"env": {"PERSONAL": "1"},
         "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": []}]}}))
    # SHARED file has the team's attribution keys that must survive the deny merge
    (cs / "settings.json").write_text(json.dumps(
        {"attribution": {"commit": "abc", "pr": "7"}, "env": {"FOO": "bar"}}))

    cmd = "/usr/local/bin/signet hook"
    assert init_cmd.wire_hook(root, "settings.local.json", cmd) == "added"
    assert init_cmd.add_native_deny_rules(root) == len(init_cmd.NATIVE_DENY_RULES)

    local = json.loads((cs / "settings.local.json").read_text())
    assert local["env"] == {"PERSONAL": "1"}
    assert local["hooks"]["PostToolUse"] == [{"matcher": "Bash", "hooks": []}]
    entry = local["hooks"]["PreToolUse"][0]
    assert entry["matcher"] == init_cmd.HOOK_MATCHER
    assert entry["hooks"] == [{"type": "command", "command": cmd}]

    shared = json.loads((cs / "settings.json").read_text())
    assert shared["attribution"] == {"commit": "abc", "pr": "7"}
    assert shared["env"] == {"FOO": "bar"}
    assert init_cmd.find_signet_hook(root, "settings.json") is None   # hook NOT in shared

    # re-wiring same command is a no-op; a new path UPDATES in place (no duplicate)
    assert init_cmd.wire_hook(root, "settings.local.json", cmd) == "unchanged"
    assert init_cmd.wire_hook(root, "settings.local.json", "/opt/signet hook") == "updated"
    pre = json.loads((cs / "settings.local.json").read_text())["hooks"]["PreToolUse"]
    assert sum(len(g["hooks"]) for g in pre) == 1
    assert init_cmd.add_native_deny_rules(root) == 0


def test_status_and_receipts_commands_run(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, FIXTURE_TREE)
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    init_cmd.cmd_init(_init())
    capsys.readouterr()
    assert init_cmd.cmd_status(SimpleNamespace()) == 0
    out = capsys.readouterr().out
    assert "policy_hash" in out and "hook            : WIRED" in out
    assert init_cmd.cmd_receipts(SimpleNamespace(verify=True, n=20)) == 0
    assert capsys.readouterr().out.startswith("OK:")


def test_status_warns_on_repo_remote_mismatch(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, ["src/app.py"])
    subprocess.run(["git", "-C", str(root), "remote", "add", "origin",
                    "https://github.com/actual/repo.git"], check=True)
    (root / ".signet").mkdir()
    (root / ".signet" / "policy.yaml").write_text(
        "version: 1\nrepo: someone/else\nprotect: ['auth/**']\n")
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    assert init_cmd.cmd_status(SimpleNamespace()) == 0
    out = capsys.readouterr().out
    assert "WARNING" in out and "someone/else" in out and "actual/repo" in out


def test_explain_uses_hook_code_path(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, FIXTURE_TREE)
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    init_cmd.cmd_init(_init())
    capsys.readouterr()
    assert init_cmd.cmd_explain(SimpleNamespace(path="auth/login.py", bash=None)) == 0
    out = capsys.readouterr().out
    assert "DENY" in out and "auth/**" in out
    assert init_cmd.cmd_explain(SimpleNamespace(path=None, bash="gh pr merge 5")) == 0
    assert "DENY" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Stage 1 hardening: wiring robustness (BROKEN detection, migration, --shared, gitignore)
# ---------------------------------------------------------------------------
def test_status_reports_broken_and_exits_2(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, ["src/app.py"])
    (root / ".signet").mkdir()
    (root / ".signet" / "policy.yaml").write_text("version: 1\nprotect: ['auth/**']\n")
    cs = root / ".claude"
    cs.mkdir()
    nonexistent = str(tmp_path / "does" / "not" / "exist" / "signet")
    (cs / "settings.local.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": [{"matcher": init_cmd.HOOK_MATCHER,
                                   "hooks": [{"type": "command",
                                              "command": f"{nonexistent} hook"}]}]}}))
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    assert init_cmd.cmd_status(SimpleNamespace()) == 2          # scriptable safety failure
    out = capsys.readouterr().out
    assert "BROKEN" in out and "NOT ENFORCED" in out
    assert "settings.local.json" in out and "signet init" in out


def test_status_unwired_exits_0(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, ["src/app.py"])
    (root / ".signet").mkdir()
    (root / ".signet" / "policy.yaml").write_text("version: 1\nprotect: ['auth/**']\n")
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    assert init_cmd.cmd_status(SimpleNamespace()) == 0
    assert "UNWIRED" in capsys.readouterr().out


def test_migration_stage1_layout_to_split_layout(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, FIXTURE_TREE)
    cs = root / ".claude"
    cs.mkdir()
    # Stage 1 layout: bare "signet hook" in the SHARED file, alongside unrelated keys
    (cs / "settings.json").write_text(json.dumps({
        "attribution": {"commit": "abc"},
        "permissions": {"deny": ["Edit(.signet/**)"]},
        "hooks": {"PreToolUse": [{"matcher": init_cmd.HOOK_MATCHER,
                                  "hooks": [{"type": "command", "command": "signet hook"}]}]},
    }))
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    init_cmd.cmd_init(_init())   # policy gets written + migration runs
    out = capsys.readouterr().out
    assert "Migration" in out and "MIGRATED" in out

    # hook removed from shared, added to local with an absolute command
    assert init_cmd.find_signet_hook(root, "settings.json") is None
    local_cmd = init_cmd.find_signet_hook(root, "settings.local.json")
    assert local_cmd and local_cmd != "signet hook" and init_cmd.command_resolves(local_cmd)
    # unrelated shared keys preserved; deny rules present
    shared = json.loads((cs / "settings.json").read_text())
    assert shared["attribution"] == {"commit": "abc"}
    assert set(init_cmd.NATIVE_DENY_RULES) <= set(shared["permissions"]["deny"])
    # idempotent after migration: a second run finds no legacy entry, leaves local intact
    local1 = (cs / "settings.local.json").read_text()
    capsys.readouterr()
    init_cmd.cmd_init(_init())
    assert "Migration" not in capsys.readouterr().out
    assert (cs / "settings.local.json").read_text() == local1


def test_shared_flag_wires_bare_command_to_shared(tmp_path, monkeypatch, capsys):
    root = _git_repo(tmp_path, FIXTURE_TREE)
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    monkeypatch.chdir(root)
    init_cmd.cmd_init(_init(shared=True))
    out = capsys.readouterr().out
    assert "PATH" in out                                        # the warning is printed
    assert init_cmd.find_signet_hook(root, "settings.json") == "signet hook"
    assert init_cmd.find_signet_hook(root, "settings.local.json") is None


def test_gitignore_append_when_uncovered(tmp_path):
    root = _git_repo(tmp_path, ["src/app.py"])
    (root / ".gitignore").write_text("__pycache__/\n")
    assert not init_cmd.repo_gitignore_covers(root, ".claude/settings.local.json")
    assert init_cmd.append_gitignore(root, ".claude/settings.local.json") is True
    assert init_cmd.repo_gitignore_covers(root, ".claude/settings.local.json")
    # idempotent: a second append is a no-op
    assert init_cmd.append_gitignore(root, ".claude/settings.local.json") is False


def test_wired_local_command_launches_and_denies_on_real_payload(tmp_path, monkeypatch):
    """The command init writes into settings.local.json must actually launch and gate —
    this is the deterministic analogue of the captured live-fire proof."""
    import os
    root = _git_repo(tmp_path, ["auth/login.py", "src/app.py"])
    sighome = tmp_path / "sighome"
    monkeypatch.setenv("SIGNET_HOME", str(sighome))
    monkeypatch.chdir(root)
    init_cmd.cmd_init(_init())
    cmd = init_cmd.find_signet_hook(root, "settings.local.json")

    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "hook_payloads" / "real_edit.json").read_text())
    payload["cwd"] = str(root)
    payload["tool_input"]["file_path"] = str(root / "auth" / "login.py")

    env = {**os.environ, "SIGNET_HOME": str(sighome),
           "PYTHONPATH": str(Path(__file__).parents[1])}
    out = subprocess.run(cmd, shell=True, input=json.dumps(payload),
                         capture_output=True, text=True, env=env, cwd=str(root))
    assert out.returncode == 0, out.stderr
    decision = json.loads(out.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "auth/login.py is protected" in decision["permissionDecisionReason"]


def test_resolve_gate_command_is_absolute_and_resolvable():
    cmd = init_cmd.resolve_gate_command()
    assert cmd.endswith("hook") and cmd != "signet hook"
    binary = cmd.split()[0].strip("'\"")
    assert __import__("os").path.isabs(binary)
    assert init_cmd.command_resolves(cmd)


# ---------------------------------------------------------------------------
# packaging: the corpus test SKIPS (not errors) when agentdojo is missing
# ---------------------------------------------------------------------------
def test_corpus_test_skips_cleanly_without_agentdojo(tmp_path):
    # Simulate the clean machine: a meta_path blocker (installed via sitecustomize) makes
    # `import agentdojo` raise ModuleNotFoundError exactly as if it were not installed.
    blocker = tmp_path / "shadow"
    blocker.mkdir()
    (blocker / "sitecustomize.py").write_text(
        "import sys\n"
        "class _Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'agentdojo' or name.startswith('agentdojo.'):\n"
        "            raise ModuleNotFoundError(f\"No module named {name!r}\", name=name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Block())\n")
    repo_root = Path(__file__).parents[1]
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_github_railbridge_corpus.py",
         "-q", "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=str(repo_root),
        env={**__import__('os').environ,
             "PYTHONPATH": f"{blocker}:{repo_root}"})
    # rc 5 == "no tests collected": pytest's code for a single-file run where the whole
    # module skipped. The failure mode we guard against is a collection ERROR (rc 2),
    # which is what cascaded into the 6-alarm scorecard FAIL before the importorskip fix.
    assert out.returncode in (0, 5), out.stdout + out.stderr
    assert "error" not in (out.stdout + out.stderr).lower()
    assert "1 skipped" in out.stdout
