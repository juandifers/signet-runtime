"""`signet hook` — contract, path normalization, self-protection, fail-closed posture.

All offline + deterministic: SIGNET_HOME is pointed at tmp_path, repos are tmp fixtures.
The real_*.json fixtures are REAL PreToolUse stdin payloads captured from Claude Code
2.1.170 (only cwd/file_path are re-pointed at the tmp repo).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from signet.cli import hook as hook_mod
from signet.cli.hook import run_hook
from signet.cli.local_receipts import LocalReceiptLog, repo_slug, signet_home

FIXTURES = Path(__file__).parent / "fixtures" / "hook_payloads"

POLICY = """\
version: 1
protect:
  - "auth/**"
  - ".github/workflows/**"
allow:
  - "**"
bash:
  deny:
    - "*git push*--force*"
  ask:
    - "*terraform plan*"
tiers:
  protected_edit: deny
  out_of_allow_edit: ask
"""


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    root = tmp_path / "repo"
    (root / ".signet").mkdir(parents=True)
    (root / ".signet" / "policy.yaml").write_text(POLICY)
    (root / "auth").mkdir()
    (root / "auth" / "login.py").write_text("x = 1\n")
    (root / "docs").mkdir()
    (root / "docs" / "readme.md").write_text("hi\n")
    return root


def hk(tool, tool_input, cwd):
    payload = {"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd)}
    return run_hook(json.dumps(payload))


def decision(result):
    code, out, err = result
    assert code == 0
    if not out:
        return None
    d = json.loads(out)["hookSpecificOutput"]
    assert d["hookEventName"] == "PreToolUse"
    assert d["permissionDecision"] in ("deny", "ask")   # LOCAL-MONOTONIC: never "allow"
    return d


def receipts(root):
    log = LocalReceiptLog(os.path.realpath(str(root)))
    return list(log.records())


# ---------------------------------------------------------------------------
# the contract, on REAL captured payloads
# ---------------------------------------------------------------------------
def _real(name, repo_root, **tool_input_overrides):
    payload = json.loads((FIXTURES / f"real_{name}.json").read_text())
    payload["cwd"] = str(repo_root)
    payload["tool_input"].update(tool_input_overrides)
    return payload


def test_real_edit_payload_protected_path_denies(repo):
    payload = _real("edit", repo, file_path=str(repo / "auth" / "login.py"))
    code, out, _ = run_hook(json.dumps(payload))
    d = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and d["permissionDecision"] == "deny"
    assert "auth/login.py is protected by .signet/policy.yaml (rule: auth/**)" in \
        d["permissionDecisionReason"]
    assert "receipt ldr_" in d["permissionDecisionReason"]


def test_real_write_payload_in_fence_passes_silently_with_receipt(repo):
    payload = _real("write", repo, file_path=str(repo / "docs" / "new.md"))
    assert run_hook(json.dumps(payload)) == (0, "", "")
    recs = receipts(repo)
    assert recs[-1]["verdict"] == "pass" and recs[-1]["cause"] == "in-fence"


def test_real_bash_payload_pass_and_deny(repo):
    benign = _real("bash", repo)                                  # "echo done"
    assert run_hook(json.dumps(benign)) == (0, "", "")
    force = _real("bash", repo, command="git push --force origin main")
    d = decision(run_hook(json.dumps(force)))
    assert d["permissionDecision"] == "deny" and "*git push*--force*" in \
        d["permissionDecisionReason"]


# ---------------------------------------------------------------------------
# contract edges
# ---------------------------------------------------------------------------
def test_unknown_tool_silent_no_receipt(repo):
    before = len(receipts(repo))
    assert hk("Read", {"file_path": str(repo / "auth" / "login.py")}, repo) == (0, "", "")
    assert hk("Grep", {"pattern": "x"}, repo) == (0, "", "")
    assert len(receipts(repo)) == before


def test_broken_stdin_escalates_to_ask():
    code, out, _ = run_hook("{this is not json")
    d = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and d["permissionDecision"] == "ask"
    assert d["permissionDecisionReason"].startswith("signet hook error:")
    assert d["permissionDecisionReason"].endswith("— escalating")


def test_missing_path_in_edit_payload_escalates(repo):
    d = decision(hk("Edit", {"old_string": "a", "new_string": "b"}, repo))
    assert d["permissionDecision"] == "ask" and "signet hook error" in \
        d["permissionDecisionReason"]


def test_uninitialized_git_repo_is_a_silent_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    plain = tmp_path / "plain"
    plain.mkdir()
    subprocess.run(["git", "init", "-q", str(plain)], check=True)
    assert hk("Edit", {"file_path": "auth/login.py", "old_string": "a",
                       "new_string": "b"}, plain) == (0, "", "")


def test_invalid_policy_escalates_to_ask(repo):
    (repo / ".signet" / "policy.yaml").write_text("version: 1\nprotct: ['typo/**']\n")
    d = decision(hk("Edit", {"file_path": "docs/readme.md", "old_string": "a",
                             "new_string": "b"}, repo))
    assert d["permissionDecision"] == "ask"
    assert "signet hook error" in d["permissionDecisionReason"]


def test_tier_ask_for_protected_edit(repo):
    (repo / ".signet" / "policy.yaml").write_text(
        POLICY.replace("protected_edit: deny", "protected_edit: ask"))
    d = decision(hk("Edit", {"file_path": "auth/login.py", "old_string": "a",
                             "new_string": "b"}, repo))
    assert d["permissionDecision"] == "ask"


def test_out_of_allow_edit_asks(repo):
    (repo / ".signet" / "policy.yaml").write_text(
        POLICY.replace('- "**"', '- "docs/**"'))
    d = decision(hk("Write", {"file_path": "src/new.py", "content": "x"}, repo))
    assert d["permissionDecision"] == "ask"
    assert "outside the allow fence" in d["permissionDecisionReason"]


def test_multiedit_and_notebookedit_are_gated(repo):
    d = decision(hk("MultiEdit", {"file_path": "auth/login.py", "edits": []}, repo))
    assert d["permissionDecision"] == "deny"
    d = decision(hk("NotebookEdit", {"notebook_path": "auth/nb.ipynb",
                                     "new_source": ""}, repo))
    assert d["permissionDecision"] == "deny"


# ---------------------------------------------------------------------------
# path normalization (security-critical)
# ---------------------------------------------------------------------------
def test_relative_path_resolved_against_payload_cwd_not_process_cwd(repo, monkeypatch):
    monkeypatch.chdir(repo / "docs")        # process cwd is decoy
    d = decision(hk("Edit", {"file_path": "../auth/login.py", "old_string": "a",
                             "new_string": "b"}, repo / "docs"))
    assert d["permissionDecision"] == "deny"


def test_absolute_path_denied(repo):
    d = decision(hk("Edit", {"file_path": str(repo / "auth" / "login.py"),
                             "old_string": "a", "new_string": "b"}, repo))
    assert d["permissionDecision"] == "deny"


def test_dotdot_traversal_out_of_repo_is_no_decision(repo):
    before = len(receipts(repo))
    assert hk("Write", {"file_path": "../../outside.txt", "content": "x"},
              repo) == (0, "", "")
    assert len(receipts(repo)) == before    # out of scope -> not evaluated -> no receipt


def test_symlinked_dir_into_protected_dir_denied(repo):
    (repo / "free").symlink_to(repo / "auth")
    d = decision(hk("Edit", {"file_path": "free/login.py", "old_string": "a",
                             "new_string": "b"}, repo))
    assert d["permissionDecision"] == "deny"


def test_new_file_under_symlinked_dir_denied(repo):
    (repo / "free").symlink_to(repo / "auth")
    d = decision(hk("Write", {"file_path": "free/brand_new.py", "content": "x"}, repo))
    assert d["permissionDecision"] == "deny"


def test_signet_home_always_denied_even_without_repo(tmp_path, monkeypatch):
    home = tmp_path / "sighome"
    monkeypatch.setenv("SIGNET_HOME", str(home))
    (home / "keys").mkdir(parents=True)
    outside = tmp_path / "nowhere"
    outside.mkdir()
    code, out, _ = hk("Write", {"file_path": str(home / "keys" / "local_ed25519.json"),
                                "content": "{}"}, outside)
    d = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and d["permissionDecision"] == "deny"
    assert "signet home" in d["permissionDecisionReason"]


# ---------------------------------------------------------------------------
# SELF-PROTECT (before the user policy loads)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", [".signet/policy.yaml", ".signet/anything.txt",
                                  ".claude/settings.json", ".claude/settings.local.json"])
def test_self_protect_edit_class(repo, path):
    for tool, ti in (("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}),
                     ("Write", {"file_path": path, "content": "x"})):
        d = decision(hk(tool, ti, repo))
        assert d["permissionDecision"] == "deny", (tool, path)
        assert "self-protected" in d["permissionDecisionReason"]


def test_self_protect_fires_even_with_invalid_policy(repo):
    # SELF-PROTECT is evaluated BEFORE the user policy loads: a broken policy must not
    # downgrade the fence-moving edit from deny to ask.
    (repo / ".signet" / "policy.yaml").write_text("version: 99\n")
    d = decision(hk("Write", {"file_path": ".signet/policy.yaml", "content": "v"}, repo))
    assert d["permissionDecision"] == "deny"


def test_self_protect_bash_redirect(repo):
    d = decision(hk("Bash", {"command": "echo x >> .signet/policy.yaml"}, repo))
    assert d["permissionDecision"] == "deny"
    assert "self-protect" in d["permissionDecisionReason"]


@pytest.mark.parametrize("cmd", [
    "rm -rf .signet",
    "mv .signet/policy.yaml /tmp/x",
    "tee .claude/settings.json < /tmp/evil",
    "sed -i '' 's/deny/ask/' .signet/policy.yaml",
    "echo '{}' > .claude/settings.json",
    "rm -rf ~/.signet",
])
def test_self_protect_bash_patterns(repo, cmd):
    d = decision(hk("Bash", {"command": cmd}, repo))
    assert d["permissionDecision"] == "deny", cmd


def test_bash_ask_pattern(repo):
    d = decision(hk("Bash", {"command": "terraform plan -out tf.plan"}, repo))
    assert d["permissionDecision"] == "ask"


# ---------------------------------------------------------------------------
# monotonicity + fail-closed degradation
# ---------------------------------------------------------------------------
def test_never_emits_allow_across_sweep(repo):
    cases = [
        ("Edit", {"file_path": p, "old_string": "a", "new_string": "b"})
        for p in ("auth/login.py", "docs/readme.md", ".signet/policy.yaml",
                  "../escape.txt", "free.py")
    ] + [("Bash", {"command": c}) for c in
         ("git push --force", "echo hi", "rm .signet/x", "terraform plan")]
    for tool, ti in cases:
        code, out, _ = hk(tool, ti, repo)
        assert code == 0
        if out:
            assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] in \
                ("deny", "ask")


def test_receipt_failure_degrades_pass_to_ask_and_keeps_deny(repo, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(hook_mod, "_append_receipt", boom)
    d = decision(hk("Write", {"file_path": "docs/new.md", "content": "x"}, repo))
    assert d["permissionDecision"] == "ask"            # a pass without its receipt escalates
    d = decision(hk("Edit", {"file_path": "auth/login.py", "old_string": "a",
                             "new_string": "b"}, repo))
    assert d["permissionDecision"] == "deny"           # a deny NEVER weakens


def test_emission_failure_falls_back_to_exit_2_deny(repo, monkeypatch, capsys):
    import io
    payload = json.dumps({"tool_name": "Edit", "cwd": str(repo),
                          "tool_input": {"file_path": "auth/login.py",
                                         "old_string": "a", "new_string": "b"}})
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))

    class Broken:
        def write(self, *_):
            raise OSError("stdout gone")
        def flush(self):
            raise OSError("stdout gone")
    monkeypatch.setattr(sys, "stdout", Broken())
    assert hook_mod.main() == 2
    assert "protected" in capsys.readouterr().err


def test_exactly_one_receipt_per_evaluated_call(repo):
    before = len(receipts(repo))
    hk("Edit", {"file_path": "auth/login.py", "old_string": "a", "new_string": "b"}, repo)
    hk("Write", {"file_path": "docs/readme.md", "content": "y"}, repo)
    hk("Bash", {"command": "echo hi"}, repo)
    hk("Read", {"file_path": "auth/login.py"}, repo)        # not evaluated
    recs = receipts(repo)
    assert len(recs) == before + 3
    assert [r["verdict"] for r in recs[-3:]] == ["deny", "pass", "pass"]
    assert all(r["policy_hash"] for r in recs[-3:])         # bound to the deciding policy


# ---------------------------------------------------------------------------
# GATE-PURITY: the hook import path carries no evals / network / heavy deps
# ---------------------------------------------------------------------------
def test_gate_purity_import_path():
    code = (
        "import sys; import signet.cli.hook, signet.cli.local_receipts, signet.fence;"
        "roots = {m.split('.')[0] for m in sys.modules};"
        "bad = roots & {'evals', 'fastapi', 'xrpl', 'requests', 'urllib3', 'pydantic'};"
        "print(','.join(sorted(bad)))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=str(Path(__file__).parents[1]))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "", f"forbidden modules on hook path: {out.stdout}"


# ---------------------------------------------------------------------------
# the end-to-end CLI surface (console-script equivalent via -m)
# ---------------------------------------------------------------------------
def test_cli_hook_subprocess_real_payload(repo):
    payload = _real("edit", repo, file_path=str(repo / "auth" / "login.py"))
    env = dict(os.environ, SIGNET_HOME=str(signet_home()),
               PYTHONPATH=str(Path(__file__).parents[1]))
    out = subprocess.run([sys.executable, "-m", "signet.cli.main", "hook"],
                         input=json.dumps(payload), capture_output=True, text=True, env=env)
    assert out.returncode == 0
    d = json.loads(out.stdout)["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny"
