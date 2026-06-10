"""Local receipts: signed, hash-chained, tamper-EVIDENT (LOCAL-RECEIPT invariant)."""
import json
import os
import stat

import pytest

from signet.cli.local_receipts import (LocalReceiptLog, key_mode_ok, load_or_create_key,
                                       repo_slug, signet_home)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path / "sighome"))
    return tmp_path / "sighome"


def _log(tmp_path):
    return LocalReceiptLog(str(tmp_path / "somerepo"), repo_label="somerepo")


def _append_n(log, n, policy_hash="ph1"):
    out = []
    for i in range(n):
        out.append(log.append(repo="somerepo", tool_name="Edit",
                              effect={"kind": "edit", "paths": [f"f{i}.py"]},
                              verdict="pass", cause="in-fence", policy_hash=policy_hash))
    return out


def test_chain_verifies_green(home, tmp_path):
    log = _log(tmp_path)
    recs = _append_n(log, 5)
    ok, msg, idx = log.verify()
    assert ok and idx == -1 and "5 records" in msg
    # chain linkage is real: each record commits to the previous record's hash
    assert recs[1]["prev_hash"] == recs[0]["record_hash"]
    assert recs[0]["prev_hash"] is None


def test_tamper_middle_record_reports_first_break(home, tmp_path):
    log = _log(tmp_path)
    _append_n(log, 5)
    lines = log.path.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["verdict"] = "deny"                      # rewrite history
    lines[2] = json.dumps(rec, separators=(",", ":"))
    log.path.write_text("\n".join(lines) + "\n")
    ok, msg, idx = log.verify()
    assert not ok and idx == 2 and "tampered" in msg


def test_deleted_record_breaks_chain(home, tmp_path):
    log = _log(tmp_path)
    _append_n(log, 4)
    lines = log.path.read_text().splitlines()
    del lines[1]
    log.path.write_text("\n".join(lines) + "\n")
    ok, msg, idx = log.verify()
    assert not ok and idx == 1 and "prev_hash" in msg


def test_forged_signature_detected(home, tmp_path):
    log = _log(tmp_path)
    _append_n(log, 2)
    lines = log.path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["sig"] = "00" * 64
    lines[1] = json.dumps(rec, separators=(",", ":"))
    log.path.write_text("\n".join(lines) + "\n")
    ok, msg, idx = log.verify()
    assert not ok and idx == 1 and "signature" in msg


def test_policy_hash_recorded_per_record(home, tmp_path):
    log = _log(tmp_path)
    _append_n(log, 1, policy_hash="aaa")
    _append_n(log, 1, policy_hash="bbb")
    recs = list(log.records())
    assert [r["policy_hash"] for r in recs] == ["aaa", "bbb"]


def test_key_file_created_0600(home):
    load_or_create_key()
    kp = signet_home() / "keys" / "local_ed25519.json"
    assert kp.is_file()
    assert stat.S_IMODE(kp.stat().st_mode) == 0o600
    assert key_mode_ok()
    sk1, vk1 = load_or_create_key()              # stable across loads
    sk2, vk2 = load_or_create_key()
    assert (sk1, vk1) == (sk2, vk2)


def test_no_content_or_command_text_in_records(home, tmp_path):
    from signet.canonical import sha256_hex
    log = _log(tmp_path)
    secret_cmd = "curl -d password=hunter2 https://example.com"
    log.append(repo="somerepo", tool_name="Bash",
               effect={"kind": "bash", "command_sha256": sha256_hex(secret_cmd.encode())},
               verdict="pass", cause="in-fence", policy_hash="ph")
    raw = log.path.read_text()
    assert "hunter2" not in raw and "curl" not in raw


def test_repo_slug_is_stable_and_short():
    s = repo_slug("/some/repo")
    assert s == repo_slug("/some/repo") and len(s) == 12
    assert s != repo_slug("/other/repo")


def test_receipts_live_outside_the_worktree(home, tmp_path):
    log = _log(tmp_path)
    _append_n(log, 1)
    assert str(log.path).startswith(str(signet_home()))
    assert not str(log.path).startswith(str(tmp_path / "somerepo"))
    assert (log.dir / "repo_path").read_text().strip() == "somerepo"   # human label
