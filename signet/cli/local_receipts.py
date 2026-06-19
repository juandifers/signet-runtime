"""Signed, hash-chained LOCAL decision receipts for the `signet hook` gate.

Mirrors the hash/sign discipline of signet/receipts.py (hash the canonical payload
excluding hash+sig; sign the hash; each record commits to the previous record's hash)
but as an append-only JSONL file under the signet home dir — OUTSIDE the agent's
worktree, so the agent cannot reach it by default (FORK A: home dir chosen).

Records are "signet.local_decision.v1". Every evaluated tool call appends exactly one
record bound to the policy_hash that decided it (LOCAL-RECEIPT invariant). Pass receipts
are ON (FORK B): they make the log a usable activity record and they are cheap.

Privacy: file CONTENTS and full bash command text are NEVER logged — a bash command is
recorded only as its sha256.

Tamper-EVIDENT, not tamper-proof: anyone with this machine's user account (including a
human) can delete or rewrite the file, but `signet receipts --verify` will report the
first break in the chain. The non-falsifiable record is the server-side rail's (Stage 3).
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from ..canonical import hash_obj, sha256_hex

RECORD_SCHEMA = "signet.local_decision.v1"

VERDICT_DENY = "deny"
VERDICT_ASK = "ask"
VERDICT_PASS = "pass"


def signet_home() -> Path:
    """The signet home dir. SIGNET_HOME overrides (tests; never set it to a worktree path —
    the home dir is deliberately outside agent reach)."""
    env = os.environ.get("SIGNET_HOME")
    return Path(env).expanduser() if env else Path("~/.signet").expanduser()


def repo_slug(repo_root_realpath: str) -> str:
    return sha256_hex(str(repo_root_realpath).encode())[:12]


def _key_path() -> Path:
    return signet_home() / "keys" / "local_ed25519.json"


def load_or_create_key() -> Tuple[str, str]:
    """Return (signing_key_hex, verify_key_hex); create with 0600 (dir 0700) if missing."""
    kp = _key_path()
    if kp.is_file():
        data = json.loads(kp.read_text())
        return data["signing_key"], data["verify_key"]
    from .. import crypto  # lazy: only the signing paths pay the nacl import
    sk, vk = crypto.generate_keypair()
    kp.parent.mkdir(parents=True, exist_ok=True)
    kp.parent.chmod(0o700)
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"schema": "signet.local_key.v1", "algo": "ed25519",
                   "signing_key": sk, "verify_key": vk}, f)
    return sk, vk


def key_mode_ok() -> bool:
    kp = _key_path()
    return kp.is_file() and stat.S_IMODE(kp.stat().st_mode) == 0o600


class LocalReceiptLog:
    """Append-only JSONL log for ONE repo (keyed by the realpath slug)."""

    def __init__(self, repo_root_realpath: str, repo_label: Optional[str] = None):
        self.repo_root = str(repo_root_realpath)
        self.dir = signet_home() / repo_slug(self.repo_root)
        self.path = self.dir / "receipts.jsonl"
        self._label = repo_label or self.repo_root

    def _ensure_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        label = self.dir / "repo_path"
        if not label.exists():
            label.write_text(self._label + "\n")

    def _last_hash(self) -> Optional[str]:
        if not self.path.is_file():
            return None
        last = None
        with self.path.open("rb") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return None
        return json.loads(last).get("record_hash")

    def append(self, *, repo: Optional[str], tool_name: str, effect: dict,
               verdict: str, cause: str, policy_hash: Optional[str]) -> dict:
        """Append one signed record; returns it (record_id is in `id`)."""
        from .. import crypto  # lazy
        self._ensure_dir()
        sk, _vk = load_or_create_key()
        record = {
            "schema": RECORD_SCHEMA,
            "id": "ldr_" + uuid.uuid4().hex[:12],
            "ts": datetime.now(timezone.utc).isoformat(),
            "repo": repo,
            "tool_name": tool_name,
            "effect": effect,                 # {kind: edit|bash, paths:[...] | command_sha256}
            "verdict": verdict,
            "cause": cause,
            "policy_hash": policy_hash,
            "prev_hash": self._last_hash(),
        }
        record["record_hash"] = hash_obj(record)   # excludes record_hash + sig by construction
        record["sig"] = crypto.sign(sk, record["record_hash"].encode())
        with self.path.open("a") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
        return record

    def records(self) -> Iterator[dict]:
        if not self.path.is_file():
            return iter(())
        out = []
        with self.path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return iter(out)

    def verify(self) -> Tuple[bool, str, int]:
        """Recompute the chain + signatures. Returns (ok, message, first_bad_index|-1)."""
        from .. import crypto  # lazy
        try:
            _sk, vk = load_or_create_key()
        except Exception as e:
            return False, f"cannot load local key: {e}", -1
        prev = None
        recs: List[dict] = list(self.records())
        for i, r in enumerate(recs):
            payload = {k: v for k, v in r.items() if k not in ("record_hash", "sig")}
            if r.get("prev_hash") != prev:
                return False, f"record {i} ({r.get('id')}): prev_hash broken (chain cut or reordered)", i
            if hash_obj(payload) != r.get("record_hash"):
                return False, f"record {i} ({r.get('id')}): record_hash does not match contents (tampered)", i
            if not r.get("sig") or not crypto.verify(vk, r["record_hash"].encode(), r["sig"]):
                return False, f"record {i} ({r.get('id')}): signature invalid", i
            prev = r["record_hash"]
        return True, f"{len(recs)} records verified (chain + signatures intact)", -1
