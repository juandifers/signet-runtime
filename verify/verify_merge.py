#!/usr/bin/env python3
"""Standalone, clean-room verifier for a Signet MERGE-rail decision-record proof bundle.

INDEPENDENCE IS THE WHOLE POINT. This module imports NOTHING from Signet — not the transparency
log, not the rail core, not signet.crypto, not any shared serialization helper. It reimplements
every check (canonical JSON, the RFC-6962 leaf/node hashing, the inclusion walk, and the Ed25519
signed-tree-head check) from scratch over the published wire format. The only third-party import is
PyNaCl's `VerifyKey` — a reference Ed25519 implementation, NOT Signet code — because verifying a
signature requires a signature library. If this borrowed Signet's own verification code it would
prove nothing to a skeptic; it would be Signet checking Signet.

It makes no network calls and reads no Signet state. Input is one bundle JSON file — the exact
object the live demo page embeds (`trace.langgraph.bundle`) and that `demos.build_demo` writes to
`docs/langgraph_receipt.json`. The bundle is self-anchoring: the enforcer public key it pins is the
trust root, and the signed tree head commits the root the inclusion proof must reach.

Fail closed, fail loud: any missing field, malformed proof, hash mismatch, or bad signature returns
FAILED naming the specific failing check, with a nonzero exit code. VERIFIED prints only when every
check passed. Read it top to bottom in one sitting — that is a feature.

    python3 verify/verify_merge.py docs/langgraph_receipt.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from typing import Any, Dict, List, Optional

LEAF_PREFIX = b"\x00"      # RFC 6962 domain separation: leaf
NODE_PREFIX = b"\x01"      # RFC 6962 domain separation: interior node
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class VerifyError(Exception):
    def __init__(self, check: str, detail: str) -> None:
        super().__init__(f"{check}: {detail}")
        self.check = check
        self.detail = detail


# ============================================================================
# Serialization + hashing (reimplemented to match signet.canonical, by spec not by import)
# ============================================================================
def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, tight separators, UTF-8, ensure_ascii=False."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _node_hash(left_hex: str, right_hex: str) -> str:
    return _sha256_hex(NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def _largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root_from_path(m: int, n: int, leaf: str, path: List[str]) -> Optional[str]:
    """Recompute the Merkle root from a leaf and its bottom-up sibling path. The side of each
    sibling is derived from (index, tree_size) by the largest-power-of-two split — never stored."""
    if n <= 0 or m < 0 or m >= n:
        return None
    if n == 1:
        return leaf if not path else None
    if not path:
        return None
    k = _largest_pow2_below(n)
    sibling = path[-1]
    if m < k:
        left = _root_from_path(m, k, leaf, path[:-1])
        return _node_hash(left, sibling) if left is not None else None
    right = _root_from_path(m - k, n - k, leaf, path[:-1])
    return _node_hash(sibling, right) if right is not None else None


# ============================================================================
# Structural parse
# ============================================================================
def _require(obj: Any, keys, where: str) -> None:
    if not isinstance(obj, dict):
        raise VerifyError("structure", f"{where} is not a JSON object")
    missing = set(keys) - set(obj)
    if missing:
        raise VerifyError("structure", f"{where} missing field(s): {sorted(missing)}")


def _norm_hash(s: Any, field: str) -> str:
    if not isinstance(s, str):
        raise VerifyError("hash-format", f"{field} is not a string")
    v = s[len("sha256:"):] if s.startswith("sha256:") else s
    if not _HEX64.match(v):
        raise VerifyError("hash-format", f"{field} is not 64 lowercase hex chars: {s!r}")
    return v


def parse_bundle(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise VerifyError("parse", f"bundle file not found: {path}")
    except json.JSONDecodeError as e:
        raise VerifyError("parse", f"not valid JSON: {e}")
    _require(raw, ("enforcer_vk", "record", "proof", "sth"), "bundle")
    _require(raw["proof"], ("leaf_index", "tree_size", "receipt_hash", "leaf_hash", "audit_path"),
             "proof")
    _require(raw["sth"], ("schema", "tree_size", "root_hash", "timestamp", "log_id", "signature"),
             "sth")
    if not isinstance(raw["record"], dict):
        raise VerifyError("structure", "record is not a JSON object")
    proof = raw["proof"]
    if not isinstance(proof["audit_path"], list):
        raise VerifyError("structure", "proof.audit_path must be a list")
    for i, h in enumerate(proof["audit_path"]):
        _norm_hash(h, f"audit_path[{i}]")
    if not (0 <= proof["leaf_index"] < proof["tree_size"]):
        raise VerifyError("structure",
                          f"leaf_index {proof['leaf_index']} out of range for tree_size "
                          f"{proof['tree_size']}")
    _norm_hash(proof["receipt_hash"], "proof.receipt_hash")
    _norm_hash(proof["leaf_hash"], "proof.leaf_hash")
    _norm_hash(raw["sth"]["root_hash"], "sth.root_hash")
    _norm_hash(raw["enforcer_vk"], "enforcer_vk")
    return raw


# ============================================================================
# Ed25519 (PyNaCl reference lib — NOT Signet)
# ============================================================================
def _ed25519_verify(vk_hex: str, message: bytes, signature_hex: str) -> bool:
    from nacl.signing import VerifyKey            # reference Ed25519 — independent of Signet
    try:
        VerifyKey(bytes.fromhex(vk_hex)).verify(message, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


# ============================================================================
# Attestation — every check, in order
# ============================================================================
def attest(bundle: Dict[str, Any]) -> List[str]:
    record = bundle["record"]
    proof = bundle["proof"]
    sth = bundle["sth"]
    vk = _norm_hash(bundle["enforcer_vk"], "enforcer_vk")

    # 1. recompute record_hash from the record's OWN bytes (sha256 of canonical JSON).
    record_hash = _sha256_hex(canonical_bytes(record))

    # 2. recompute the RFC-6962 leaf from (receipt_hash, record_hash) and bind it to the proof.
    receipt_hash = _norm_hash(proof["receipt_hash"], "proof.receipt_hash")
    leaf = _sha256_hex(LEAF_PREFIX + canonical_bytes(
        {"receipt_hash": receipt_hash, "record_hash": record_hash}))
    if leaf != _norm_hash(proof["leaf_hash"], "proof.leaf_hash"):
        raise VerifyError("leaf-binding",
                          "recomputed leaf hash does not match the proof's leaf_hash — the "
                          "record/receipt does not hash to what was committed")

    # 3. the proof must speak about the same tree the signed head describes.
    if proof["tree_size"] != sth["tree_size"]:
        raise VerifyError("tree-size", "proof tree_size != signed tree head tree_size")

    # 4. inclusion: walk the audit path to a root.
    audit = [_norm_hash(h, "audit_path") for h in proof["audit_path"]]
    root = _root_from_path(proof["leaf_index"], proof["tree_size"], leaf, audit)
    if root is None:
        raise VerifyError("inclusion", "audit path is malformed for this (leaf_index, tree_size)")
    claimed_root = _norm_hash(sth["root_hash"], "sth.root_hash")
    if root != claimed_root:
        raise VerifyError("inclusion",
                          "computed root does not match the signed root — the leaf is not in this "
                          "tree (tampered audit path or wrong sibling)")

    # 5. the signed tree head: the enforcer key must have signed THIS root.
    signing_payload = canonical_bytes(
        {"schema": sth["schema"], "tree_size": sth["tree_size"], "root_hash": sth["root_hash"],
         "timestamp": sth["timestamp"], "log_id": sth["log_id"]})
    if not sth.get("signature") or not _ed25519_verify(vk, signing_payload, sth["signature"]):
        raise VerifyError("signature",
                          "signed tree head signature is invalid under the pinned enforcer key")

    verdict = record.get("verdict", "?")
    cause = record.get("cause", "?")
    eff = record.get("effect_class", "?")
    return [
        f"record:    {record.get('schema', '?')}  (repo {record.get('repo_id', '?')})",
        f"verdict:   {verdict}  ·  effect_class {eff}  ·  cause {cause}",
        f"receipt:   {receipt_hash}",
        f"inclusion: leaf {proof['leaf_index']} of tree size {proof['tree_size']} -> root {root}",
        f"signature: valid under enforcer key {vk[:16]}…",
        "claim:     this exact enforcement decision is recorded, unaltered, in the enforcer-signed "
        "log — the orchestrator's proposal could not change what was committed.",
    ]


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Independently verify a Signet merge-rail decision proof bundle (clean-room).")
    ap.add_argument("bundle", help="path to the proof-bundle JSON (e.g. docs/langgraph_receipt.json)")
    args = ap.parse_args(argv)
    try:
        bundle = parse_bundle(args.bundle)
        lines = attest(bundle)
    except VerifyError as e:
        print(f"FAILED: {e.detail}")
        print(f"  failing check: {e.check}")
        return 1
    print("VERIFIED")
    for ln in lines:
        print(f"  {ln}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
