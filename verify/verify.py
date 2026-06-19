#!/usr/bin/env python3
"""Standalone, clean-room receipt verifier for Signet egress receipts.

INDEPENDENCE IS THE WHOLE POINT. This module imports NOTHING from Signet — not the
transparency log, not the rail core, not any shared crypto/serialization helper. It uses
only the Python standard library and reimplements every check from `RECEIPT_FORMAT.md`.
If it borrowed Signet's own verification code it would prove nothing to a skeptic; it
would be Signet checking Signet. The only coupling is the published wire format (data).

It makes no network calls and reads no Signet state. Inputs are a receipt file and an
anchor root (hex string or a file containing one), obtained out of band by the operator.

Fail closed, fail loud: any missing field, malformed proof, serialization mismatch, or
root mismatch returns FAILED naming the specific failing check, with a nonzero exit code.
VERIFIED prints only when every check passed.

Read it top to bottom in one sitting — that is a feature.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from typing import Any, Dict, List, Tuple

LEAF_PREFIX = b"\x00"      # RFC 6962 domain separation: leaf
NODE_PREFIX = b"\x01"      # RFC 6962 domain separation: interior node

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMITMENT = re.compile(r"^sha256:[0-9a-f]{64}$")


class VerifyError(Exception):
    """A named, fail-loud verification failure. `check` is the specific failing check."""

    def __init__(self, check: str, detail: str) -> None:
        super().__init__(f"{check}: {detail}")
        self.check = check
        self.detail = detail


# ============================================================================
# Serialization + hashing (reimplemented from RECEIPT_FORMAT.md §1)
# ============================================================================
def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, tight separators, UTF-8, ensure_ascii=False."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(NODE_PREFIX + left + right)


def _largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


# ============================================================================
# Structural parse + validation (RECEIPT_FORMAT.md §3)
# ============================================================================
_TOP = ("decision", "effect", "policy_basis", "leaf", "inclusion_proof", "claimed_root")
_EFFECT = ("class", "destination", "payload_commitment", "session_id", "timestamp")
_BASIS = ("layer", "axis", "rule", "learned_rule_id")
_PROOF = ("leaf_index", "tree_size", "audit_path")


def _require_keys(obj: Any, keys: Tuple[str, ...], where: str) -> None:
    if not isinstance(obj, dict):
        raise VerifyError("structure", f"{where} is not a JSON object")
    have = set(obj)
    want = set(keys)
    missing = want - have
    extra = have - want
    if missing:
        raise VerifyError("structure", f"{where} missing field(s): {sorted(missing)}")
    if extra:
        raise VerifyError("structure", f"{where} has unexpected field(s): {sorted(extra)}")


def _norm_hash(s: Any, field: str) -> str:
    if not isinstance(s, str):
        raise VerifyError("hash-format", f"{field} is not a string")
    v = s[len("sha256:"):] if s.startswith("sha256:") else s
    if not _HEX64.match(v):
        raise VerifyError("hash-format", f"{field} is not 64 lowercase hex chars: {s!r}")
    return v


def parse_receipt(path: str) -> Dict[str, Any]:
    """Parse and structurally validate a receipt file; fail loud on any missing/extra/
    wrong-typed field. Returns the raw dict (hashes left as strings)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise VerifyError("parse", f"receipt file not found: {path}")
    except json.JSONDecodeError as e:
        raise VerifyError("parse", f"not valid JSON: {e}")

    _require_keys(raw, _TOP, "receipt")
    _require_keys(raw["effect"], _EFFECT, "effect")
    _require_keys(raw["policy_basis"], _BASIS, "policy_basis")
    _require_keys(raw["leaf"], ("leaf_hash",), "leaf")
    _require_keys(raw["inclusion_proof"], _PROOF, "inclusion_proof")

    if not isinstance(raw["decision"], str):
        raise VerifyError("structure", "decision is not a string")

    eff = raw["effect"]
    for k in _EFFECT:
        if not isinstance(eff[k], str) or not eff[k]:
            raise VerifyError("structure", f"effect.{k} must be a non-empty string")

    basis = raw["policy_basis"]
    for k in ("layer", "axis", "rule"):
        if not isinstance(basis[k], str) or not basis[k]:
            raise VerifyError("structure", f"policy_basis.{k} must be a non-empty string")
    if basis["learned_rule_id"] is not None and not isinstance(basis["learned_rule_id"], str):
        raise VerifyError("structure", "policy_basis.learned_rule_id must be a string or null")

    proof = raw["inclusion_proof"]
    if not isinstance(proof["leaf_index"], int) or isinstance(proof["leaf_index"], bool):
        raise VerifyError("structure", "inclusion_proof.leaf_index must be an integer")
    if not isinstance(proof["tree_size"], int) or isinstance(proof["tree_size"], bool):
        raise VerifyError("structure", "inclusion_proof.tree_size must be an integer")
    if not isinstance(proof["audit_path"], list):
        raise VerifyError("structure", "inclusion_proof.audit_path must be a list")
    if proof["tree_size"] < 1:
        raise VerifyError("structure", "inclusion_proof.tree_size must be >= 1")
    if not (0 <= proof["leaf_index"] < proof["tree_size"]):
        raise VerifyError("structure",
                          f"leaf_index {proof['leaf_index']} out of range for tree_size "
                          f"{proof['tree_size']}")
    # normalize all hash-shaped fields (raises on malformed)
    _norm_hash(raw["leaf"]["leaf_hash"], "leaf.leaf_hash")
    _norm_hash(raw["claimed_root"], "claimed_root")
    for i, h in enumerate(proof["audit_path"]):
        _norm_hash(h, f"audit_path[{i}]")
    return raw


# ============================================================================
# Leaf recomputation (RECEIPT_FORMAT.md §4) — proves WHAT was committed
# ============================================================================
def recompute_leaf_hash(receipt: Dict[str, Any]) -> bytes:
    leaf_contents = {"decision": receipt["decision"],
                     "effect": receipt["effect"],
                     "policy_basis": receipt["policy_basis"]}
    return _sha256(LEAF_PREFIX + canonical_bytes(leaf_contents))


# ============================================================================
# Inclusion walk (RECEIPT_FORMAT.md §2) — KAT-gated, no trusted bit math
# ============================================================================
def root_from_proof(leaf: bytes, index: int, tree_size: int, audit_path: List[bytes]) -> bytes:
    """Recompute the Merkle root from a leaf and its bottom-up sibling path. The side of each
    sibling is derived from (index, tree_size) by the largest-power-of-two split — never stored,
    never guessed. Raises VerifyError on any malformed shape (wrong path length, bad index)."""
    root = _walk(leaf, index, tree_size, list(audit_path))
    if root is None:
        raise VerifyError("inclusion", "audit path is malformed for this (leaf_index, tree_size)")
    return root


def _walk(leaf: bytes, m: int, n: int, path: List[bytes]):
    if n <= 0 or m < 0 or m >= n:
        return None
    if n == 1:
        return leaf if not path else None
    if not path:
        return None
    k = _largest_pow2_below(n)
    sibling = path[-1]
    if m < k:
        left = _walk(leaf, m, k, path[:-1])
        return _node_hash(left, sibling) if left is not None else None
    right = _walk(leaf, m - k, n - k, path[:-1])
    return _node_hash(sibling, right) if right is not None else None


# ============================================================================
# Anchor input
# ============================================================================
def load_anchor(anchor_arg: str) -> str:
    """The anchor is hex on the command line, or a path to a file containing the hex. Obtained
    out of band by the operator; we never fetch it."""
    candidate = anchor_arg.strip()
    # try as a file first, but only if it does not already look like a bare hash
    import os
    if os.path.exists(candidate):
        with open(candidate, "r", encoding="utf-8") as f:
            candidate = f.read().strip()
    return _norm_hash(candidate, "anchor")


# ============================================================================
# Attestation (RECEIPT_FORMAT.md §5)
# ============================================================================
def attest(receipt: Dict[str, Any], anchor_hex: str, *, expect_decision: str) -> List[str]:
    """Run every check in order; raise VerifyError (named) on the first failure. On success
    return the verdict body lines (the bounded attestation)."""
    eff = receipt["effect"]
    basis = receipt["policy_basis"]
    proof = receipt["inclusion_proof"]

    # 2. decision matches the requested mode
    if receipt["decision"] != expect_decision:
        raise VerifyError("decision",
                          f"receipt decision is {receipt['decision']!r}, expected "
                          f"{expect_decision!r} (use --allow for ALLOW-mode control receipts)")

    # 3. egress effect shape
    if eff["class"] != "egress":
        raise VerifyError("effect-class", f"effect.class is {eff['class']!r}, expected 'egress'")

    # 4. payload is a commitment, never raw data (confidentiality)
    if not _COMMITMENT.match(eff["payload_commitment"]):
        raise VerifyError("payload-commitment",
                          "payload_commitment is not a 'sha256:<64hex>' commitment — refusing to "
                          "attest a receipt that may carry raw payload")

    # 5. recomputed leaf hash matches the committed leaf (the binding)
    recomputed_leaf = recompute_leaf_hash(receipt)
    stored_leaf = _norm_hash(receipt["leaf"]["leaf_hash"], "leaf.leaf_hash")
    if recomputed_leaf.hex() != stored_leaf:
        raise VerifyError("leaf-binding",
                          "recomputed leaf hash does not match the committed leaf — the receipt's "
                          "stated effect/decision/basis does not hash to what was recorded")

    # 6. inclusion: walk the proof to a root
    audit = [bytes.fromhex(_norm_hash(h, "audit_path")) for h in proof["audit_path"]]
    computed_root = root_from_proof(recomputed_leaf, proof["leaf_index"], proof["tree_size"], audit)
    claimed_root = _norm_hash(receipt["claimed_root"], "claimed_root")
    if computed_root.hex() != claimed_root:
        raise VerifyError("inclusion",
                          "computed root does not match the receipt's claimed_root — the leaf is "
                          "not in this tree (tampered audit path or wrong sibling)")

    # 7. equivocation: claimed root equals the independently-supplied anchor
    if claimed_root != anchor_hex:
        raise VerifyError("anchor",
                          "claimed_root does not match the supplied anchor root — the log this "
                          "receipt came from is not the anchored one (equivocation)")

    # 8. basis: standing-vs-learned governs the STRENGTH of the claim (not pass/fail of inclusion)
    layer = basis["layer"]
    lrid = basis["learned_rule_id"]
    if layer == "standing":
        if lrid is not None:
            raise VerifyError("policy-basis",
                              "layer is 'standing' but learned_rule_id is set — inconsistent basis")
        basis_line = (f"basis:     standing hard axis {basis['axis']!r} "
                      f"(not a learned rule; \"{basis['rule']}\")")
        claim_line = ("claim:     this exact "
                      f"{'denied' if expect_decision == 'DENY' else 'allowed'} egress is recorded, "
                      "unaltered, in the anchored log, on the operator's STANDING fence — the part "
                      "no approval could move.")
    elif layer == "learned":
        if lrid is None:
            raise VerifyError("policy-basis",
                              "layer is 'learned' but learned_rule_id is null — inconsistent basis")
        basis_line = (f"basis:     LEARNED rule {lrid!r} on axis {basis['axis']!r} — NOT the "
                      "operator ceiling; this decision could be moved by an approval")
        claim_line = ("claim:     this exact egress decision is recorded, unaltered, in the anchored "
                      "log; it rests on a LEARNED rule, so it is NOT attested as the operator "
                      "standing fence.")
    else:
        raise VerifyError("policy-basis", f"unknown policy_basis.layer {layer!r}")

    return [
        f"effect:    {eff['class']} → {eff['destination']}",
        f"payload:   {eff['payload_commitment']}  (commitment only)",
        f"decision:  {receipt['decision']}",
        basis_line,
        f"inclusion: leaf {proof['leaf_index']} of tree size {proof['tree_size']} "
        f"→ root {claimed_root}",
        "anchor:    matches supplied root",
        claim_line,
    ]


# ============================================================================
# CLI
# ============================================================================
def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Independently verify a Signet egress receipt against an anchor root.")
    ap.add_argument("receipt", help="path to the receipt JSON file")
    ap.add_argument("--anchor", required=True,
                    help="anchor root: 64-hex string (optional 'sha256:' prefix) or a file with one")
    ap.add_argument("--allow", action="store_true",
                    help="ALLOW mode: expect decision=ALLOW (for the legitimate-egress control)")
    args = ap.parse_args(argv)
    expect = "ALLOW" if args.allow else "DENY"

    try:
        receipt = parse_receipt(args.receipt)
        anchor_hex = load_anchor(args.anchor)
        lines = attest(receipt, anchor_hex, expect_decision=expect)
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
