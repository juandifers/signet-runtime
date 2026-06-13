"""Record real egress decisions into an anchored Merkle log and export self-contained receipts
in the published wire format (`verify/RECEIPT_FORMAT.md`).

This is the RUNTIME side of the standalone-verifier story: it is allowed to use Signet. It runs
the REAL egress destination decision (`effective_admits` over an operator `EgressStandingPolicy`
∩ a per-task `EgressMandate`) to classify each connection, derives the structured `policy_basis`
(standing-vs-learned, reusing the convergence build's distinction), commits each decision as a
Merkle leaf using Signet's UNCHANGED RFC-6962 primitives, and writes golden receipts + the anchor
root to `verify/testdata/`. The clean-room verifier then reproduces every hash from the format doc
alone — proving it needs none of this code.

Run:  python -m evals.egress_receipts.record
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from signet.canonical import canonical_json

# Merkle primitives: reused from the unchanged transparency log so the recorder and the clean-room
# verifier share ONE node convention (0x01) — the verifier reimplements it and KATs prove they agree.
from evals._rail_core.transparency import audit_path, merkle_root

# Real egress decision logic.
from signet.rails.egress.effect import EgressEffect
from signet.rails.egress.mandate import (EgressGrant, EgressMandate, EgressStandingPolicy,
                                         effective_admits)

# The standing-vs-learned basis distinction, from the policy-convergence build.
from evals._rail_core.policy_spec import (CATEGORICAL, OWN, SOFT, AttrDecl, Condition, IN_SET)
from evals._rail_core.policy_convergence import (ActiveLayer, Standing, confirm, generalize)

_OUT = Path(__file__).resolve().parents[2] / "verify" / "testdata"
_TS = "2026-06-13T00:00:00Z"
_SESSION = "run_2026_06_13_001"


def _leaf_hash_hex(body: Dict) -> str:
    """leaf_hash = SHA-256( 0x00 || canonical_bytes(body) ) — identical to verify.py / the format doc."""
    return hashlib.sha256(b"\x00" + canonical_json(body)).hexdigest()


def _commit(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


# ----------------------------------------------------------------------------
# Build the policy_basis for an egress destination decision via the REAL decision fn.
# ----------------------------------------------------------------------------
def _standing_basis(eff: EgressEffect, mandate: EgressMandate,
                    standing: EgressStandingPolicy) -> Tuple[str, Dict]:
    """Return (decision, policy_basis) from the real `effective_admits`. A destination outside the
    operator's standing allow-set is denied on the STANDING hard axis `egress_destination` — the
    part of the fence no approval (no learned rule) can move (learned rules only open SOFT axes)."""
    admitted, reason = effective_admits(eff, mandate, standing)
    if admitted:
        return "ALLOW", {"layer": "standing", "axis": "egress_destination",
                         "rule": "destination within operator standing allow-set ∩ task mandate",
                         "learned_rule_id": None}
    # both out-of-standing and out-of-mandate are recorded against the standing egress axis; the
    # destination is not one the operator's ceiling permits.
    return "DENY", {"layer": "standing", "axis": "egress_destination",
                    "rule": f"destination not in operator standing allow-set ({reason})",
                    "learned_rule_id": None}


def _learned_rule_id() -> str:
    """Mint a GENUINE convergence learned rule (soft axis opened within an operator-declared class)
    and return its id — so the learned-basis fixture's id traces to a real confirmable rule, not a
    placeholder. egress_destination stays HARD here; only a soft axis is learnable."""
    schema = (AttrDecl("egress_destination",
                       CATEGORICAL({"none", "api.supabase.internal"}), OWN),     # HARD (default)
              AttrDecl("command_class",
                       CATEGORICAL({"test_runner", "build_tool", "deploy_tool"}), OWN, variability=SOFT))
    standing = Standing(ceiling=(
        Condition("egress_destination", IN_SET, frozenset({"none", "api.supabase.internal"})),
        Condition("command_class", IN_SET, frozenset({"test_runner", "build_tool", "deploy_tool"}))))
    approved = {"egress_destination": "api.supabase.internal", "command_class": "test_runner"}
    cand = generalize(approved, schema, standing,
                      declared_classes={"command_class": frozenset({"test_runner", "build_tool"})},
                      from_effect="eff_egress_learned")
    layer = ActiveLayer()
    rule, _ = confirm(cand, layer, rule_id="lr_egress_softclass", created_at=_TS)
    return rule.id


# ============================================================================
# Stage 1 — the IN-PATH emitter (the block IS the receipt)
# ============================================================================
# Decision vocabulary at the chokepoint. ALLOW/DENY come straight from the real
# `effective_admits`; REVIEW is the in-ceiling-but-not-granted case (held, never an allow).
ALLOW, DENY, REVIEW = "ALLOW", "DENY", "REVIEW"


def _three_way_basis(eff: EgressEffect, mandate: EgressMandate,
                     standing: EgressStandingPolicy) -> Tuple[str, Dict]:
    """Run the REAL egress decision and map it to the chokepoint's three-way disposition + the
    structured policy_basis. This is the single source of truth — the chokepoint calls it and the
    same call commits the leaf.

      * within standing ∩ mandate                -> ALLOW  (perform egress)
      * outside the operator STANDING allow-set  -> DENY   (the hard axis no approval can move)
      * in the standing ceiling but NOT granted   -> REVIEW (held, no human; never silently allowed)
        by this task's mandate
    """
    admitted, reason = effective_admits(eff, mandate, standing)
    if admitted:
        return ALLOW, {"layer": "standing", "axis": "egress_destination",
                       "rule": "destination within operator standing allow-set ∩ task mandate",
                       "learned_rule_id": None}
    if reason == "out-of-standing-policy":
        return DENY, {"layer": "standing", "axis": "egress_destination",
                      "rule": "destination not in operator standing allow-set",
                      "learned_rule_id": None}
    # out-of-mandate-destination: the operator's ceiling would permit this host, but THIS task was
    # not granted it -> escalate. With no human present the chokepoint holds it (fail-safe).
    return REVIEW, {"layer": "standing", "axis": "egress_destination",
                    "rule": "in standing ceiling but not granted by this task's mandate — escalate",
                    "learned_rule_id": None}


@dataclass(frozen=True)
class EgressReceipt:
    """The block's output, fixed at decision time: the decision, the bound effect, the basis, and
    the committed leaf (with its append-order index). The Merkle inclusion proof + claimed_root are
    NOT here yet — they are stamped by `to_wire` at publish time against the finalized tree (a
    membership proof is relative to a tree size; the LEAF is the commitment, and it is fixed now)."""
    leaf_index: int
    decision: str
    effect: Dict
    policy_basis: Dict
    leaf_hash: str

    def to_wire(self, audit_path_hexes: List[str], root: str, tree_size: int) -> Dict:
        return {
            "decision": self.decision, "effect": self.effect, "policy_basis": self.policy_basis,
            "leaf": {"leaf_hash": self.leaf_hash},
            "inclusion_proof": {"leaf_index": self.leaf_index, "tree_size": tree_size,
                                "audit_path": list(audit_path_hexes)},
            "claimed_root": root,
        }


class EgressMerkleLog:
    """Append-only Merkle log of egress decision leaves, built with the UNCHANGED transparency.py
    primitives (`merkle_root`/`audit_path`). `emit` runs the real decision and appends the leaf at
    the moment of the attempted egress — the decision that blocks is the call that appends the leaf.
    `finalize` computes the root and each leaf's inclusion proof against the complete tree."""

    def __init__(self, standing: EgressStandingPolicy, mandate: EgressMandate, *,
                 session_id: str, clock: Optional[Callable[[], str]] = None) -> None:
        self._standing = standing
        self._mandate = mandate
        self._session_id = session_id
        self._clock = clock or (lambda: _TS)
        self._leaves: List[str] = []
        self._drafts: List[EgressReceipt] = []

    def emit(self, *, destination: str, host: str, port: int, payload: bytes,
             protocol: str = "http_connect") -> Tuple[str, EgressReceipt]:
        """Run the real decision for this bound egress, commit its leaf, and return
        (decision, receipt). Synchronous and anchor-free — the decision is final before any
        anchoring exists."""
        eff = EgressEffect(host, port, protocol)
        decision, basis = _three_way_basis(eff, self._mandate, self._standing)
        effect = {"class": "egress", "destination": destination,
                  "payload_commitment": _commit(payload),
                  "session_id": self._session_id, "timestamp": self._clock()}
        body = {"decision": decision, "effect": effect, "policy_basis": basis}
        leaf = _leaf_hash_hex(body)
        idx = len(self._leaves)
        self._leaves.append(leaf)
        draft = EgressReceipt(leaf_index=idx, decision=decision, effect=effect,
                              policy_basis=basis, leaf_hash=leaf)
        self._drafts.append(draft)
        return decision, draft

    def root(self) -> str:
        return merkle_root(self._leaves)

    def size(self) -> int:
        return len(self._leaves)

    def drafts(self) -> List[EgressReceipt]:
        return list(self._drafts)

    def finalize(self) -> Tuple[str, List[Dict]]:
        """After the run: read the root and stamp each committed leaf's inclusion proof against the
        complete tree. Returns (root, wire_receipts) in append order."""
        root = self.root()
        n = len(self._leaves)
        wire = [d.to_wire(audit_path(d.leaf_index, self._leaves), root, n) for d in self._drafts]
        return root, wire


# ----------------------------------------------------------------------------
# The recorded run (the original fixture generator — unchanged, still backs the golden fixtures)
# ----------------------------------------------------------------------------
def build_receipts() -> Dict[str, Dict]:
    """Run a batch of egress decisions, commit them to one Merkle tree, and return the exported
    receipts keyed by name plus the shared anchor root."""
    # Operator standing fence + a per-task mandate (narrows, never widens).
    standing = EgressStandingPolicy(grants=(
        EgressGrant("api.supabase.internal", (443,)),
        EgressGrant("*.allowed.test", (443,)),
    ))
    mandate = EgressMandate(task_id="task-1", grants=(
        EgressGrant("api.supabase.internal", (443,)),
        EgressGrant("*.allowed.test", (443,)),
    ))

    # Each entry: (name|None, decision, policy_basis, effect-fields, attempted-payload-bytes)
    entries: List[Tuple] = []

    def egress_effect(host, port, dest_str, payload, *, learned_id=None):
        eff = EgressEffect(host, port, "http_connect")
        decision, basis = _standing_basis(eff, mandate, standing)
        if learned_id is not None:                       # override basis to a learned-rule basis
            decision, basis = "ALLOW", {"layer": "learned", "axis": "command_class",
                                        "rule": "admitted by a learned allow-rule (soft axis within "
                                                "its operator-declared class)",
                                        "learned_rule_id": learned_id}
        effect = {"class": "egress", "destination": dest_str,
                  "payload_commitment": _commit(payload),
                  "session_id": _SESSION, "timestamp": _TS}
        return decision, effect, basis

    # index 0 — legitimate ALLOW control
    entries.append(("legit_allow", *egress_effect(
        "api.supabase.internal", 443, "api.supabase.internal:443",
        b"GET /v1/orders HTTP/1.1 (legitimate task traffic)")))
    # index 1 — an out-of-mandate DENY (padding; not exported)
    entries.append((None, *egress_effect(
        "metrics.allowed.test", 8080, "metrics.allowed.test:8080",
        b"telemetry batch")))
    # index 2 — another legit ALLOW (padding)
    entries.append((None, *egress_effect(
        "files.allowed.test", 443, "files.allowed.test:443", b"PUT /artifact")))
    # index 3 — learned-basis ALLOW (basis is a LEARNED rule, not the operator ceiling)
    entries.append(("learned_basis", *egress_effect(
        "api.supabase.internal", 443, "api.supabase.internal:443",
        b"GET /v1/health", learned_id=_learned_rule_id())))
    # index 4 — the exfil DENY: attacker destination outside the operator's standing allow-set
    entries.append(("exfil_deny", *egress_effect(
        "attacker.example", 443, "https://attacker.example/collect",
        b"stolen secret: SUPABASE_SERVICE_ROLE=eyJ... (would-be exfil payload)")))
    # index 5 — one more denied attempt (padding)
    entries.append((None, *egress_effect(
        "evil.test", 443, "evil.test:443", b"beacon")))

    bodies = [{"decision": d, "effect": e, "policy_basis": b} for (_n, d, e, b) in entries]
    leaves = [_leaf_hash_hex(body) for body in bodies]
    root = merkle_root(leaves)

    out: Dict[str, Dict] = {"_anchor_root": root}
    for idx, (name, d, e, b) in enumerate(entries):
        if name is None:
            continue
        out[name] = {
            "decision": d, "effect": e, "policy_basis": b,
            "leaf": {"leaf_hash": leaves[idx]},
            "inclusion_proof": {"leaf_index": idx, "tree_size": len(leaves),
                                "audit_path": list(audit_path(idx, leaves))},
            "claimed_root": root,
        }
    return out


def main() -> None:
    _OUT.mkdir(parents=True, exist_ok=True)
    receipts = build_receipts()
    root = receipts.pop("_anchor_root")
    (_OUT / "anchor.txt").write_text(root + "\n", encoding="utf-8")
    for name, receipt in receipts.items():
        (_OUT / f"{name}.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {name}.json  (leaf {receipt['inclusion_proof']['leaf_index']} of "
              f"{receipt['inclusion_proof']['tree_size']})")
    print(f"anchor root: {root}")


if __name__ == "__main__":
    main()
