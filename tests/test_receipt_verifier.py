"""Tests for the standalone, clean-room receipt verifier (`verify/verify.py`).

The KATs gate the Merkle walk (RFC 6962 §2.1.1 conventions); the golden + tamper cases prove the
binding and the anchor/equivocation check; the independence test proves the verifier stands alone
with no Signet importable. The KAT vectors are computed from the documented construction with
hashlib alone — they do NOT call any Signet code, so passing them is a real known-answer check.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Make `verify/` importable for the in-process unit tests (the independence test instead runs the
# CLI as a subprocess in an environment where Signet is NOT importable).
_REPO = Path(__file__).resolve().parents[1]
_VERIFY_DIR = _REPO / "verify"
sys.path.insert(0, str(_VERIFY_DIR))
import verify as V  # noqa: E402  (verify/verify.py)

_TESTDATA = _VERIFY_DIR / "testdata"
_ANCHOR = (_TESTDATA / "anchor.txt").read_text().strip()


# ============================================================================
# KAT — the inclusion walk against known-answer vectors (no Signet involved)
# ============================================================================
def _kat_leaf(i: int) -> bytes:
    # leaf_i = SHA-256( 0x00 || single byte i ) — a fixed, documented construction.
    return hashlib.sha256(b"\x00" + bytes([i])).digest()


# Roots and audit paths generated independently from the construction in RECEIPT_FORMAT.md §2.
_KAT_ROOTS = {
    1: "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    2: "a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a",
    3: "3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688",
    4: "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb",
    5: "b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f",
}
# (tree_size, leaf_index) -> bottom-up audit path (hex)
_KAT_PATHS = {
    (3, 0): ["b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
             "fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f"],
    (3, 2): ["a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a"],
    (4, 2): ["583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d",
             "a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a"],
    (5, 0): ["b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
             "52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825",
             "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4"],
    (5, 4): ["9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb"],
}


def test_root_from_proof_known_answer_vectors():
    # single-leaf tree: root == leaf, empty path
    assert V.root_from_proof(_kat_leaf(0), 0, 1, []).hex() == _KAT_ROOTS[1]
    for (n, m), path in _KAT_PATHS.items():
        leaf = _kat_leaf(m)
        audit = [bytes.fromhex(h) for h in path]
        assert V.root_from_proof(leaf, m, n, audit).hex() == _KAT_ROOTS[n], (n, m)


def test_root_from_proof_rejects_malformed_path():
    # too many siblings for the (index, size) -> malformed, must raise, never silently pass.
    with pytest.raises(V.VerifyError) as ei:
        V.root_from_proof(_kat_leaf(0), 0, 1, [_kat_leaf(1)])
    assert ei.value.check == "inclusion"


# ============================================================================
# Golden receipts — VERIFIED
# ============================================================================
def _run(name, *extra):
    receipt = V.parse_receipt(str(_TESTDATA / name))
    return receipt


def test_golden_exfil_deny_verifies():
    receipt = _run("exfil_deny.json")
    lines = V.attest(receipt, _ANCHOR, expect_decision="DENY")
    text = "\n".join(lines)
    assert "egress → https://attacker.example/collect" in text
    assert "standing hard axis 'egress_destination' (not a learned rule" in text
    assert "no approval could move" in text


def test_golden_legit_allow_verifies_in_allow_mode():
    receipt = _run("legit_allow.json")
    lines = V.attest(receipt, _ANCHOR, expect_decision="ALLOW")
    assert any("decision:  ALLOW" in ln for ln in lines)


def test_golden_cli_exit_codes():
    # DENY golden, default mode -> exit 0
    r = subprocess.run([sys.executable, str(_VERIFY_DIR / "verify.py"),
                        str(_TESTDATA / "exfil_deny.json"), "--anchor", _ANCHOR],
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("VERIFIED")
    # DENY golden run in ALLOW mode -> decision check FAILED, exit 1
    r2 = subprocess.run([sys.executable, str(_VERIFY_DIR / "verify.py"),
                         str(_TESTDATA / "exfil_deny.json"), "--anchor", _ANCHOR, "--allow"],
                        capture_output=True, text=True)
    assert r2.returncode == 1 and "FAILED" in r2.stdout and "decision" in r2.stdout


# ============================================================================
# Tamper cases — each fails LOUD with its specific check
# ============================================================================
def _golden(name="exfil_deny.json"):
    return json.loads((_TESTDATA / name).read_text())


def _expect_fail(receipt, check, *, mode="DENY", anchor=None):
    with pytest.raises(V.VerifyError) as ei:
        V.attest(receipt, anchor if anchor is not None else _ANCHOR, expect_decision=mode)
    assert ei.value.check == check, f"expected check {check!r}, got {ei.value.check!r}"
    return ei.value


def test_tampered_destination_breaks_leaf_binding():
    r = _golden()
    r["effect"]["destination"] = "https://attacker.example/EXFIL-ELSEWHERE"
    _expect_fail(r, "leaf-binding")    # the stated effect no longer hashes to the committed leaf


def test_tampered_payload_commitment_breaks_leaf_binding():
    r = _golden()
    r["effect"]["payload_commitment"] = "sha256:" + "0" * 64
    _expect_fail(r, "leaf-binding")


def test_tampered_audit_path_breaks_inclusion():
    r = _golden()
    # flip one sibling -> recomputed root != claimed_root
    bad = list(r["inclusion_proof"]["audit_path"])
    bad[0] = "f" * 64
    r["inclusion_proof"]["audit_path"] = bad
    _expect_fail(r, "inclusion")


def test_wrong_sibling_count_breaks_inclusion():
    r = _golden()
    r["inclusion_proof"]["audit_path"] = r["inclusion_proof"]["audit_path"][:-1]
    _expect_fail(r, "inclusion")


def test_anchor_mismatch_is_equivocation():
    r = _golden()
    _expect_fail(r, "anchor", anchor="ab" * 32)


def test_missing_field_fails_loud(tmp_path):
    r = _golden()
    del r["policy_basis"]["learned_rule_id"]
    p = tmp_path / "missing.json"
    p.write_text(json.dumps(r))
    with pytest.raises(V.VerifyError) as ei:
        V.parse_receipt(str(p))
    assert ei.value.check == "structure" and "learned_rule_id" in ei.value.detail


def test_extra_field_fails_loud(tmp_path):
    r = _golden()
    r["effect"]["sneaky"] = "x"
    p = tmp_path / "extra.json"
    p.write_text(json.dumps(r))
    with pytest.raises(V.VerifyError) as ei:
        V.parse_receipt(str(p))
    assert ei.value.check == "structure"


def test_raw_payload_is_refused():
    r = _golden()
    # a value that is not a sha256 commitment (looks like raw data) -> refused at the semantic check.
    # Keep the leaf binding intact by recomputing the committed leaf for the tampered body.
    r["effect"]["payload_commitment"] = "the actual secret bytes"
    r["leaf"]["leaf_hash"] = V.recompute_leaf_hash(r).hex()
    _expect_fail(r, "payload-commitment")


# ============================================================================
# Standing-vs-learned basis (Stage 3)
# ============================================================================
def test_learned_basis_does_not_get_the_strong_attestation():
    receipt = _golden("learned_basis.json")
    lines = V.attest(receipt, _ANCHOR, expect_decision="ALLOW")
    text = "\n".join(lines)
    assert "LEARNED rule 'lr_egress_softclass'" in text
    assert "NOT the operator ceiling" in text
    # the strong operator-ceiling phrasing must NOT appear for a learned basis
    assert "no approval could move" not in text
    assert "not a learned rule" not in text


def _self_consistent(receipt):
    """Rebuild a receipt as a single-leaf tree (root == leaf) so the leaf-binding, inclusion, and
    anchor checks all pass and a LATER semantic check is what fires. Returns (receipt, anchor)."""
    leaf = V.recompute_leaf_hash(receipt).hex()
    receipt["leaf"]["leaf_hash"] = leaf
    receipt["inclusion_proof"] = {"leaf_index": 0, "tree_size": 1, "audit_path": []}
    receipt["claimed_root"] = leaf
    return receipt, leaf


def test_inconsistent_basis_standing_with_learned_id_fails():
    r = _golden()
    r["policy_basis"]["learned_rule_id"] = "lr_x"      # standing layer but a learned id set
    r, anchor = _self_consistent(r)                    # make everything before the basis check pass
    _expect_fail(r, "policy-basis", anchor=anchor)


# ============================================================================
# INDEPENDENCE — verify.py runs with Signet NOT importable
# ============================================================================
def test_verifier_runs_with_signet_not_importable(tmp_path):
    # Stage the verifier + a golden receipt in an isolated dir whose ONLY import path is itself,
    # so the repo (and therefore `signet`) is not importable. A pass here is concrete proof of
    # independence. (.github CI wiring is blocked by the fenced .github/workflows/**; this test is
    # the runnable equivalent — see the PR notes.)
    import shutil
    shutil.copy(_VERIFY_DIR / "verify.py", tmp_path / "verify.py")
    shutil.copy(_TESTDATA / "exfil_deny.json", tmp_path / "exfil_deny.json")

    # `-S` skips site processing, so the editable `pip install -e .` (which puts the repo on
    # sys.path via a .pth in site-packages) does NOT apply — signet becomes unreachable. The
    # verifier needs only the stdlib, which `-S` leaves intact.
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH",)}

    # 1. confirm `import signet` genuinely FAILS in this environment
    probe = subprocess.run([sys.executable, "-S", "-c", "import signet"],
                           cwd=str(tmp_path), env=env, capture_output=True, text=True)
    assert probe.returncode != 0 and "ModuleNotFoundError" in probe.stderr, (
        f"signet must NOT be importable for the independence test to mean anything; "
        f"stderr={probe.stderr!r}")

    # 2. the verifier nonetheless verifies the golden receipt
    r = subprocess.run([sys.executable, "-S", str(tmp_path / "verify.py"), "exfil_deny.json",
                        "--anchor", _ANCHOR],
                       cwd=str(tmp_path), env=env, capture_output=True, text=True)
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    assert r.stdout.startswith("VERIFIED")


def test_verifier_imports_no_signet_in_source():
    # static guarantee: no IMPORT statement in the verifier references Signet (prose in the
    # docstring is fine — we check actual import lines, not mentions).
    for raw in (_VERIFY_DIR / "verify.py").read_text().splitlines():
        line = raw.strip()
        if line.startswith(("import ", "from ")):
            for pkg in ("signet", "evals", "transparency", "_rail_core"):
                assert pkg not in line, f"verify.py import references {pkg!r}: {line!r}"
