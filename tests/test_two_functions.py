"""CI-enforce the demo's central claim: "writing a rail is two functions."

The proof itself lives in `demos/two_functions_proof.py`, but the repo's pytest `testpaths`
is `tests/`, so a proof living under `demos/` is never auto-collected. This test pulls the
proof's `check()` into the collected suite so the structural claim can't silently regress: if
a rail starts overriding `authorize()`, grows an extra public method, or the kernel begins
importing an authorizer, this test goes red.
"""
from demos.two_functions_proof import check


def test_two_functions_claim_is_all_pass():
    results = check()
    assert results, "proof returned no checks"
    failures = [(label, detail) for label, ok, detail in results if not ok]
    assert not failures, "two-functions claim regressed:\n" + "\n".join(
        f"  - {label} -> {detail}" for label, detail in failures)
