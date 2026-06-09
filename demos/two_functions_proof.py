"""Proof: "writing a rail is two functions."

This makes the demo's central claim machine-checkable. It asserts, for every credential-custody
(Role-2) rail bridge, that:

  1. the base template exposes exactly TWO abstract hooks a rail must fill —
     `recheck_against_context` and `produce_capability`;
  2. each rail implements exactly those two (plus, optionally, the no-op-by-default `on_rejected`);
  3. NO rail overrides `authorize()` — the order, the token check, and fail-closed live in the
     kernel template, not in the rail;
  4. the kernel (`signet.verifier` + the other kernel modules) imports NO authorizer — the
     dependency points rail -> kernel, never kernel -> rail, so the kernel is rail-agnostic by
     construction.

The cosigner rails (xrpl, mpc) deliberately override `authorize` to raise (their real path is
`cosign(...)`, a different signature) — that's the documented exception, reported separately.

Run:    python -m demos.two_functions_proof
Or as a test:  pytest demos/two_functions_proof.py
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from signet.authorizers.base import Authorizer
from signet.authorizers.mock_broker import MockCredentialBroker
from signet.authorizers.github_railbridge import GitHubRailBridge
from signet.authorizers.deploy_railbridge import DeployRailBridge
from signet.authorizers.infra_railbridge import InfraRailBridge

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_HOOKS = {"recheck_against_context", "produce_capability"}
OPTIONAL_HOOKS = {"on_rejected"}

# The Role-2 (credential-custody) rails the claim is about.
ROLE2_RAILS = [MockCredentialBroker, GitHubRailBridge, DeployRailBridge, InfraRailBridge]

# Kernel modules that must never import a rail (the rail-agnostic invariant).
KERNEL_MODULES = ["verifier", "chain", "policy", "nonce", "models", "crypto",
                  "canonical", "revocation", "builder"]


def _base_abstract_hooks() -> set:
    return {n for n in vars(Authorizer)
            if getattr(getattr(Authorizer, n), "__isabstractmethod__", False)}


def _own_methods(cls) -> set:
    """Methods defined ON the class itself (not inherited)."""
    return {n for n, v in vars(cls).items() if callable(v) and not n.startswith("__")}


def _kernel_imports_any_authorizer():
    """Static check: no kernel module's source mentions `authorizers` in an import."""
    offenders = []
    for mod in KERNEL_MODULES:
        path = ROOT / "signet" / f"{mod}.py"
        if not path.exists():
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "authorizers" in node.module:
                offenders.append((mod, node.module))
            if isinstance(node, ast.Import):
                for a in node.names:
                    if "authorizers" in a.name:
                        offenders.append((mod, a.name))
    return offenders


def check():
    results = []
    base_hooks = _base_abstract_hooks()
    results.append(("base template exposes exactly the two hooks",
                    base_hooks == REQUIRED_HOOKS, sorted(base_hooks)))

    for cls in ROLE2_RAILS:
        own = _own_methods(cls)
        impl_required = own & REQUIRED_HOOKS
        # the rail's own callables minus the two hooks, the optional hook, and private helpers
        extras = {n for n in own
                  if n not in REQUIRED_HOOKS and n not in OPTIONAL_HOOKS and not n.startswith("_")}
        overrides_authorize = "authorize" in vars(cls)
        ok = (impl_required == REQUIRED_HOOKS
              and not overrides_authorize
              and not extras)
        detail = (f"hooks={sorted(impl_required)} "
                  f"on_rejected={'yes' if 'on_rejected' in own else 'no'} "
                  f"overrides_authorize={overrides_authorize} "
                  f"extra_public_methods={sorted(extras) or 'none'}")
        results.append((f"{cls.__name__} is exactly the two hooks over the template", ok, detail))

    offenders = _kernel_imports_any_authorizer()
    results.append(("kernel imports no authorizer (rail -> kernel, never the reverse)",
                    not offenders, offenders or "clean"))
    return results


def main() -> int:
    print("PROOF — writing a rail is two functions\n" + "=" * 52)
    results = check()
    allok = True
    for label, ok, detail in results:
        allok = allok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        print(f"         {detail}")
    print("=" * 52)
    print("RESULT:", "PROVEN — every Role-2 rail is two hooks; the kernel stays rail-agnostic."
          if allok else "FAILED — the claim does not hold; see the lines above.")
    # Note the documented exception so the report is honest.
    print("\nNote: the cosigner rails (XRPLCosigner, MPCThresholdCosigner) deliberately override\n"
          "authorize() to raise — their real path is cosign(tx, agent_signed, token, req), a\n"
          "different signature. That is the one documented exception to the template.")
    return 0 if allok else 1


# --- pytest entry points ---
def test_two_functions_claim_holds():
    for label, ok, detail in check():
        assert ok, f"{label} -> {detail}"


if __name__ == "__main__":
    raise SystemExit(main())