"""The local path/command fence + .signet/policy.yaml loader (Stage 1 product surface).

Self-contained: stdlib + yaml + signet.canonical ONLY. No evals imports — this module sits
on the `signet hook` execution path, which is deterministic, offline, and LLM-free
(GATE-PURITY invariant).

The matching semantics are LIFTED VERBATIM from evals/github_railbridge/policy.py
(`MergePolicy._matches_any`, `stricter`, the conjunctive `extra_allow_layers` rule and the
deny-wins disposition) so the local fence and the server-side rail agree on what a glob
means. tests/test_fence.py proves the parity table against the original.

HONESTY (DESIGN.md P2): this fence is the *client-side* layer — containment UX and
tamper-evidence, never the enforcement boundary. The boundary is the server-side rail.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .canonical import hash_obj

# ---- tiers (verbatim vocabulary from the GitHub rail policy) ----
TIER_AUTO = "auto"        # proceed without a Signet opinion (normal permission flow)
TIER_APPROVE = "approve"  # a human must approve (hook: permissionDecision "ask")
TIER_COSIGN = "cosign"    # a second signer must co-sign (hook: also "ask" — Stage 1 has no co-signer)
TIER_DENY = "deny"        # never (hook: permissionDecision "deny")
_TIER_ORDER = {TIER_AUTO: 0, TIER_APPROVE: 1, TIER_COSIGN: 2, TIER_DENY: 3}
TIERS = (TIER_AUTO, TIER_APPROVE, TIER_COSIGN, TIER_DENY)


def stricter(a: str, b: str) -> str:
    """The more restrictive of two tiers (higher in the order). Unknown -> treated strictest."""
    return a if _TIER_ORDER.get(a, 99) >= _TIER_ORDER.get(b, 99) else b


def matches_any(path: str, globs) -> bool:
    """IDENTICAL semantics to MergePolicy._matches_any: backslash-normalized, case-insensitive;
    a glob with a `**` gets its literal prefix matched as a directory prefix BEFORE fnmatch
    (so "auth/**" covers "auth" itself and everything under it); otherwise plain fnmatch."""
    p = str(path).replace("\\", "/").lower()
    for g in globs:
        gl = str(g).lower()
        prefix = gl.split("**", 1)[0].rstrip("/")
        if prefix and (p == prefix or p.startswith(prefix + "/")):
            return True
        if fnmatch.fnmatch(p, gl):
            return True
    return False


# ---- dispositions ----
DISP_DENIED = "denied"
DISP_OUT_OF_ALLOW = "out-of-allow"
DISP_IN_FENCE = "in-fence"


@dataclass(frozen=True)
class PathFence:
    """A frozen path fence with the rail's exact layering semantics.

    Deny wins over allow. A path is allowed only if it matches an allow glob AND matches an
    allow glob in EVERY extra layer (conjunctive narrowing — a layer can only shrink the
    fence, never grow it: LOCAL-MONOTONIC)."""
    allow_globs: tuple = ("**",)
    deny_globs: tuple = ()
    extra_allow_layers: tuple = field(default=())

    def _allowed(self, path: str) -> bool:
        if not matches_any(path, self.allow_globs):
            return False
        return all(matches_any(path, layer) for layer in self.extra_allow_layers)

    def _denied(self, path: str) -> bool:
        return matches_any(path, self.deny_globs)

    def disposition(self, path: str) -> str:
        if self._denied(path):
            return DISP_DENIED
        if not self._allowed(path):
            return DISP_OUT_OF_ALLOW
        return DISP_IN_FENCE

    def matched_deny_glob(self, path: str) -> Optional[str]:
        """The first deny glob that fires for `path` (for the receipt/reason), or None."""
        for g in self.deny_globs:
            if matches_any(path, (g,)):
                return g
        return None


# ============================================================================
# .signet/policy.yaml — schema v1
# ============================================================================
class PolicyError(ValueError):
    """The policy file is missing/invalid. The hook FAILS CLOSED toward the human (ask)."""


POLICY_RELPATH = Path(".signet") / "policy.yaml"

_TOP_KEYS = {"version", "repo", "protect", "allow", "branches", "bash", "tiers"}
_BRANCH_KEYS = {"protected"}
_BASH_KEYS = {"deny", "ask"}
_TIER_KEYS = {"protected_edit", "out_of_allow_edit"}
_EDIT_TIER_VALUES = ("deny", "ask")


def _str_list(value: Any, where: str) -> tuple:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise PolicyError(f"{where} must be a list of strings, got {value!r}")
    return tuple(value)


@dataclass(frozen=True)
class PolicyFile:
    """The parsed, validated .signet/policy.yaml plus its binding hash.

    `policy_hash` is sha256 of the canonical_json of the PARSED document — every local
    receipt carries it, binding WHICH policy made each decision (LOCAL-RECEIPT)."""
    version: int
    repo: Optional[str]
    protect: tuple
    allow: tuple
    protected_branches: tuple
    bash_deny: tuple
    bash_ask: tuple
    tier_protected_edit: str       # "deny" | "ask"
    tier_out_of_allow_edit: str    # "deny" | "ask"
    policy_hash: str

    @property
    def fence(self) -> PathFence:
        return PathFence(allow_globs=self.allow, deny_globs=self.protect)

    @staticmethod
    def parse(data: Any) -> "PolicyFile":
        if not isinstance(data, dict):
            raise PolicyError(f"policy.yaml must be a mapping, got {type(data).__name__}")
        unknown = set(data) - _TOP_KEYS
        if unknown:
            # Unknown keys are an ERROR, not a warning: a typo'd "protct:" silently
            # ignored would be a fail-open fence.
            raise PolicyError(f"unknown top-level keys {sorted(unknown)} "
                              f"(allowed: {sorted(_TOP_KEYS)})")
        if data.get("version") != 1:
            raise PolicyError(f"version must be 1, got {data.get('version')!r}")
        repo = data.get("repo")
        if repo is not None and not isinstance(repo, str):
            raise PolicyError(f"repo must be a string, got {repo!r}")

        branches = data.get("branches") or {}
        if not isinstance(branches, dict) or set(branches) - _BRANCH_KEYS:
            raise PolicyError(f"branches accepts only {sorted(_BRANCH_KEYS)}, got {branches!r}")
        bash = data.get("bash") or {}
        if not isinstance(bash, dict) or set(bash) - _BASH_KEYS:
            raise PolicyError(f"bash accepts only {sorted(_BASH_KEYS)}, got {bash!r}")
        tiers = data.get("tiers") or {}
        if not isinstance(tiers, dict) or set(tiers) - _TIER_KEYS:
            raise PolicyError(f"tiers accepts only {sorted(_TIER_KEYS)}, got {tiers!r}")
        tier_protected = tiers.get("protected_edit", "deny")
        tier_out = tiers.get("out_of_allow_edit", "ask")
        for name, val in (("protected_edit", tier_protected), ("out_of_allow_edit", tier_out)):
            if val not in _EDIT_TIER_VALUES:
                raise PolicyError(f"tiers.{name} must be one of {_EDIT_TIER_VALUES}, got {val!r}")

        return PolicyFile(
            version=1,
            repo=repo,
            protect=_str_list(data.get("protect"), "protect"),
            allow=_str_list(data.get("allow"), "allow") or ("**",),
            protected_branches=_str_list(branches.get("protected"), "branches.protected"),
            bash_deny=_str_list(bash.get("deny"), "bash.deny"),
            bash_ask=_str_list(bash.get("ask"), "bash.ask"),
            tier_protected_edit=tier_protected,
            tier_out_of_allow_edit=tier_out,
            policy_hash=hash_obj(data),
        )

    @staticmethod
    def load(path: Path) -> "PolicyFile":
        import yaml  # lazy: keeps `import signet.fence` light for non-policy callers
        try:
            text = Path(path).read_text()
        except OSError as e:
            raise PolicyError(f"cannot read {path}: {e}") from e
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise PolicyError(f"invalid YAML in {path}: {e}") from e
        return PolicyFile.parse(data)


def render_policy_yaml(*, repo: Optional[str], protect, allow=("**",),
                       protected_branches=("main",), bash_deny=(), bash_ask=(),
                       tier_protected_edit: str = "deny",
                       tier_out_of_allow_edit: str = "ask") -> str:
    """Render a schema-v1 policy.yaml (used by `signet init`; round-trips through parse())."""
    import yaml
    doc: Dict[str, Any] = {"version": 1}
    if repo:
        doc["repo"] = repo
    doc["protect"] = list(protect)
    doc["allow"] = list(allow)
    doc["branches"] = {"protected": list(protected_branches)}
    doc["bash"] = {"deny": list(bash_deny), "ask": list(bash_ask)}
    doc["tiers"] = {"protected_edit": tier_protected_edit,
                    "out_of_allow_edit": tier_out_of_allow_edit}
    header = (
        "# .signet/policy.yaml — local containment fence for coding agents (schema v1).\n"
        "# Evaluated by `signet hook` (a Claude Code PreToolUse hook): deterministic, offline,\n"
        "# no LLM. This local gate is containment UX + tamper-evident receipts — it is NOT the\n"
        "# enforcement boundary; the server-side rail (Stage 3) is. `signet explain <path>`\n"
        "# shows exactly which rule fires.\n"
    )
    return header + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
