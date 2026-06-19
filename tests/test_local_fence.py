"""signet/fence.py — parity with the rail's MergePolicy semantics + policy.yaml validation.

The fence module is a LIFT of evals/github_railbridge/policy.py matching semantics
(prefix-before-**, case-insensitivity, backslash normalization, deny-wins, conjunctive
extra allow layers). The parity table below runs every case through BOTH implementations.
"""
import pytest

from signet.fence import (DISP_DENIED, DISP_IN_FENCE, DISP_OUT_OF_ALLOW, PathFence,
                          PolicyError, PolicyFile, matches_any, stricter)

# ---------------------------------------------------------------------------
# parity with MergePolicy._matches_any (table-driven, both implementations)
# ---------------------------------------------------------------------------
MATCH_CASES = [
    # (path, globs, expected)
    ("auth/login.py", ["auth/**"], True),
    ("auth", ["auth/**"], True),                  # prefix-before-** covers the dir itself
    ("auth/sub/deep/x.py", ["auth/**"], True),
    ("AUTH/Login.PY", ["auth/**"], True),         # case-insensitive
    ("auth\\login.py", ["auth/**"], True),        # backslash normalization
    ("authx/login.py", ["auth/**"], False),       # prefix is a path prefix, not a string prefix
    ("docs/auth/x.py", ["auth/**"], False),       # anchored at the front
    (".github/workflows/ci.yml", [".github/workflows/**"], True),
    (".github/workflowsx", [".github/workflows/**"], False),
    ("x.pem", ["*.pem"], True),
    ("deep/nested/x.pem", ["*.pem"], True),       # fnmatch * crosses "/"
    ("x.pem", ["**/*.pem"], False),               # needs a slash — why init proposes *.pem
    ("src/.env", ["**/.env*"], True),
    (".env", [".env*"], True),
    ("db/migrations/001.sql", ["db/migrations/**"], True),
    ("anything/at/all", ["**"], True),
    ("readme.md", [], False),
]


@pytest.mark.parametrize("path,globs,expected", MATCH_CASES)
def test_matches_any_table(path, globs, expected):
    assert matches_any(path, globs) is expected


def test_parity_with_merge_policy_matches_any():
    rail_policy = pytest.importorskip(
        "evals.github_railbridge.policy",
        reason="evals package not present (core-only install) — parity proven in the dev venv")
    for path, globs, expected in MATCH_CASES:
        assert rail_policy._matches_any(path, globs) == matches_any(path, globs) == expected, (
            path, globs)


def test_stricter_matches_rail_tier_order():
    assert stricter("auto", "deny") == "deny"
    assert stricter("approve", "auto") == "approve"
    assert stricter("cosign", "approve") == "cosign"
    assert stricter("deny", "cosign") == "deny"
    assert stricter("garbage", "auto") == "garbage"   # unknown treated strictest (fail closed)


# ---------------------------------------------------------------------------
# PathFence: deny-wins + conjunctive extra allow layers
# ---------------------------------------------------------------------------
def test_deny_wins_over_allow():
    f = PathFence(allow_globs=("**",), deny_globs=("auth/**",))
    assert f.disposition("auth/login.py") == DISP_DENIED
    assert f.disposition("docs/x.md") == DISP_IN_FENCE


def test_out_of_allow():
    f = PathFence(allow_globs=("docs/**",), deny_globs=("auth/**",))
    assert f.disposition("src/x.py") == DISP_OUT_OF_ALLOW
    assert f.disposition("docs/x.md") == DISP_IN_FENCE
    assert f.disposition("auth/x.py") == DISP_DENIED        # deny beats out-of-allow


def test_conjunctive_extra_allow_layers():
    # A path passes only if it matches an allow glob in EVERY layer.
    f = PathFence(allow_globs=("**",), extra_allow_layers=(("docs/**", "tests/**"), ("docs/**",)))
    assert f.disposition("docs/a.md") == DISP_IN_FENCE       # in both layers
    assert f.disposition("tests/t.py") == DISP_OUT_OF_ALLOW  # layer 1 yes, layer 2 no
    assert f.disposition("src/x.py") == DISP_OUT_OF_ALLOW    # no layer


def test_conjunctive_layers_parity_with_merge_policy():
    policy_mod = pytest.importorskip("evals.github_railbridge.policy")
    standing = policy_mod.MergePolicy(allow_paths=("**",), deny_paths=("auth/**",))
    task = policy_mod.MergePolicy(allow_paths=("docs/**", "tests/**"), deny_paths=())
    eff = standing.intersect(task)
    ours = PathFence(allow_globs=eff.allow_paths, deny_globs=eff.deny_paths,
                     extra_allow_layers=eff.extra_allow_layers)
    for p in ("docs/a.md", "tests/t.py", "src/x.py", "auth/login.py", "auth"):
        assert ours.disposition(p) == eff.path_disposition([p]), p


def test_matched_deny_glob_reports_first_firing_rule():
    f = PathFence(deny_globs=("infra/**", "auth/**"))
    assert f.matched_deny_glob("auth/x.py") == "auth/**"
    assert f.matched_deny_glob("docs/x.md") is None


# ---------------------------------------------------------------------------
# PolicyFile: schema v1 validation (unknown keys ERROR — fail closed)
# ---------------------------------------------------------------------------
def _minimal(**over):
    doc = {"version": 1, "protect": ["auth/**"]}
    doc.update(over)
    return doc


def test_policy_parse_minimal_defaults():
    p = PolicyFile.parse(_minimal())
    assert p.allow == ("**",)
    assert p.tier_protected_edit == "deny"
    assert p.tier_out_of_allow_edit == "ask"
    assert p.bash_deny == () and p.bash_ask == ()


def test_policy_unknown_top_level_key_is_an_error():
    with pytest.raises(PolicyError, match="unknown top-level keys"):
        PolicyFile.parse(_minimal(protct=["typo/**"]))


def test_policy_version_must_be_1():
    with pytest.raises(PolicyError, match="version"):
        PolicyFile.parse({"protect": ["auth/**"]})
    with pytest.raises(PolicyError, match="version"):
        PolicyFile.parse(_minimal(version=2))


def test_policy_nested_unknown_keys_and_bad_tiers_error():
    with pytest.raises(PolicyError):
        PolicyFile.parse(_minimal(bash={"deny": [], "allow": ["*"]}))   # "allow" not a bash key
    with pytest.raises(PolicyError):
        PolicyFile.parse(_minimal(tiers={"protected_edit": "allow"}))   # widening tier rejected
    with pytest.raises(PolicyError):
        PolicyFile.parse(_minimal(branches={"default": "main"}))


def test_policy_hash_binds_content():
    a = PolicyFile.parse(_minimal())
    b = PolicyFile.parse(_minimal(protect=["auth/**", "infra/**"]))
    assert a.policy_hash != b.policy_hash
    assert a.policy_hash == PolicyFile.parse(_minimal()).policy_hash   # deterministic


def test_render_round_trips_through_parse(tmp_path):
    from signet.fence import render_policy_yaml
    text = render_policy_yaml(repo="o/r", protect=["auth/**"], bash_deny=["*gh pr merge*"])
    f = tmp_path / "policy.yaml"
    f.write_text(text)
    p = PolicyFile.load(f)
    assert p.repo == "o/r" and p.protect == ("auth/**",) and p.bash_deny == ("*gh pr merge*",)
