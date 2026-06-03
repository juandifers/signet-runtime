"""Acceptance: the GitHub rail-bridge PRODUCTION + kernel-attack-test import path is
agentdojo-FREE. The §6 pure primitives were factored into evals/effect_core.py so the
authorizer + the merge-chain builder + the domain encoding never drag the eval/agentdojo
pipeline into their import graph. Verified in a fresh subprocess so the parent pytest
process (which may have imported agentdojo elsewhere) cannot mask a leak.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_PROBE = """\
import sys
# The exact modules the kernel attack tests + the authorizer depend on:
import evals.effect_core
import evals.github_railbridge.domain
import evals.github_railbridge.merge_chain
import evals.github_railbridge.tasks
import signet.authorizers.github_railbridge
leaked = sorted(m for m in sys.modules
                if m == "agentdojo" or m.startswith("agentdojo."))
assert not leaked, "agentdojo leaked into the production path: " + repr(leaked)
print("AGENTDOJO_FREE_OK")
"""


def test_production_import_path_is_agentdojo_free():
    proc = subprocess.run([sys.executable, "-c", _PROBE], cwd=str(REPO_ROOT),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "AGENTDOJO_FREE_OK" in proc.stdout
