"""register_rail — the LOAD GATE. A rail that fails the offline conformance battery PHYSICALLY
cannot load: the platform refuses a weak gate rather than trusting the author's claim. Red-team
(redteam.py) is adversarial DEEPENING run later; it is not a load blocker.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from evals._rail_core.policy_spec import schema_violations
from .battery import ConformanceReport, run_conformance
from .protocol import ConformanceError


def _commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return "nogit"


@dataclass
class Certification:
    rail: str
    commit: str
    certified_at: str
    last_red_team: Optional[str] = None


@dataclass
class CertifiedRail:
    """A rail that PASSED the battery. Carries the plugin, the report, and the certification record.
    Only obtainable via register_rail — so holding one is proof the gate ran and passed."""
    plugin: object
    report: ConformanceReport
    certification: Certification = field(default=None)

    @property
    def name(self) -> str:
        return self.report.rail


def _structural_contract(plugin) -> None:
    """The DECLARATIVE contract, checked BEFORE the behavioral battery: a rail MUST declare a
    non-empty CandidateSchema and a PolicySpec, and every fence/allow-list Condition must reference a
    DECLARED, OWN attribute. A Condition over an UNTRUSTED attr (or an undeclared one) is a contract
    violation — the rail cannot load. This makes the schema/policy MANDATORY TYPED DATA by
    construction (it also closes the prefilter-provenance gap: the policy can't read untrusted data)."""
    name = getattr(plugin, "name", "?")
    for meth in ("candidate_schema", "policy_spec", "project", "make_probe"):
        if not callable(getattr(plugin, meth, None)):
            raise ConformanceError(
                f"rail '{name}' is NON-CONFORMANT and cannot load: missing required declarative "
                f"method {meth!r} (schema/policy/project are MANDATORY)")
    schema = plugin.candidate_schema()
    if not schema:
        raise ConformanceError(
            f"rail '{name}' is NON-CONFORMANT and cannot load: candidate_schema() is EMPTY")
    spec = plugin.policy_spec(plugin.build_world())
    violations = schema_violations(schema, spec)
    if violations:
        raise ConformanceError(
            f"rail '{name}' is NON-CONFORMANT and cannot load: declarative-policy contract "
            f"violations: {violations}")


def register_rail(plugin) -> CertifiedRail:
    """Run the declarative contract + the offline battery synchronously; REFUSE (raise
    ConformanceError) on any failure.

    The conformance report is the single source of truth — register_rail never trusts the author's
    word, only the structural contract + the battery's verdict over the plugin's REAL pipeline."""
    _structural_contract(plugin)
    report = run_conformance(plugin)
    if not report.all_pass:
        raise ConformanceError(
            f"rail '{report.rail}' is NON-CONFORMANT and cannot load: {report.failures}")
    cert = Certification(rail=report.rail, commit=_commit(),
                         certified_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         last_red_team=None)
    return CertifiedRail(plugin=plugin, report=report, certification=cert)
