"""Plugin-safety machine — generalizes the scorecard's behavioral invariants from "our two rails"
to "any rail plugin."

  protocol.py   the RailPlugin handle (the SDK's seed) + Verdict / probes / ConformanceError
  rails.py      thin adapters proving github + deploy already satisfy the handle
  battery.py    run_conformance(plugin) -> ConformanceReport (OFFLINE; the load gate)
  register.py   register_rail(plugin) — REFUSES any rail that fails the battery
  redteam.py    adaptive adversarial deepening (LIVE; breakout_rate must be 0)

A non-conformant rail PHYSICALLY cannot load: the platform refuses a weak gate rather than trusting
the author. Red-team is deepening, not a load blocker.
"""
from .protocol import (ConformanceError, DeclarativeRailPlugin, EffectKeyProbe, RailPlugin,
                       TokenProbe, Verdict)
from .battery import ConformanceReport, run_conformance
from .register import CertifiedRail, register_rail

__all__ = ["RailPlugin", "DeclarativeRailPlugin", "Verdict", "EffectKeyProbe", "TokenProbe",
           "ConformanceError", "run_conformance", "ConformanceReport", "register_rail",
           "CertifiedRail"]
