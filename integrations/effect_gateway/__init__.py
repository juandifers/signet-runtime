"""The orchestrator-agnostic effect gateway — the control-plane primitive.

`seam.py` holds `EffectInterceptor` + `ProposedEffect` / `Decision` / `Outcome` and the
`RailBinding` protocol. `rails_github.py` binds the EXISTING GitHub merge pipeline to the
seam (a thin wrapper over `resolve_task_mandate` + `authorize_closed_mandate`; no rail-logic
rewrite). Nothing here imports LangGraph or any other orchestrator: an agent's proposal
becomes, at most, a Role-B candidate pick, and containment is the rail pipeline — never the
proposal.
"""

from .seam import Decision, EffectInterceptor, Outcome, ProposedEffect, RailBinding

__all__ = ["Decision", "EffectInterceptor", "Outcome", "ProposedEffect", "RailBinding"]
