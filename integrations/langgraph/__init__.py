"""LangGraph binding for the Signet effect gateway — the FIRST orchestrator consumer of the
seam. LangGraph is imported LAZILY (inside the functions that need it), so the deterministic
test suite + the seam itself never require it: absent `langgraph`, only the opt-in
graph/interrupt paths are unavailable, and the rest stays green (A8).
"""

from .guarded_tool import GuardedResult, signet_guarded_tool

__all__ = ["GuardedResult", "signet_guarded_tool"]
