"""Signet orchestrator adapters — the framework-agnostic control plane.

This package sits ABOVE the rails. A rail (merge / deploy / infra) is one irreversible
EFFECT TYPE with its own authorizer + declarative fence. An orchestrator (LangGraph, the
Claude Code hook, CrewAI, ...) DRIVES rails: it proposes effects. These adapters intercept
a proposed effect from an agent runtime and route it through the EXISTING rail pipeline —
they only IMPORT the kernel (`signet/`) and the rail bridges; they never edit the kernel.
"""
