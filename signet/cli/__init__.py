"""The `signet` CLI — Stage 1 product surface (local gate + receipts + onboarding).

Everything here is the CLIENT-SIDE layer (DESIGN.md P2): containment UX and tamper-EVIDENT
local receipts, never the enforcement boundary. The server-side rail is the boundary.
Modules on the `signet hook` execution path import NOTHING from evals/ and make no
network or LLM calls (GATE-PURITY).
"""
