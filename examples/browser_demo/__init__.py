"""Spec 01 — Guarded browser spine.

A `browser-use` agent whose only path to a web effect is a set of custom guarded
tools. Every proposed action passes through a frozen, default-deny `WebMandate`
before any effect runs; allowed actions perform, disallowed ones return a
structured refusal the model can re-plan around; every decision writes a real
(research-grade Ed25519) signet receipt; the run emits a `session.json` in the
existing refund-triage viewer shape.

HONESTY (mirrors the egress rail): enforcement here is **in-process / advisory**.
The structural upgrade is an out-of-process performer that is the *sole path* to
the browser (the netns analogue). Until that exists, a determined in-process agent
could reach the browser by other means; the gate is containment UX + tamper-evident
receipts, not the enforcement boundary. Every decision is labelled `advisory`.
"""
