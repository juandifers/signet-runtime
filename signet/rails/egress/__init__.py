"""Egress credential rail — the first OS-interposition only-door (DESIGN.md P9).

Unlike the Supabase rail (a FREE only-door: Postgres/RLS enforces a scoped JWT on its own),
egress has NO external trusted enforcer of "which destination". So the broker is BOTH issuer
and enforcer, on the data path: a forward proxy admits each outbound connection only after the
unchanged authorize template re-checks the destination against the frozen mandate ∩ standing
policy, consume-once, with a receipt. The capability is consumed INLINE at admission — there is
no bearer token handed to the agent.

Adoption property (preserve it): egress requires ZERO agent code. The agent makes normal
outbound connections; the proxy (v0) or the netns (productization, EGRESS-SOLE-PATH) intercepts
them. No SDK, no client call. The boundary holds only under the declared netns deployment; in
v0 the netns is simulated and a negative test proves the proxy is advisory without it.
"""
