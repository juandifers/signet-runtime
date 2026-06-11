"""The Signet broker — the Role-2 authorizer template exposed over a transport.

The broker is the SOLE ISSUER of the capabilities privileged actions require
(DESIGN.md P7, "the gate is the keyholder, not the command inspector"). It reuses
the unchanged kernel `Verifier` (consume-once on chain_hash, signed token) and the
unchanged `Authorizer.authorize` template (verify_token -> recheck_against_context
-> produce_capability); a rail fills only the two content hooks. Transport is a
Unix domain socket authenticated by peer credentials (the agent is a DIFFERENT OS
principal), never a bearer secret the agent could leak.
"""
