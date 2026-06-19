"""Per-rail keyholder adapters (DESIGN.md P7/P8).

A rail makes a protected resource unreachable without a brokered, effect-bound
capability. Each rail subclasses the unchanged Role-2 authorizer template
(signet/authorizers/base.py) and fills only the two content hooks; the kernel and
the authorizer template are never edited per rail.
"""
