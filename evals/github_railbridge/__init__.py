"""GitHub rail-bridge: the first infra rail-bridge adapter for Signet.

Effect: "merge a GitHub pull request to a protected branch." Built on the §6
effect-key machinery with NO kernel edits -- the merge effect rides the payment
fields (recipient/amount/destination_account) so the unmodified verifier
context-binds it. Offline build (no live GitHub).
"""
