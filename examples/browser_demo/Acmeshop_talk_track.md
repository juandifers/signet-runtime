# Talk track — Acme Shop

## 30-second pitch

> This is one browser agent under a **frozen, two-tier mandate**. The agent can only act inside a
> declared **ceiling**; within it, a human operator flips between pre-authorized **lanes** live — by
> voice — to widen or narrow what the agent may touch, *without restarting it*. The single
> irreversible step — **placing the order** — is left **outside the ceiling**, so no lane, no
> operator command, and no instruction the agent picks up from the page can ever reach it. Every
> decision is default-deny and leaves a signed receipt. Authority is the operator's; intent is the
> agent's; the gate keeps the two separate.

## The guarantee ledger (claim only what's true)

**STRUCTURAL — the ceiling wall (no operator, no scope, no prompt can cross it).**
- Placing the order lives at `/order-complete`, which is **absent from the ceiling**. Because the
  gate dual-checks ceiling AND active scope on *every* decision, no menu lane can include it and no
  operator phrase can switch to it. This is the demo's hard guarantee — show the REFUSED receipt.
- An operator steers *intent* but never *authority* beyond the ceiling. A steer maps to **one frozen
  menu key or `none`** — it can't invent or widen a lane.

**ADVISORY — true, but honest about the layer.**
- The browser gate is **tier-0 / advisory**: in-process, default-deny, signed receipts — the right
  shape, but not the kernel/broker boundary (that's the Role-1/Role-2/egress work in the main repo).
- `allow_unresolved` lanes let a JS-button click *land* off-path; the **current-page check** is the
  backstop — the agent can't `type`/`extract`/`click` there. Containment is on **acting**, not
  **landing**.
- `BROWSER_ALLOWED_DOMAINS` is browser-use's own belt; our gate is the enforcer of record. Both are
  in-process belts, not a network boundary.

**OUT OF SCOPE — by design.**
- A self-consistent malicious *goal* injected by the operator still only changes what the agent
  *attempts* — every action is gated — but it could trigger a wrong *in-lane* action (e.g. the wrong
  item), which the lane permits. The fix is upstream (confirmation / human-present), not more gate
  heuristics.
- **Credential entry** is the human's job; the agent is not a credential manager.
- **Prompt injection** that produces an in-ceiling action is contained to the ceiling, not
  prevented — that's the point of the wall: make the actions you can't afford *unreachable*.

## Hard questions — crisp answers

- *"Couldn't the agent just place the order anyway?"* — It can try; the gate blocks it under every
  lane (ceiling-deny) with a receipt. `/order-complete` isn't in the ceiling, so there's nothing to
  switch to. (Demo it: say "place the order".)
- *"What if the operator tells it to?"* — A steer maps only to a frozen menu key or `none`;
  `/order-complete` is in no lane, so it's REFUSED + receipted, lane unchanged.
- *"What if the page tells it to?"* — Page content can become a *goal* (intent) but not *authority*;
  the action it triggers is still gated against the active lane.
- *"Is this the real Signet enforcement?"* — This is the **advisory tier-0** browser gate (same
  default-deny + frozen-mandate + signed-receipt shape). The hard boundary is the broker / keyholder
  rails in the main repo (OS-separated principal, capability tokens, netns egress).
