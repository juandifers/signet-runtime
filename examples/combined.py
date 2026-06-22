"""One agent, two rails, one session — re-expressed through the on-ramp.

The same combined refund-triage run (a legitimate DB credit ALLOWED + an injected egress exfil
BLOCKED) but the door is assembled by the on-ramp from a `Mandate`, instead of hand-wired. This is
also the faithfulness check: the emitted session is identical to the hand-wired one
(`tests/test_onramp.py::test_onramp_reproduces_handwired_refund_session`).

    python3 -m examples.combined
"""
from signet import Mandate, SignetConfig
from examples.onramp import build_onramp_door
from examples.refund_triage.egress import ALLOWED_HOST
from examples.refund_triage.session import build_combined_session

CLEAN = "examples/refund_triage/scenarios/mandate.clean.json"


def main() -> int:
    # One frozen task spanning both rails: the DB grant (loaded from the scenario file) + egress.
    mandate = Mandate.from_json(CLEAN).allow_egress(ALLOWED_HOST).build()

    # Tier 0 advisory (default). The same mandate drives BOTH rails through ONE interceptor.
    door = build_onramp_door(mandate, SignetConfig())
    try:
        session = build_combined_session(door=door)
    finally:
        door.stop()

    print(f"session {session['session_id']}  tier={session['tier']}")
    for e in session["effects"]:
        p = e["proposed"]
        print(f"  {e['rail']:9} {p['action']:7} {p['target']:26} -> {e['decision']:5}"
              f"  token={str(e['token_minted']):5}  {e['reason']}")
    decisions = {e["rail"]: e["decision"] for e in session["effects"]}
    assert decisions == {"supabase": "ALLOW", "egress": "BLOCK"}, decisions
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
