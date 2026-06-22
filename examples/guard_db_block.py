"""The 5-minute path: guard a DB tool, drop it in a graph, watch an out-of-mandate write get BLOCKED.

Imports ONLY the blessed surface (`from signet import guard, Mandate`) — no internal modules.

    python3 -m examples.guard_db_block
"""
from typing import TypedDict

from signet import guard, Mandate


def main() -> int:
    # 1. Declare what the agent may do: only select/insert public.credits.
    mandate = (Mandate("support-bot", task_id="refund-001")
               .allow_db("public.credits", ops=("select", "insert"))
               .build())

    # 2. Your LangGraph DB tool. Its body runs only if Signet ALLOWs the effect.
    def db_write(**args):
        ...  # your real insert/update goes here

    # 3. Wrap it. No SignetConfig -> Tier 0, advisory (local-dev default; it says so when it wires).
    safe_db_write = guard(db_write, mandate)

    # 4. Drop it into a LangGraph node. An injected ticket has tricked the agent into trying a
    #    privilege escalation (UPDATE public.users SET role=admin) — outside the frozen mandate.
    from langgraph.graph import StateGraph, START, END

    class S(TypedDict, total=False):
        verdict: object

    def attempt(state):
        return {"verdict": safe_db_write(database="app", schema="public", table="users",
                                         op="update", set="role=admin")}

    g = StateGraph(S)
    g.add_node("attempt", attempt)
    g.add_edge(START, "attempt")
    g.add_edge("attempt", END)
    r = g.compile().invoke({})["verdict"]

    print(f"verdict: {r.outcome.upper()}   ({r.cause})")
    print("the privilege-escalation write was contained — no capability minted, nothing executed.")
    assert r.outcome == "block", r.outcome
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
