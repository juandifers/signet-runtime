"""Entrypoint: `python -m examples.browser_demo.run`.

Build a frozen WebMandate -> build the guarded Tools() -> hand them to a browser-use
Agent restricted to those tools -> run a hardcoded demo task on a public site -> print
a one-line narration per step and write `session.json` (refund-triage viewer shape).

The mandate, task, start_url, and models are all hardcoded constants below, kept easy to
swap. Both the primary and fallback LLMs are full OpenAI models via `ChatOpenAI` (reads
`OPENAI_API_KEY`, loaded from the repo-root `.env`, NEVER hardcoded). We drive a LOCAL
Chrome with our guarded tools and `directly_open_url=False`, so a hosted browsing model
buys nothing here — a full model gives better tool-use reasoning.

Demo scenario (proves the spine end-to-end on a public site):
  * ALLOW   navigate -> en.wikipedia.org      (subdomain of allowlisted wikipedia.org; performs)
  * ALLOW   extract  -> en.wikipedia.org      (read the article)
  * BLOCK   navigate -> ycombinator.com       (the official-site link is off-allowlist;
                                               structured refusal, the agent re-plans, no crash)
All four action types are granted here; the action-type BLOCK (a withheld action) is
exercised deterministically in the offline self-check (see README / selfcheck.py).
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# browser-use 0.13.1 exposes these at top level. If a build doesn't, use:
#   from browser_use.llm import ChatOpenAI
from browser_use import Agent, BrowserProfile, ChatOpenAI

# Load the repo-root .env so OPENAI_API_KEY is read from there (never hardcoded).
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from .guarded_tools import build_tools
from .session import Session
from .web_mandate import WebMandate

# ---- hardcoded demo config (swap freely) --------------------------------------------------
START_URL = "https://en.wikipedia.org/wiki/Y_Combinator"
TASK = (
    f"Use `navigate` to open {START_URL}, then `extract` to read it and report the article's "
    f"title and first sentence. Then try to follow the link to Y Combinator's official "
    f"website to learn more. Report what you found, note anything you were blocked from "
    f"doing, then call `done`."
)
ALLOWED_DOMAINS = ["wikipedia.org"]                  # subdomain match covers en.wikipedia.org
ALLOWED_ACTIONS = ["navigate", "click", "type", "extract"]
# browser-use's own (belt-and-suspenders) domain guard; our gate is the advisory enforcer of record.
BROWSER_ALLOWED_DOMAINS = ["*.wikipedia.org", "https://*.wikipedia.org"]
# Full OpenAI models (NOT mini) — primary + a second full model as backup. Swap to any your key has.
MODEL = os.environ.get("SIGNET_DEMO_MODEL", "gpt-5.5")
FALLBACK_MODEL = os.environ.get("SIGNET_DEMO_FALLBACK_MODEL", "gpt-5.4")


def build_mandate() -> "WebMandate":
    return (
        WebMandate("demo-agent", task_id="browse-demo-001")
        .allow_domains(ALLOWED_DOMAINS)
        .allow_actions(ALLOWED_ACTIONS)
        .build()
    )


async def _run() -> int:
    openai_key = os.environ.get("OPENAI_API_KEY")
    if not openai_key:
        print("ERROR: OPENAI_API_KEY is not set. Set it in .env and re-run "
              "(the key is read from the environment, never hardcoded).", file=sys.stderr)
        return 2

    mandate = build_mandate()
    session = Session(mandate)
    tools = build_tools(mandate, session)

    llm = ChatOpenAI(model=MODEL, api_key=openai_key)             # full OpenAI model (primary)
    fallback = ChatOpenAI(model=FALLBACK_MODEL, api_key=openai_key)  # second full model as backup

    print(f"[signet] frozen WebMandate  domains={sorted(mandate.allowed_domains)}  "
          f"actions={sorted(mandate.allowed_actions)}  (tier 0 / advisory)")
    print(f"[signet] guarded tools: {sorted(tools.registry.registry.actions)}")

    agent = Agent(
        task=TASK,
        llm=llm,
        fallback_llm=fallback,
        tools=tools,
        browser_profile=BrowserProfile(headless=False, allowed_domains=BROWSER_ALLOWED_DOMAINS),
        # No ungated auto-navigation: the agent must reach the start URL via our guarded
        # `navigate`, so even the first hop is gated and receipted. (Agent kwarg — BrowserProfile
        # has no such field in 0.13.1.)
        directly_open_url=False,
    )

    async def snapshot(a: "Agent") -> None:
        """on_step_start: state snapshot ONLY (never enforcement, Spec 01 locked decision)."""
        try:
            step = getattr(getattr(a, "state", None), "n_steps", None)
            url = await a.browser_session.get_current_page_url()
            title = await a.browser_session.get_current_page_title()
            session.snapshot(step=step, url=url, title=title)
            print(f"[step {step}] at {url}")
        except Exception:
            pass   # snapshotting must never affect the run

    await agent.run(on_step_start=snapshot, max_steps=15)

    print("\n[signet] decisions (each backed by a signed receipt):")
    for e in session.to_dict()["effects"]:
        ok = "✓" if e["receipt_verified"] else "✗"
        print(f"  #{e['seq']:>2} {e['decision']:<5} {e['proposed']['action']:<8} "
              f"{e['proposed']['target']:<24} receipt {e['receipt_id'][:10]} {ok}  "
              f"— {e['reason']}")
    print(f"\n[signet] wrote {session.out_path}  ({len(session._effects)} decisions)")
    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
