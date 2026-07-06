"""Measurement for Spec 05 Part 1 — the refuse-the-operator beat is LOUD in BOTH panels.

Real Chromium (skips clean if unavailable), no DNS/LLM. Builds a session containing one scope
ALLOW (a steer) and one scope BLOCK (a refusal), then asserts the refusal renders as a distinct
"OPERATOR REQUEST REFUSED" row in:
  1. the in-page overlay (inpage_panel JS, injected + pushed via CDP), and
  2. the separate-page sidebar (viewer/index.html, polling a served session.json).

Run: `python -m examples.browser_demo.selfcheck_refusal_ui`   (exit 0 = PASS or SKIP)
"""
from __future__ import annotations

import asyncio
import functools
import http.server
import socketserver
import threading
from pathlib import Path

from .inpage_panel import InPagePanel, panel_state
from .scopes import select_scope
from .session import Session
from .web_mandate import WebMandate

HERE = Path(__file__).resolve().parent


def _mandate():
    return (
        WebMandate("demo-agent", task_id="refusal-ui")
        .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "click", "extract"])
        .scope("tour",       domains=["wikipedia.org"],                    actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .scope("learn_more", domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .default_scope("tour")
        .build()
    )


def _restore(out: Path, backup) -> None:
    """Restore the committed session.json (or remove the temp one if there was none)."""
    if backup is not None:
        out.write_bytes(backup)
    else:
        out.unlink(missing_ok=True)


def _build_session(out: Path) -> Session:
    m = _mandate()
    s = Session(m, out_path=out, session_id="refusal-ui")
    select_scope(m, "show me Y Combinator's official website", session=s, use_llm=False)  # ALLOW -> learn_more
    select_scope(m, "open my online banking dashboard", session=s, use_llm=False)         # REFUSE
    return s


async def _run() -> int:
    try:
        from browser_use import BrowserProfile, BrowserSession
        from browser_use.browser.events import NavigateToUrlEvent
    except Exception as e:                                   # pragma: no cover
        print(f"SPEC-05 REFUSAL-UI SELF-CHECK: SKIP (browser-use unavailable: {e})")
        return 0

    # The sidebar polls the hardcoded "/session.json". Write the crafted session THERE, backing
    # up the committed sample and restoring it in `finally` so the real artifact is untouched.
    out = HERE / "session.json"
    backup = out.read_bytes() if out.exists() else None
    s = _build_session(out)

    # Serve the demo dir (viewer/ + the crafted session.json) over localhost.
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(HERE))
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]

    bs = BrowserSession(browser_profile=BrowserProfile(
        headless=True, allowed_domains=[f"http://127.0.0.1:{port}", "http://127.0.0.1:*"]))
    try:
        await bs.start()
    except Exception as e:                                   # pragma: no cover
        print(f"SPEC-05 REFUSAL-UI SELF-CHECK: SKIP (cannot launch browser: {e})")
        _restore(out, backup)
        return 0

    async def _innertext(expr_target="document.body") -> str:
        cdp = await bs.get_or_create_cdp_session()
        r = await cdp.cdp_client.send.Runtime.evaluate(
            params={"expression": f"({expr_target}||{{}}).innerText||''", "returnByValue": True},
            session_id=cdp.session_id)
        return (r.get("result", {}) or {}).get("value", "") or ""

    try:
        # (1) in-page overlay on a served HTML page (the dir listing at "/").
        ev = bs.event_bus.dispatch(NavigateToUrlEvent(url=f"http://127.0.0.1:{port}/"))
        await ev
        await ev.event_result(raise_if_any=True, raise_if_none=False)
        panel = InPagePanel(bs)
        await panel.install()
        await panel.push(panel_state(s))
        overlay_text = await _innertext("document.getElementById('__signet_panel__')")
        ok_overlay = "OPERATOR REQUEST REFUSED" in overlay_text

        # (2) the separate-page sidebar polling the served session.json.
        ev2 = bs.event_bus.dispatch(NavigateToUrlEvent(url=f"http://127.0.0.1:{port}/viewer/"))
        await ev2
        await ev2.event_result(raise_if_any=True, raise_if_none=False)
        await asyncio.sleep(2.0)                             # let it poll + render
        sidebar_text = await _innertext("document.body")
        ok_sidebar = "OPERATOR REQUEST REFUSED" in sidebar_text

        print("SPEC-05 REFUSAL-UI SELF-CHECK (measurement)")
        print(f"  [{'PASS' if ok_overlay else 'FAIL'}] in-page overlay shows OPERATOR REQUEST REFUSED")
        print(f"  [{'PASS' if ok_sidebar else 'FAIL'}] separate-page sidebar shows OPERATOR REQUEST REFUSED")
        ok = ok_overlay and ok_sidebar
        print(f"SPEC-05 REFUSAL-UI SELF-CHECK: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        try:
            await bs.kill()
        except Exception:
            pass
        _restore(out, backup)


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
