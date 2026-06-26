"""Acceptance-2 GATE for Spec 04 Part 2 — does the in-page panel leave the agent untouched?

This is a MEASUREMENT (like the netns test), not a pure offline check: it needs a real
Chromium via browser-use, but it uses a LOCAL file:// page so it needs no network/DNS and no
LLM. It skips cleanly (exit 0) if browser-use can't launch here.

It proves the two things Acceptance 2 hinges on:
  1. INDEX STABILITY — the interactive-element selector map (index -> tag+href/text) is
     BYTE-IDENTICAL before and after the overlay is installed and rendered. If the overlay
     shifted or renumbered a real element, the agent would click the wrong thing.
  2. NON-INTERACTIVE — the overlay container (#__signet_panel__) never appears in the selector
     map, i.e. browser-use never assigns it an index, so the agent can't act on it.

Run: `python -m examples.browser_demo.selfcheck_inpage`   (exit 0 = PASS or SKIP)
"""
from __future__ import annotations

import asyncio
import functools
import http.server
import socketserver
import tempfile
import threading
from pathlib import Path

from .inpage_panel import InPagePanel, panel_state
from .session import Session
from .web_mandate import WebMandate

_TEST_HTML = """<!doctype html><html><head><meta charset=utf-8><title>fixture</title></head>
<body>
  <h1>Fixture</h1>
  <a id="a1" href="https://en.wikipedia.org/wiki/Y_Combinator">YC article</a>
  <a id="a2" href="https://www.ycombinator.com/">ycombinator.com</a>
  <p>Some text with <a id="a3" href="https://example.org/more">a third link</a> inside.</p>
  <button id="b1">A button</button>
  <input id="i1" type="text" placeholder="type here">
  <a id="a4" href="https://www.google.com">google</a>
</body></html>
"""


def _fingerprint(selector_map: dict) -> list:
    """Stable (index -> tag + href/text) signature of the interactive elements."""
    out = []
    for idx in sorted(selector_map):
        node = selector_map[idx]
        attrs = getattr(node, "attributes", {}) or {}
        out.append((idx, node.tag_name, attrs.get("href") or attrs.get("id") or ""))
    return out


def _mandate():
    return (
        WebMandate("demo-agent", task_id="inpage-selfcheck")
        .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "click", "extract"])
        .scope("tour",       domains=["wikipedia.org"],                    actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .scope("learn_more", domains=["wikipedia.org", "ycombinator.com"], actions=["navigate", "extract", "click"], click_policy="in_domain_only")
        .default_scope("tour")
        .build()
    )


async def _run() -> int:
    try:
        from browser_use import BrowserProfile, BrowserSession
    except Exception as e:                           # pragma: no cover
        print(f"SPEC-04 PART-2 SELF-CHECK: SKIP (browser-use unavailable: {e})")
        return 0

    out = Path(__file__).resolve().parent / "_selfcheck_inpage.session.json"
    session = Session(_mandate(), out_path=out, session_id="inpage-selfcheck")

    with tempfile.TemporaryDirectory() as td:
        fixture = Path(td) / "fixture.html"
        fixture.write_text(_TEST_HTML)
        # Serve over localhost http (the security watchdog blocks file://); no DNS needed.
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=td)
        httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        url = f"http://127.0.0.1:{port}/fixture.html"

        bs = BrowserSession(browser_profile=BrowserProfile(
            headless=True, allowed_domains=[f"http://127.0.0.1:{port}", "http://127.0.0.1:*"]))
        try:
            await bs.start()
        except Exception as e:                       # pragma: no cover
            print(f"SPEC-04 PART-2 SELF-CHECK: SKIP (cannot launch browser: {e})")
            out.unlink(missing_ok=True)
            return 0
        try:
            from browser_use.browser.events import NavigateToUrlEvent
            ev = bs.event_bus.dispatch(NavigateToUrlEvent(url=url))
            await ev
            await ev.event_result(raise_if_any=True, raise_if_none=False)

            await bs.get_browser_state_summary(include_screenshot=False)   # build the DOM first
            before = _fingerprint(await bs.get_selector_map())

            panel = InPagePanel(bs)
            await panel.install()
            await panel.push(panel_state(session))
            # Force a fresh DOM build so any overlay-induced shift WOULD show up.
            await bs.get_browser_state_summary(include_screenshot=False)
            after_map = await bs.get_selector_map()
            after = _fingerprint(after_map)

            ok_installed = panel._installed
            ok_indices = before == after
            ids = {(getattr(n, "attributes", {}) or {}).get("id") for n in after_map.values()}
            ok_noninteractive = "__signet_panel__" not in ids

            # The overlay must also actually PAINT (exists in the DOM with rendered content).
            cdp = await bs.get_or_create_cdp_session()
            r = await cdp.cdp_client.send.Runtime.evaluate(
                params={"expression":
                        "(function(){var e=document.getElementById('__signet_panel__');"
                        "return e?e.innerText:'';})()",
                        "returnByValue": True},
                session_id=cdp.session_id)
            panel_text = (r.get("result", {}) or {}).get("value", "") or ""
            ok_rendered = ("CEILING" in panel_text and "SCOPES" in panel_text
                           and "DECISIONS" in panel_text)

            print("SPEC-04 PART-2 SELF-CHECK (measurement)")
            print(f"  [{'PASS' if ok_installed else 'FAIL'}] init script installed via CDP")
            print(f"  [{'PASS' if ok_indices else 'FAIL'}] interactive indices identical with panel on")
            if not ok_indices:
                print(f"      before={before}\n      after ={after}")
            print(f"  [{'PASS' if ok_noninteractive else 'FAIL'}] overlay NOT in selector map (non-interactive)")
            print(f"  [{'PASS' if ok_rendered else 'FAIL'}] overlay paints policy content (CEILING/SCOPES/DECISIONS)")
            print(f"  (interactive elements indexed: {len(after)})")
            ok = ok_installed and ok_indices and ok_noninteractive and ok_rendered
            print(f"SPEC-04 PART-2 SELF-CHECK: {'PASS' if ok else 'FAIL'}")
            return 0 if ok else 1
        finally:
            try:
                await bs.kill()
            except Exception:
                pass
            out.unlink(missing_ok=True)


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
