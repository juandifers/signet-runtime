"""In-page policy panel (Spec 04 Part 2) — the enforcement view ON the agent's own page.

Flag-gated (`SIGNET_INPAGE_PANEL=1`), OFF by default. The separate-page Spec 03 sidebar
stays and remains the fallback; this is an addition, never a replacement.

THE NON-NEGOTIABLE SAFETY CONTRACT (an overlay done wrong can break the agent):
  * Non-interactive content only — `<div>`/`<span>`/text. No `<a>`/`<button>`/`<input>`.
  * `position:fixed`, max `z-index`, `pointer-events:none`, `aria-hidden="true"`,
    `role="presentation"` — so browser-use's interactive-element indexing never assigns the
    overlay an index, and the agent can neither see nor act on it. It also must not shift the
    indices of the real interactive elements (verified by selfcheck_inpage.py — the gate).
  * Injected via CDP `Page.addScriptToEvaluateOnNewDocument` (`_cdp_add_init_script`) so it
    RE-APPLIES on every new document (survives the agent's navigations) instead of being
    re-injected by hand each step.
  * State is pushed from Python after each decision/step via `Runtime.evaluate` (set a JS
    global + re-render). The page never fetches session.json cross-origin.

This module is pure presentation. It reads nothing the gate depends on and writes nothing the
gate reads — disabling it cannot change a single decision.
"""
from __future__ import annotations

import json
import os
from typing import Optional

# The init script: defines window.__signetRender (idempotent), creates ONE fixed, inert
# container, and renders from window.__SIGNET__ (pushed by Python). Runs at document-start on
# every navigation, so it re-establishes itself after the page context resets. Colours mirror
# the Spec 03 sidebar / refund-triage viewer tokens.
_INIT_SCRIPT = r"""
(function () {
  if (window.__signetPanelInstalled) return;
  window.__signetPanelInstalled = true;
  window.__SIGNET__ = window.__SIGNET__ || null;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c];
    });
  }
  function ensureRoot() {
    var root = document.getElementById("__signet_panel__");
    if (!root) {
      root = document.createElement("div");
      root.id = "__signet_panel__";
      root.setAttribute("aria-hidden", "true");   // a11y tree skips it -> browser-use skips it
      root.setAttribute("role", "presentation");
      root.style.cssText = [
        "position:fixed", "top:12px", "right:12px", "width:300px", "max-height:88vh",
        "overflow:hidden", "z-index:2147483647", "pointer-events:none",
        "font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace",
        "color:#cdd9e5", "background:rgba(15,20,25,0.94)",
        "border:1px solid #2f81f7", "border-radius:10px", "padding:12px 13px",
        "box-shadow:0 8px 28px rgba(0,0,0,0.55)"
      ].join(";");
      // Append LAST in <body> so real interactive elements keep their DOM order / indices.
      (document.body || document.documentElement).appendChild(root);
    }
    return root;
  }
  function chip(text, bg, ink) {
    return '<span style="display:inline-block;margin:1px 3px 1px 0;padding:1px 6px;'
      + 'border-radius:5px;background:' + bg + ';color:' + ink + ';font-size:11px">'
      + esc(text) + "</span>";
  }
  window.__signetRender = function () {
    var root; try { root = ensureRoot(); } catch (e) { return; }
    var s = window.__SIGNET__;
    if (!s) { root.innerHTML = ""; return; }
    var h = "";
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'
      + '<b style="color:#2f81f7">signet · web mandate</b>'
      + chip(s.tier || "0 (advisory)", "#3a2d00", "#e3b341") + "</div>";
    h += '<div style="color:#768390;margin-bottom:2px">CEILING (locked)</div>';
    h += "<div style='margin-bottom:6px'>"
      + (s.ceiling && s.ceiling.domains || []).map(function (d) { return chip("🔒 " + d, "#1c2330", "#9da7b3"); }).join("")
      + (s.ceiling && s.ceiling.actions || []).map(function (a) { return chip(a, "#10202e", "#56a3f7"); }).join("")
      + (s.ceiling && s.ceiling.paths || []).map(function (p) { return chip(p, "#23202e", "#b39ddb"); }).join("")
      + "</div>";
    h += '<div style="color:#768390;margin-bottom:2px">SCOPES</div>';
    (s.scopes || []).forEach(function (sc) {
      var on = sc.name === s.active;
      h += '<div style="margin:2px 0;padding:3px 6px;border-radius:6px;border:1px solid '
        + (on ? "#2ea043" : "#21262d") + ";background:" + (on ? "rgba(46,160,67,0.12)" : "transparent") + '">'
        + '<span style="color:' + (on ? "#56d364" : "#768390") + '">' + (on ? "● " : "○ ") + esc(sc.name) + "</span>"
        + '<span style="color:#586069;font-size:11px"> · ' + esc((sc.domains || []).join(", ")) + "</span>"
        + '<span style="color:#8a7fb8;font-size:11px"> · ' + esc((sc.paths || []).join(" ")) + "</span></div>";
    });
    h += '<div style="color:#768390;margin:8px 0 2px">DECISIONS</div>';
    (s.decisions || []).forEach(function (d) {
      if (d.decision === "REFUSED") {
        // Loud, full-width amber beat — the operator asked and was DENIED + receipted.
        h += '<div style="margin:3px 0;padding:4px 6px;border-radius:6px;'
          + 'background:rgba(227,179,65,0.16);border:1px solid #e3b341;color:#f0c674;'
          + 'white-space:normal">⛔ <b>OPERATOR REQUEST REFUSED</b> — outside ceiling<br>'
          + '<span style="color:#d8b974">' + esc(d.target) + "</span></div>";
        return;
      }
      var c = d.decision === "ALLOW" ? ["#56d364", "✓"]
            : d.decision === "BLOCK" ? ["#ff7b72", "✗"]
            : ["#a371f7", "⇄"];
      h += '<div style="margin:2px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'
        + '<span style="color:' + c[0] + '">' + c[1] + " " + esc(d.decision) + "</span>"
        + '<span style="color:#768390"> [' + esc(d.scope) + "] " + esc(d.action) + "</span> "
        + '<span style="color:#9da7b3">' + esc(d.target) + "</span></div>";
    });
    root.innerHTML = h;
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", window.__signetRender);
  }
  // Document-start has no <body> yet; retry briefly so the panel appears once the DOM exists.
  var n = 0, iv = setInterval(function () {
    try { window.__signetRender(); } catch (e) {}
    if (++n > 24) clearInterval(iv);
  }, 250);
})();
"""


def enabled() -> bool:
    return bool(os.environ.get("SIGNET_INPAGE_PANEL"))


def panel_state(session, max_decisions: int = 7) -> dict:
    """Map the session's viewer dict -> the compact state the overlay renders."""
    d = session.to_dict()
    m = d["mandate"]
    decisions = []
    for e in d["effects"][-max_decisions:]:
        if e["rail"] == "scope":
            # A scope-rail ALLOW is a switch; a scope-rail BLOCK is an operator REFUSAL — the
            # refuse-the-operator beat (Spec 05). Show the *request* on a refusal, not "none".
            if e["decision"] == "ALLOW":
                verdict, target = "SWITCH", "→ " + str(e["proposed"]["target"])
            else:
                verdict = "REFUSED"
                target = str(e["proposed"].get("detail") or "").replace("query=", "") \
                    or str(e["proposed"]["target"])
        else:
            verdict, target = e["decision"], str(e["proposed"]["target"])
        decisions.append({
            "decision": verdict,
            "action": e["proposed"]["action"],
            "target": target,
            "scope": e.get("active_scope") or m["active"],
        })
    return {
        "tier": d["tier"],
        "ceiling": m["ceiling"],
        "scopes": m["scopes"],
        "active": m["active"],
        "decisions": decisions,
    }


class InPagePanel:
    """Installs the init script once, then pushes state to the live page each step.

    All browser interaction is best-effort and swallowed: a panel error must never surface to
    the agent or abort a step (Acceptance 2 — the run is identical with the panel on or off).
    """

    def __init__(self, browser_session) -> None:
        self._session = browser_session
        self._installed = False

    async def install(self) -> None:
        """Register the init script via CDP so it re-applies on every new document."""
        try:
            await self._session._cdp_add_init_script(_INIT_SCRIPT)
            self._installed = True
        except Exception:
            self._installed = False

    async def push(self, state: dict) -> None:
        """Set window.__SIGNET__ on the current page + re-render. No-op on any failure."""
        if not self._installed:
            return
        expr = ("window.__SIGNET__ = " + json.dumps(state) + ";"
                "if (window.__signetRender) { try { window.__signetRender(); } catch (e) {} }")
        try:
            cdp = await self._session.get_or_create_cdp_session()
            await cdp.cdp_client.send.Runtime.evaluate(
                params={"expression": expr, "returnByValue": False, "awaitPromise": False},
                session_id=cdp.session_id,
            )
        except Exception:
            pass


async def maybe_attach(browser_session) -> Optional["InPagePanel"]:
    """If the flag is on, install the panel and return it; else return None."""
    if not enabled():
        return None
    panel = InPagePanel(browser_session)
    await panel.install()
    return panel
