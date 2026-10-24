"""Headless-browser execution layer (1.15.0): unit + integration tests.

Everything here is hermetic: the real Playwright layer is monkeypatched with
fakes, EXCEPT one explicitly-marked smoke test that launches a real Chromium
against a local sink page and skips gracefully when no browser is available.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import quote

import pytest

from bughound import browser_exec
from bughound.browser_exec import BrowserResult
from bughound.exploits.xss import XssRun, browser_verify_run
from bughound.models import Category, ScanConfig, Severity
from bughound.modules.base import RequestTarget, ScanContext

from tests.test_xss_exploit import FakeClient, FakeLab, finding, rt_get

LAB = "https://lab0ad3f1f03a.web-security-academy.net"


def _browser_ctx(lab: FakeLab) -> ScanContext:
    from bughound.modules.base import Target as _Target

    client = FakeClient(lab.handler)
    config = ScanConfig(target_url=LAB + "/", aggressive=True, exploit=True, browser_exec=True)
    target = _Target(url=LAB + "/", scheme="https", host="lab.web-security-academy.net",
                     port=443, authorized=True)
    return ScanContext(
        client=client, config=config, target=target, base_url=LAB,
        urls=[LAB + "/"], request_targets=[], seed_html="<html><body>blog</body></html>",
    )


def _run(ctx: ScanContext, url: str = LAB + "/?search=x") -> XssRun:
    run = XssRun(ctx=ctx, finding=finding("XSS"), rt=rt_get(url, search="x"), param="search")
    from bughound.exploits.xss import Success

    run.record(Success(label="dom-flow/innerHTML", payload="<img src=1 onerror=alert(1)>",
                       client_side=True, poc_url=url))
    return run


def _fake_execute(result: BrowserResult, calls: list[str] | None = None):
    async def _execute(poc_url, needles=None, timeout_s=25.0, settle_ms=1200):
        if calls is not None:
            calls.append(poc_url)
        return result
    return _execute


# ---------------------------------------------------------------------------
# browser_verify_run plumbing
# ---------------------------------------------------------------------------


def test_browser_verify_upgrades_evidence(monkeypatch):
    ctx = _browser_ctx(FakeLab(sink="html"))
    run = _run(ctx)
    res = BrowserResult(url=run.successes[0].poc_url, ok=True,
                        dialogs=[{"type": "alert", "message": "1"}], payload_visible=True)
    monkeypatch.setattr(browser_exec, "enabled", True)
    monkeypatch.setattr(browser_exec, "execute_payload", _fake_execute(res))
    asyncio.run(browser_verify_run(run))
    assert run.browser_dialog == "alert:1"
    assert run.browser_poc == run.successes[0].poc_url
    assert any("Headless-browser execution" in e for e in run.successes[0].evidence)
    assert any("Browser-executed PoC URL" in x for x in run.extracted)
    assert "headless" in run.impact_proof


def test_browser_verify_builds_poc_url_when_missing(monkeypatch):
    ctx = _browser_ctx(FakeLab(sink="html"))
    run = _run(ctx)
    run.successes[0].poc_url = ""  # force the fallback URL construction
    calls: list[str] = []
    res = BrowserResult(url="", ok=True, dialogs=[{"type": "confirm", "message": "go"}])
    monkeypatch.setattr(browser_exec, "enabled", True)
    monkeypatch.setattr(browser_exec, "execute_payload", _fake_execute(res, calls))
    asyncio.run(browser_verify_run(run))
    assert calls and "search=%3Cimg+src%3D1+onerror%3Dalert%281%29%3E" in calls[0]
    assert run.browser_dialog == "confirm:go"


def test_browser_verify_silent_when_disabled(monkeypatch):
    ctx = _browser_ctx(FakeLab(sink="html"))
    run = _run(ctx)
    notes_before = list(run.notes)
    monkeypatch.setattr(browser_exec, "enabled", False)  # conftest default, explicit here

    def _boom(*a, **k):  # must never be reached
        raise AssertionError("execute_payload called while disabled")

    monkeypatch.setattr(browser_exec, "execute_payload", _boom)
    asyncio.run(browser_verify_run(run))
    assert run.browser_dialog == "" and run.notes == notes_before


def test_browser_verify_records_hint_when_unavailable(monkeypatch):
    ctx = _browser_ctx(FakeLab(sink="html"))
    run = _run(ctx)
    res = BrowserResult(url=run.successes[0].poc_url, ok=False,
                        error="playwright is not installed", hint=browser_exec.INSTALL_HINT)
    monkeypatch.setattr(browser_exec, "enabled", True)
    monkeypatch.setattr(browser_exec, "execute_payload", _fake_execute(res))
    asyncio.run(browser_verify_run(run))
    assert run.browser_dialog == ""
    assert run.successes[0].evidence == []  # no false execution claim
    assert any("did not run" in n and "playwright" in n for n in run.notes)


def test_browser_verify_respects_config_flag(monkeypatch):
    ctx = _browser_ctx(FakeLab(sink="html"))
    ctx.config.browser_exec = False
    run = _run(ctx)

    def _boom(*a, **k):
        raise AssertionError("execute_payload called despite browser_exec=False")

    monkeypatch.setattr(browser_exec, "enabled", True)
    monkeypatch.setattr(browser_exec, "execute_payload", _boom)
    asyncio.run(browser_verify_run(run))
    assert run.browser_dialog == ""


# ---------------------------------------------------------------------------
# exploit_xss end-to-end with a fake browser
# ---------------------------------------------------------------------------


def test_exploit_xss_end_to_end_browser_proof(monkeypatch):
    from bughound.exploits.xss import exploit_xss

    lab = FakeLab(sink="html")
    ctx = _browser_ctx(lab)
    from bughound.modules.base import RequestTarget as _RT

    target = _RT(url=LAB + "/?search=x", method="GET", params={"search": "x"}, source="query")
    ctx.request_targets = [target]
    f = finding("DOM XSS in innerHTML sink using source location.search")
    res = BrowserResult(url="", ok=True, dialogs=[{"type": "alert", "message": "1"}])
    monkeypatch.setattr(browser_exec, "enabled", True)
    monkeypatch.setattr(browser_exec, "execute_payload", _fake_execute(res))
    out = asyncio.run(exploit_xss(ctx, f, target, "search"))
    assert out.exploit_status == "succeeded"
    assert any(d.startswith("Browser execution proof") for d in out.extracted_data)
    assert "headless browser" in (out.exploit_summary or "")


# ---------------------------------------------------------------------------
# solve-phase browser strategy
# ---------------------------------------------------------------------------


ACADEMY_SEED = """
<div id="academyLabHeader"><section class='academyLabBanner'>
<h2>DOM XSS in <code>innerHTML</code> sink using source <code>location.search</code></h2>
<div class='widgetcontainer-lab-status is-notsolved'><span>LAB</span><p>Not solved</p></div>
</section></div>
"""


def _solve_ctx() -> ScanContext:
    ctx = _browser_ctx(FakeLab(sink="html"))
    ctx.seed_html = ACADEMY_SEED
    from bughound.modules.base import RequestTarget as _RT

    ctx.request_targets = [_RT(url=LAB + "/?search=", method="GET", params={"search": ""}, source="form")]
    return ctx


def test_browser_solve_strategy_flips_lab(monkeypatch):
    from bughound.objectives import SolveBudget, strategy_xss_browser_solve

    ctx = _solve_ctx()
    class _R:
        findings = []
        sorted_findings = []
    calls: list[str] = []
    res = BrowserResult(url="", ok=True, dialogs=[{"type": "alert", "message": "1"}])
    monkeypatch.setattr(browser_exec, "enabled", True)
    monkeypatch.setattr(browser_exec, "execute_payload", _fake_execute(res, calls))

    import bughound.solving as solving

    monkeypatch.setattr(solving, "check_lab_status",
                        _async(lambda ctx: {"solved": True, "title": "lab", "evidence": "is-solved"}))
    notes = asyncio.run(strategy_xss_browser_solve(
        ctx, _R(), lambda s: None, SolveBudget(max_requests=50)))
    assert calls, "strategy must browser-execute at least one candidate PoC"
    assert "flipped to solved" in notes


def test_browser_solve_strategy_disabled(monkeypatch):
    from bughound.objectives import SolveBudget, strategy_xss_browser_solve

    ctx = _solve_ctx()

    def _boom(*a, **k):
        raise AssertionError("strategy must short-circuit when disabled")

    monkeypatch.setattr(browser_exec, "execute_payload", _boom)
    notes = asyncio.run(strategy_xss_browser_solve(
        ctx, type("R", (), {"findings": [], "sorted_findings": []})(),
        lambda s: None, SolveBudget(max_requests=50)))
    assert "disabled" in notes


def test_browser_solve_strategy_unavailable_browser(monkeypatch):
    from bughound.objectives import SolveBudget, strategy_xss_browser_solve

    ctx = _solve_ctx()
    monkeypatch.setattr(browser_exec, "enabled", True)
    monkeypatch.setattr(browser_exec, "_AVAILABILITY_CACHE", (False, browser_exec.INSTALL_HINT))
    notes = asyncio.run(strategy_xss_browser_solve(
        ctx, type("R", (), {"findings": [], "sorted_findings": []})(),
        lambda s: None, SolveBudget(max_requests=50)))
    assert "unavailable" in notes


def test_ladder_includes_browser_solver():
    from bughound.objectives import STRATEGIES

    names = [s.name for s in STRATEGIES]
    assert "xss-browser-solve" in names
    xss_strats = [(i, n) for i, n in enumerate(names) if n.startswith("xss-")]
    assert any(n == "xss-browser-solve" for _, n in xss_strats)


def _async(fn):
    """Tiny helper: turn a lambda into an async callable (monkeypatch target)."""
    import types

    async def inner(*a, **k):
        return fn(*a, **k)
    return inner


# ---------------------------------------------------------------------------
# REAL browser smoke test (skipped when no Chromium is present)
# ---------------------------------------------------------------------------

SINK_PAGE = """<!DOCTYPE html>
<html><head><title>DOM XSS in innerHTML sink using source location.search</title></head>
<body>
<h1><span>0 search results for '</span><span id="searchMessage"></span><span>'</span></h1>
<script>
    function doSearchQuery(query) {{
        document.getElementById('searchMessage').innerHTML = query;
    }}
    var query = (new URLSearchParams(window.location.search)).get('search');
    if (query) {{ doSearchQuery(query); }}
</script>
</body></html>
"""


@pytest.fixture(scope="module")
def sink_http_server():
    """Local HTTP server serving the Academy innerHTML-sink page (real lab shape)."""

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(SINK_PAGE.encode())

        def log_message(self, *a):  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()


def test_real_browser_executes_sink_payload(sink_http_server, monkeypatch):
    ok, hint = browser_exec.browser_available()
    if not ok:
        pytest.skip(f"headless browser not available: {hint}")
    monkeypatch.setattr(browser_exec, "enabled", True)
    payload = "<img src=1 onerror=alert(1)>"
    poc = f"{sink_http_server}?search={quote(payload)}"
    res = asyncio.run(browser_exec.execute_payload(poc, needles=[payload]))
    assert res.ok, f"browser failed to load the page: {res.error}"
    assert res.executed, "alert(1) must fire in the headless browser"
    assert res.dialogs[0]["type"] == "alert"
    assert res.payload_visible
