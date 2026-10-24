"""1.18.0 lab-solve tests: exploit-server victim delivery (hashchange family).

Pins the three real bugs that made the agent unable to solve the
"DOM XSS in jQuery selector sink using a hashchange event" lab while the
manual chat playbook succeeded:

1. store_body/deliver_to_victim posted the human labels ("Store" /
   "Deliver to victim") instead of the canonical button values the live
   form submits (STORE / DELIVER_TO_VICTIM) -- a silent 200 no-op.
2. discover_exploit_server rejected the lab page's own off-origin link and
   fell back to the constructed exploit-<lab-id> name -- which current
   Academy instances do NOT answer (the exploit host carries a DIFFERENT
   lab id; the wrong name answers HTTP 421).
3. No strategy existed for the victim-delivery lab family, so the ladder
   fired reflected-XSS payloads at query params that can never solve it.

Offline tests reuse the FakeClient pattern (no network, no browser).
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager

import pytest

from bughound.http_client import Response
from bughound.models import ScanConfig, Category, Finding, Severity, ScanResult
from bughound.modules.base import ScanContext, Target

LAB = "https://0aa6002c048d221481d9e8d300da002d.web-security-academy.net"
EXPLOIT = "https://exploit-0afc000504df220f81efe7ae013a0009.exploit-server.net"

SEED = (
    "<html><head><title>DOM XSS in jQuery selector sink using a hashchange event</title></head>"
    "<body><div id='academyLabHeader'><div class=title-container>"
    "<h2>DOM XSS in jQuery selector sink using a hashchange event</h2></div>"
    "<div class='widgetcontainer-lab-status is-notsolved'><p>Not solved</p></div></div>"
    "<a href='" + EXPLOIT + "'>Go to exploit server</a>"
    "</body></html>"
)


def _ctx(seed_html=SEED, handler=None):
    from tests.test_xss_exploit import FakeClient

    config = ScanConfig(target_url=LAB + "/", exploit=True)
    target = Target(url=LAB + "/", scheme="https",
                    host="0aa6002c048d221481d9e8d300da002d.web-security-academy.net",
                    port=443, authorized=True)
    return ScanContext(
        client=FakeClient(handler or (lambda m, u, p, d, headers=None: _page(200, False))),
        config=config, target=target, base_url=LAB + "/", seed_html=seed_html,
    )


def _page(status, solved, url=LAB + "/"):
    cls = "is-solved" if solved else "is-notsolved"
    txt = "Solved" if solved else "Not solved"
    return Response(
        url=url, status=status, headers={}, elapsed=0.01,
        text=(
            "<html><head><title>DOM XSS in jQuery selector sink using a hashchange event</title></head>"
            "<body><div id='academyLabHeader'><div class=title-container>"
            "<h2>DOM XSS in jQuery selector sink using a hashchange event</h2></div>"
            f"<div class='widgetcontainer-lab-status {cls}'><p>{txt}</p></div></div>"
            "</body></html>"
        ),
    )


def _no_sleep(monkeypatch):
    async def _instant(_s):
        return None
    monkeypatch.setattr(asyncio, "sleep", _instant)


# ---------------------------------------------------------------------------
# Bug 1: canonical formAction values
# ---------------------------------------------------------------------------


def _ok(url):
    return Response(url=url, status=200, headers={}, text="ok", elapsed=0.01)


@pytest.mark.asyncio
async def test_store_body_posts_canonical_store_value():
    from bughound.exploits.xss_platform import ExploitServer, store_body

    posts = []

    def handler(method, url, params, data, headers=None):
        posts.append(data)
        return _ok(url)

    ctx = _ctx(handler=handler)
    ok = await store_body(ctx, ExploitServer(EXPLOIT), "<iframe></iframe>")
    assert ok
    assert posts and posts[0]["formAction"] == "STORE", (
        "the live form submits STORE via its button value; posting the human "
        "label 'Store' is accepted as an ordinary render -- a silent no-op"
    )


@pytest.mark.asyncio
async def test_deliver_to_victim_posts_canonical_deliver_value():
    from bughound.exploits.xss_platform import ExploitServer, deliver_to_victim

    posts = []

    def handler(method, url, params, data, headers=None):
        posts.append(data)
        return _ok(url)

    ctx = _ctx(handler=handler)
    ok = await deliver_to_victim(ctx, ExploitServer(EXPLOIT), body="<x>")
    assert ok
    assert posts and posts[0]["formAction"] == "DELIVER_TO_VICTIM"


@pytest.mark.asyncio
async def test_deliver_to_victim_carries_body():
    from bughound.exploits.xss_platform import ExploitServer, deliver_to_victim

    posts = []

    def handler(method, url, params, data, headers=None):
        posts.append(data)
        return _ok(url)

    ctx = _ctx(handler=handler)
    await deliver_to_victim(ctx, ExploitServer(EXPLOIT), body="<iframe src='x/#'></iframe>")
    assert "iframe" in (posts[0].get("responseBody") or "")


# ---------------------------------------------------------------------------
# Bug 1b: verify_exploit_server (probe, signature-safe)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_accepts_form_page():
    from bughound.exploits.xss_platform import verify_exploit_server

    def handler(method, url, params, data, headers=None):
        return Response(url=url, status=200, headers={}, elapsed=0.01,
                        text="<form><button name='formAction' value='STORE'></form>")

    assert await verify_exploit_server(_ctx(handler=handler), EXPLOIT) is True


@pytest.mark.asyncio
async def test_verify_rejects_421_and_errors():
    from bughound.exploits.xss_platform import verify_exploit_server

    def gone(method, url, params, data, headers=None):
        return Response(url=url, status=421, headers={}, text="", elapsed=0.01)

    async def boom(url, **kw):
        raise RuntimeError("no route")

    ctx = _ctx(handler=gone)
    assert await verify_exploit_server(ctx, EXPLOIT) is False
    ctx.client = type("B", (), {"get": staticmethod(boom)})()
    assert await verify_exploit_server(ctx, EXPLOIT) is False


# ---------------------------------------------------------------------------
# Bug 2: the lab page's off-origin exploit link wins over the constructed name
# ---------------------------------------------------------------------------


def test_candidates_scrape_off_origin_link_first():
    from bughound.objectives import _exploit_server_candidates

    cands = _exploit_server_candidates(_ctx())
    assert cands, "seed page carries the exploit link"
    assert cands[0] == EXPLOIT, (
        "the lab page's own 'Go to exploit server' link (off-origin, DIFFERENT "
        "lab id) must be the first candidate"
    )


def test_candidates_constructed_name_is_last():
    from bughound.objectives import _exploit_server_candidates

    cands = _exploit_server_candidates(_ctx(seed_html="<html><body>no links</body></html>"))
    assert cands, "naming-convention fallback must still exist"
    # legacy convention: exploit-<lab-id> under the lab's own parent domain
    # (WRONG on current instances -- the probe in resolve_exploit_server
    # rejects it, which is why it stays LAST)
    assert cands[-1] == "https://exploit-0aa6002c048d221481d9e8d300da002d.web-security-academy.net"


def test_discover_prefers_scraped_link():
    from bughound.objectives import discover_exploit_server

    assert discover_exploit_server(_ctx()) == EXPLOIT


# ---------------------------------------------------------------------------
# Bug 3: the ladder solves the hashchange family through victim delivery
# ---------------------------------------------------------------------------


def test_ladder_ranks_delivery_first_for_hashchange_lab():
    from bughound.objectives import build_ladder

    ladder = build_ladder(
        "DOM XSS in jQuery selector sink using a hashchange event", None)
    assert ladder[0].name == "xss-exploit-server-deliver"


def test_ladder_keeps_local_playbooks_first_for_reflected_labs():
    from bughound.objectives import build_ladder

    ladder = build_ladder("Reflected XSS into HTML context with nothing encoded", None)
    names = [s.name for s in ladder]
    assert names.index("xss-class-playbooks") < names.index("xss-exploit-server-deliver")


def _solve_handler(state):
    """Fake lab + exploit server implementing the documented semantics."""

    def handler(method, url, params, data, headers=None):
        if url.startswith(EXPLOIT):
            if method == "GET":
                return Response(url=url, status=200, headers={}, elapsed=0.01,
                                text="<form><button name='formAction' value='STORE'>")
            action = (data or {}).get("formAction", "")
            if action == "STORE":
                state["stored"] = (data or {}).get("responseBody", "")
            elif action == "DELIVER_TO_VICTIM":
                body = state.get("stored") or ""
                # the victim bot renders the stored page; emulate the
                # iframe hash-append + jQuery 1.8 sink + print() condition
                if "iframe" in body and "onerror=print(1)" in body:
                    state["solved"] = True
            return _ok(url)
        # lab pages
        return _page(200, state.get("solved", False))

    return handler


@pytest.mark.asyncio
async def test_delivery_strategy_solves_hashchange_lab(monkeypatch):
    from bughound.objectives import SolveBudget, strategy_xss_exploit_deliver

    _no_sleep(monkeypatch)
    state = {"solved": False}
    ctx = _ctx(handler=_solve_handler(state))
    budget = SolveBudget(max_requests=80)
    notes: list[str] = []

    def emit(msg):
        notes.append(msg)

    result = await strategy_xss_exploit_deliver(ctx, None, emit, budget)
    assert "SOLVED" in result, f"strategy must solve the lab, got: {result}"
    assert state["solved"], "the fake victim bot must have executed print(1)"
    # the stored exploit page is the documented iframe hash-append shape
    assert '<iframe src="' + LAB + '/#"' in state["stored"]
    assert "onload" in state["stored"] and "onerror=print(1)" in state["stored"]


@pytest.mark.asyncio
async def test_delivery_strategy_alternates_to_alert(monkeypatch):
    """A lab whose solve condition is alert(): print() round fails, the
    alternate-function redelivery completes the objective."""
    from bughound.objectives import SolveBudget, strategy_xss_exploit_deliver

    _no_sleep(monkeypatch)
    state = {"solved": False}

    def handler(method, url, params, data, headers=None):
        if url.startswith(EXPLOIT):
            if method == "GET":
                return Response(url=url, status=200, headers={}, elapsed=0.01,
                                text="<form><button name='formAction' value='STORE'>")
            action = (data or {}).get("formAction", "")
            if action == "STORE":
                state["stored"] = (data or {}).get("responseBody", "")
            elif action == "DELIVER_TO_VICTIM":
                if "onerror=alert(1)" in (state.get("stored") or ""):
                    state["solved"] = True
            return _ok(url)
        return _page(200, state.get("solved", False))

    ctx = _ctx(handler=handler)
    result = await strategy_xss_exploit_deliver(ctx, None, lambda m: None,
                                                SolveBudget(max_requests=80))
    assert "SOLVED" in result, f"alternation must reach alert(), got: {result}"
    assert "onerror=alert(1)" in state["stored"]


@pytest.mark.asyncio
async def test_delivery_strategy_reports_missing_server(monkeypatch):
    from bughound.objectives import SolveBudget, strategy_xss_exploit_deliver

    ctx = _ctx(seed_html="<html><body>nothing here</body></html>",
               handler=lambda m, u, p, d, headers=None: Response(
                   url=u, status=421, headers={}, text="", elapsed=0.01))
    result = await strategy_xss_exploit_deliver(ctx, None, lambda m: None,
                                                SolveBudget(max_requests=20))
    assert "no reachable exploit server" in result


def test_solve_phase_records_objective_completion(monkeypatch):
    """solving._record flips the objective and adds the completion finding."""
    from bughound.solving import _record
    from bughound.models import ScanResult

    _no_sleep(monkeypatch)
    config = ScanConfig(target_url=LAB + "/")
    target = Target(url=LAB + "/", scheme="https",
                    host="0aa6002c048d221481d9e8d300da002d.web-security-academy.net",
                    port=443, authorized=True)
    result = ScanResult(config=config, target=target)
    objective = {
        "type": "portswigger-lab",
        "title": "DOM XSS in jQuery selector sink using a hashchange event",
        "solved_before": False,
        "attempts": [{"strategy": "xss-exploit-server-deliver",
                      "finding": "victim bot executed print(1)",
                      "exploit_status": "budget=14 reqs", "lab_solved": True}],
        "solved_after": True,
        "evidence": "is-solved",
    }
    emitted: list[str] = []
    _record(result, objective, emitted.append)
    assert result.stats["objective"] == 1
    assert any("Lab objective completed" in f.title for f in result.findings)
