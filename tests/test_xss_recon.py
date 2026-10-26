"""Recon tests: reflection context classification, escaping profiles,
CSP parsing and DOM flow analysis (pure functions, no network)."""

from bughound.exploits import xss_recon as xr
from bughound.exploits.xss_recon import MARKER


def test_context_html():
    body = f"<h1>Results for {MARKER}</h1><p>nothing</p>"
    assert xr.CONTEXT_HTML in xr.find_marker_context(body, MARKER)


def test_context_comment_is_dead_end():
    body = f"<!-- note {MARKER} kept for ops -->"
    assert xr.find_marker_context(body, MARKER) == [xr.CONTEXT_COMMENT]


def test_context_attribute_value():
    body = f'<a href="/search" title="Results for {MARKER}" class=big>go</a>'
    assert xr.CONTEXT_ATTR in xr.find_marker_context(body, MARKER)


def test_context_href_attribute():
    body = f'<a href="/redirect?url={MARKER}">next</a>'
    assert xr.CONTEXT_HREF in xr.find_marker_context(body, MARKER)


def test_context_script_string():
    body = f"<script>var q = '{MARKER}'; track(q);</script>"
    assert xr.CONTEXT_SCRIPT_STRING in xr.find_marker_context(body, MARKER)


def test_context_script_plain_js():
    body = f"<script>var q = {MARKER};</script>"
    assert xr.CONTEXT_SCRIPT_JS in xr.find_marker_context(body, MARKER)


def test_context_script_template():
    body = f"<script>var t = `Hello ${{'{MARKER}'}}!`;</script>"
    contexts = xr.find_marker_context(body, MARKER)
    assert xr.CONTEXT_SCRIPT_TEMPLATE in contexts


def test_context_select():
    body = f"<select><option>1</option><option>{MARKER}</option></select>"
    assert xr.CONTEXT_SELECT in xr.find_marker_context(body, MARKER)


def test_context_angular_expression():
    body = f"<div ng-app><h1>{{{{resultsFor('{MARKER}')}}}}</h1></div>"
    assert xr.CONTEXT_ANGULAR in xr.find_marker_context(body, MARKER)


def test_context_title():
    body = f"<title>Search: {MARKER} - Shop</title>"
    assert xr.CONTEXT_TITLE in xr.find_marker_context(body, MARKER)


def test_escaping_profile_detects_html_encoding():
    body = "&lt;bhxss7q4&gt;\"onmouseover=\"alert(1)"
    profile = xr.escaping_profile(body)
    assert profile["<"] == "html-encoded"
    assert profile[">"] == "html-encoded"
    assert profile['"'] == "raw"


def test_escaping_profile_detects_backslash_escape():
    # lab-16 shape: the app escapes our quote with a backslash next to the marker
    body = "var q = 'bhxss7q4\\'-alert(1)//';"
    profile = xr.escaping_profile(body)
    assert profile["'"] == "backslash-escaped"


def test_escaping_profile_raw():
    # full raw reflection of the probe: every special char comes back untouched
    body = "results: bhxss7q4<>\"'${}();=`\\"
    profile = xr.escaping_profile(body)
    assert profile["<"] == "raw"
    assert profile["`"] == "raw"
    assert profile["'"] == "raw"
    assert profile['"'] == "raw"


def test_parse_csp_basic():
    policy = xr.parse_csp({"content-security-policy":
                           "default-src 'self'; script-src 'self' https://cdn.example.com; img-src *"})
    assert policy.directives["script-src"] == ["'self'", "https://cdn.example.com"]
    assert policy.blocks_inline_script
    assert policy.allows_script_from("cdn.example.com")
    assert not policy.allows_script_from("evil.example.com")


def test_parse_csp_allows_inline():
    policy = xr.parse_csp({"content-security-policy": "script-src 'unsafe-inline'"})
    assert not policy.blocks_inline_script


def test_parse_csp_missing():
    assert xr.parse_csp({}).raw == ""


def test_dom_flow_innerhtml():
    page = """
    <form action="/?search="><input name=search></form>
    <script>
    const params = new URLSearchParams(location.search);
    document.getElementById('results').innerHTML = params.get('search');
    </script>
    """
    flows = xr.analyze_dom_flows(page)
    assert any(f.sink == "innerHTML" and f.param_hint == "search" and f.delivery == "query"
               for f in flows)


def test_dom_flow_select_context_uses_select_close():
    page = """
    <select id=picker></select>
    <script>document.write('<select>'+location.search.split('category=')[1]+'</select>');</script>
    """
    flows = xr.analyze_dom_flows(page)
    assert flows
    docwrite = [f for f in flows if f.sink == "document.write"]
    assert docwrite and docwrite[0].payload.startswith("</select>")


def test_dom_flow_jquery_attr():
    page = """
    <a id=backLink href="/">Back</a>
    <script src="https://lab.example.net/jquery.min.js"></script>
    <script>
    $(function() {
      $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnUrl'));
    });
    </script>
    """
    flows = xr.analyze_dom_flows(page)
    attr = [f for f in flows if f.sink == "jquery-attr"]
    # Official Academy payload for this sink family (fires on click via the
    # poisoned href; browser_exec clicks javascript: anchors after load).
    assert attr and attr[0].param_hint == "returnUrl"
    assert attr[0].payload == "javascript:alert(document.cookie)"


def test_dom_flow_jquery_selector_hashchange():
    page = """
    <script src="https://lab.example.net/jquery.min.js"></script>
    <script>
    $(window).on('hashchange', function() {
      var element = $(location.hash);
      element[0].scrollIntoView();
    });
    </script>
    """
    flows = xr.analyze_dom_flows(page)
    sel = [f for f in flows if f.sink == "jquery-selector"]
    assert sel and sel[0].delivery == "fragment"


def test_dom_flow_angular_detected():
    page = '<div ng-app>search: <b>{{results}}</b></div><script src="/angular.min.js"></script>'
    flows = xr.analyze_dom_flows(page)
    assert any(f.sink == "angular" for f in flows)


def test_waf_matrix_suggests_body_resize():
    m = xr.WafMatrix(tags={"body", "xss"}, event_attrs={"onresize"})
    assert xp_is_expected(m)


def xp_is_expected(m):
    from bughound.exploits import xss_payloads as xp
    return xp.WAF_BODY_RESIZE in m.suggest_payloads()


def test_waf_matrix_suggests_svg_animate():
    m = xr.WafMatrix(tags={"svg", "a", "animate", "text"}, special_attrs={"attributeName", "values"})
    out = m.suggest_payloads()
    assert out and "attributeName=href" in out[0]


def test_waf_matrix_suggests_custom_tag():
    m = xr.WafMatrix(tags={"xss"}, event_attrs={"onfocus"})
    out = m.suggest_payloads()
    assert out and out[0].startswith("<xss id=x")


def test_reflection_profile_properties():
    p = xr.ReflectionProfile(escaping={"<": "raw", '"': "raw", "'": "raw"})
    assert p.angle_brackets_raw and p.double_quote_raw and p.single_quote_raw
    p2 = xr.ReflectionProfile(escaping={"<": "html-encoded", '"': "raw"})
    assert not p2.angle_brackets_raw and p2.double_quote_raw
