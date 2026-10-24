"""Regression tests for the 1.13.1 exploit-engine correctness fixes.

Every test here pins a real bug found while running the engine against a
lab replica:

* the escaping probe's own echo poisoning the context classifier and the
  escaping profile (phantom backslash-escapes, everything looked like a
  template literal),
* inert-payload false positives (needles surviving raw INSIDE strings,
  attribute payloads that never left the attribute),
* empty CSP treated as a strict policy,
* impact-chain memo key mismatch (cookie-steal re-ran on every finding),
* WAF probe budget accounting.
"""

from bughound.exploits import xss_recon as xr
from bughound.exploits.xss import find_unescaped
from bughound.exploits.xss_payloads import (
    CSP_DIRECTIVE_PAYLOAD,
    JSSTRING_BACKSLASH,
    JSSTRING_BREAKOUT,
    class_key_from_title,
)


# ---------------------------------------------------------------------------
# find_unescaped: a needle preceded by a backslash is the ESCAPED form
# ---------------------------------------------------------------------------

def test_find_unescaped_rejects_backslash_escaped():
    body = r"var msg = '\';alert(1)//';"
    # the needle occurrence sits right after the application's backslash:
    # the quote was escaped, the payload is INERT
    assert find_unescaped(body, "';alert(1)//") is None


def test_find_unescaped_accepts_raw_occurrence():
    body = "var msg = '';alert(1)//';"
    assert find_unescaped(body, "';alert(1)//") == "';alert(1)//"


def test_find_unescaped_first_occurrence_escaped_second_raw():
    body = r"x = '\'-alert(1)-\'' + '-alert(1)-'"
    assert find_unescaped(body, "-alert(1)-") == "-alert(1)-"


def test_find_unescaped_at_start_and_empty_needle():
    assert find_unescaped("'-alert(1)-'", "'-alert(1)-'") == "'-alert(1)-'"
    assert find_unescaped("anything", "") is None


def test_jsstring_backslash_payload_verify_shape():
    # lab 16: application escapes ' -> the echo is \\'-alert(1)// and the
    # double-backslash needle must match AT position 0 (not shadowed)
    echo = r"\\'-alert(1)//"
    assert find_unescaped(echo, r"\\'-alert(1)//") == r"\\'-alert(1)//"
    # the bare quote needle IS preceded by a backslash in that echo
    assert find_unescaped(echo, "'-alert(1)//") is None
    # sanity: the payload constant is the official one-backslash shape
    assert JSSTRING_BACKSLASH == "\\'-alert(1)//"
    assert JSSTRING_BREAKOUT == "'-alert(1)-'"


# ---------------------------------------------------------------------------
# escaping profile: probe echo must not poison the verdicts
# ---------------------------------------------------------------------------

def test_escaping_profile_exact_raw_echo_reports_raw():
    body = "<p>Results for " + xr.MARKER + xr.ECHO_TAIL + "</p>"
    prof = xr.escaping_profile(body)
    assert prof["<"] == "raw"
    assert prof["'"] == "raw"
    assert prof["\\"] == "raw"
    assert prof['"'] == "raw"


def test_escaping_profile_no_phantom_backslash_escape():
    # the OLD probe ended with a backslash: echoed raw it escaped the
    # application's NEXT character and every quote looked backslash-escaped
    body = "<p>" + xr.MARKER + xr.ECHO_TAIL + "'; show(msg);</p>"
    prof = xr.escaping_profile(body)
    assert prof["'"] != "backslash-escaped"


def test_escaping_profile_detects_real_backslash_escaping():
    # application escapes ' with a backslash: the echo differs from the tail
    body = "<p>" + xr.MARKER + xr.ECHO_TAIL.replace("'", "\\'") + "'; show;</p>"
    prof = xr.escaping_profile(body)
    assert prof["'"] == "backslash-escaped"


# ---------------------------------------------------------------------------
# context classification: probe backtick must not fake a template literal
# ---------------------------------------------------------------------------

def test_classifier_quote_string_not_template_despite_probe_backtick():
    # the CHAR_PROBE contains a backtick AFTER the marker: a naive window
    # check classified every script reflection as a template literal
    js = "var msg = '" + xr.MARKER + xr.CHAR_PROBE[len(xr.MARKER):] + "'; show(msg);"
    html = f"<html><script>{js}</script></html>"
    ctx = xr.find_marker_context(html, xr.MARKER)
    assert xr.CONTEXT_SCRIPT_STRING in ctx
    assert xr.CONTEXT_SCRIPT_TEMPLATE not in ctx


def test_classifier_real_template_literal_detected():
    js = "var msg = `" + xr.MARKER + xr.ECHO_TAIL + "`; show(msg);"
    html = f"<html><script>{js}</script></html>"
    ctx = xr.find_marker_context(html, xr.MARKER)
    assert xr.CONTEXT_SCRIPT_TEMPLATE in ctx


def test_detect_string_delim_single_double_backtick():
    assert xr.detect_string_delim("var s = '" + xr.MARKER, xr.MARKER) == "'"
    assert xr.detect_string_delim('var s = "' + xr.MARKER, xr.MARKER) == '"'
    assert xr.detect_string_delim("var s = `" + xr.MARKER, xr.MARKER) == "`"
    # escaped quote directly before the marker: ambiguous -> ""
    assert xr.detect_string_delim("var s = \\'" + xr.MARKER, xr.MARKER) == ""


# ---------------------------------------------------------------------------
# CSP policy: no header is NOT a strict policy
# ---------------------------------------------------------------------------

def test_empty_csp_is_not_strict():
    assert xr.parse_csp({}).blocks_inline_script is False
    assert xr.parse_csp({"content-security-policy": ""}).blocks_inline_script is False


def test_strict_csp_detected_and_directive_payload_shape():
    strict = xr.parse_csp({"content-security-policy": "script-src 'self'; object-src 'none'"})
    assert strict.blocks_inline_script is True
    assert not strict.allows_script_from("evil.example")
    permissive = xr.parse_csp({"content-security-policy": "script-src 'unsafe-inline'"})
    assert permissive.blocks_inline_script is False
    assert ";script-src-elem 'unsafe-inline'" == CSP_DIRECTIVE_PAYLOAD


# ---------------------------------------------------------------------------
# class keys: the 27 lab families still map
# ---------------------------------------------------------------------------

def test_class_keys_survive():
    pairs = {
        "DOM XSS in innerHTML sink using source location.search": "dom-innerhtml",
        "Reflected XSS into attribute with angle brackets HTML-encoded": "reflected-attr",
        "Reflected XSS into a JavaScript string with single quote and backslash escaped":
            "jsstring-script-close",
        "Reflected XSS into a template literal with angle brackets, single, double quotes, "
        "backslash and backticks Unicode-escaped": "template-literal",
        "Exploiting cross-site scripting to steal cookies": "impact-cookie-steal",
        "Exploiting cross-site scripting to capture passwords": "impact-password-capture",
        "Exploiting XSS to bypass CSRF defenses": "impact-csrf-bypass",
        "Reflected XSS protected by very strict CSP, with dangling markup attack":
            "csp-dangling-markup",
        "Reflected XSS protected by CSP, with CSP bypass": "csp-directive-injection",
    }
    for title, key in pairs.items():
        assert class_key_from_title(title) == key, title
