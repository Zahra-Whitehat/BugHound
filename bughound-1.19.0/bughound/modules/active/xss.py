"""Reflected / DOM / attribute / JS-context XSS detection.

Probes multiple reflection contexts used by PortSwigger Academy labs and
real-world apps:

  • HTML body (unencoded angle brackets)
  • Attribute (quote break-out when brackets are encoded)
  • JavaScript string
  • AngularJS expression
  • javascript: URL / href sinks
"""

from __future__ import annotations

import html
import re

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ._util import send_with_param

MARKER = "bhXSS9271"
PROBE_HTML = f"<{MARKER}>\"'"
PROBE_ATTR = f'"{MARKER}" onfocus='
PROBE_JS = f"'-{MARKER}-'"
PROBE_ANGULAR = f"{{{{{MARKER}}}}}"
PROBE_JSURL = f"javascript:{MARKER}"

CONTEXT_PROBES: list[tuple[str, str, str]] = [
    # label, payload, evidence substring that proves a useful reflection.
    # Needles are the FULL probe shape: a bare MARKER needle matched every
    # raw reflection and reported all five contexts at once, which both
    # mislabelled the finding and steered the exploit engine to the wrong
    # playbooks.
    ("html-body", PROBE_HTML, f"<{MARKER}>"),
    ("attribute", PROBE_ATTR, f'"{MARKER}" onfocus='),
    ("js-string", PROBE_JS, f"'-{MARKER}-'"),
    ("angular", PROBE_ANGULAR, f"{{{{{MARKER}}}}}"),
    ("js-url", PROBE_JSURL, f"javascript:{MARKER}"),
]


@register
class XssModule(Module):
    name = "xss"
    categories = [Category.XSS]
    passive = False
    # 1.13.2: active DETECTION runs in default scans -- a scanner that
    # hides its detectors behind --aggressive finds nothing by default.

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()  # (url, param)

        for rt in ctx.request_targets:
            for param in list(rt.params) or ["search", "q", "query"]:
                key = (rt.url, param)
                if key in seen:
                    continue
                seen.add(key)

                contexts: list[str] = []
                best_evidence = ""
                best_request = ""
                excerpt = ""
                raw_marker_html = False

                for label, payload, needle in CONTEXT_PROBES:
                    try:
                        r = await send_with_param(ctx.client, rt, param, payload)
                    except Exception:  # noqa: BLE001
                        continue
                    if not r.ok:
                        continue
                    body = r.text or ""
                    if needle in body:
                        contexts.append(label)
                        if not best_evidence:
                            best_evidence = f"Probe {payload!r} reflected ({label}); needle {needle!r} present."
                            best_request = f"{rt.method} {rt.url} ({param}={payload})"
                            excerpt = self._excerpt(body, needle)
                        if label == "html-body" and f"<{MARKER}>" in body:
                            raw_marker_html = True

                if not contexts:
                    # Last chance: any reflection of the marker at all
                    try:
                        r = await send_with_param(ctx.client, rt, param, PROBE_HTML)
                    except Exception:  # noqa: BLE001
                        continue
                    if r.ok and MARKER in (r.text or ""):
                        contexts = ["partial"]
                        best_evidence = f"Marker {MARKER!r} present in response (encoding needs review)."
                        best_request = f"{rt.method} {rt.url} ({param}={PROBE_HTML})"
                        excerpt = self._excerpt(r.text or "", MARKER)
                    else:
                        continue

                high_conf = raw_marker_html or any(
                    c in contexts for c in ("html-body", "attribute", "js-string", "angular", "js-url")
                )
                severity = Severity.HIGH if high_conf and "partial" not in contexts else (
                    Severity.MEDIUM if high_conf else Severity.LOW
                )
                title_ctx = ", ".join(contexts)
                findings.append(
                    Finding(
                        category=Category.XSS,
                        title=f"XSS reflection in '{param}' [{title_ctx}]",
                        severity=severity,
                        confidence="confirmed" if high_conf and "partial" not in contexts else "firm",
                        url=rt.url,
                        description=(
                            f"Input from '{param}' is reflected into the response in "
                            f"context(s): {title_ctx}. Context-aware encoding is missing or incomplete, "
                            "so an attacker can inject executable script depending on the sink."
                        ),
                        evidence=best_evidence,
                        request=best_request,
                        response_excerpt=excerpt,
                        remediation=(
                            "Apply context-aware output encoding (HTML, attribute, JS string, URL). "
                            "Prefer strict CSP with nonces/hashes; avoid sinks like innerHTML, "
                            "document.write, and jQuery.html() with untrusted data."
                        ),
                        cwe="CWE-79",
                        module=self.name,
                        verified=high_conf and "partial" not in contexts,
                    )
                )
        return findings

    @staticmethod
    def _excerpt(text: str, needle: str) -> str:
        idx = text.find(needle)
        if idx < 0:
            return text[:160]
        start = max(0, idx - 80)
        return text[start : idx + 80]
