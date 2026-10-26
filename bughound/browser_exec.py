"""Headless-browser payload execution (Playwright, optional).

The HTTP-only exploit engine can PROVE that a payload reaches an executable
position (raw reflection, DOM source->sink flow, exploit-server delivery) --
but some exploit objectives only complete when the payload actually RUNS in
a real browser. PortSwigger's XSS labs, for example, flip their status to
"solved" only when ``alert()`` / ``print()`` genuinely fire in a browser
session; no amount of HTTP traffic can satisfy that.

This module closes the last mile:

1. **Detect** the browser stack: Playwright + a Chromium binary. Probed
   cheaply (no launch) and cached. Missing stack is never an error -- it
   degrades to a hint string, consistent with the tool's no-auto-install
   contract.
2. **Execute** a PoC URL in headless Chromium and capture every dialog
   (``alert`` / ``confirm`` / ``prompt``) as real execution proof, plus
   whether the payload markers survive in the rendered DOM.
3. **Report** a uniform :class:`BrowserResult` so callers (XSS exploit
   engine, solve phase) can upgrade "payload prepared" into "payload
   EXECUTED" and re-check lab status after a dialog fired.

The browser is driven from a worker thread (``asyncio.to_thread``) so the
asyncio engine never blocks. Everything is fail-open: any browser error
becomes an informational ``BrowserResult.error``, never an exception.
"""

from __future__ import annotations

import asyncio
import os
import threading
from dataclasses import dataclass, field

#: Module-level kill switch used by the test-suite (and exotic embedders) to
#: keep the suite hermetic: when False, ``execute_payload`` short-circuits to
#: a "disabled" result without touching Playwright.
enabled: bool = True

_AVAILABILITY_CACHE: tuple[bool, str] | None = None

INSTALL_HINT = (
    "headless-browser execution unavailable -- install Playwright (optional, "
    "never automatic): pip install playwright && python -m playwright install chromium"
)


@dataclass
class BrowserResult:
    """Uniform outcome of one headless-browser PoC execution."""

    url: str
    ok: bool = False                 # the page was actually loaded by a browser
    dialogs: list[dict] = field(default_factory=list)  # [{"type": "alert", "message": "1"}]
    payload_visible: bool = False    # payload markers present in the rendered DOM
    page_title: str = ""
    error: str = ""
    hint: str = ""
    # Anchors whose href is a javascript: URL only execute on CLICK (the
    # jQuery attr('href') lab family): after load we click them for the
    # operator. Clicked hrefs are recorded as execution evidence.
    clicked_hrefs: list[str] = field(default_factory=list)

    @property
    def executed(self) -> bool:
        """True when at least one JS dialog fired (alert/confirm/prompt)."""
        return bool(self.dialogs)

    def dialog_summary(self) -> str:
        if not self.dialogs:
            return ""
        first = self.dialogs[0]
        more = f" (+{len(self.dialogs) - 1} more)" if len(self.dialogs) > 1 else ""
        return f"{first.get('type', 'dialog')} dialog fired (message: {first.get('message', '')!r}){more}"


def browser_available() -> tuple[bool, str]:
    """Cheap, cached probe: is a usable headless Chromium present?

    Returns ``(True, "")`` when Playwright + Chromium are importable/present,
    else ``(False, INSTALL_HINT)``. Import failures and missing browser
    binaries are expected on locked-down hosts and are reported, never raised.
    """
    global _AVAILABILITY_CACHE
    if _AVAILABILITY_CACHE is not None:
        return _AVAILABILITY_CACHE
    result = _probe_availability()
    _AVAILABILITY_CACHE = result
    return result


def _find_chromium_binary() -> str:
    """Locate a Playwright-managed Chromium without starting the driver.

    The sync Playwright API refuses to run inside a live asyncio event loop
    (the engine is asyncio), so the cheap probe must not use it. A filesystem
    glob over the standard browser caches is instant and version-proof
    (chromium-NNNN folders); the authoritative driver-based probe remains as
    a thread-based fallback for custom installs.
    """
    import glob

    base = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or os.path.expanduser(
        "~/.cache/ms-playwright"
    )
    patterns = [
        os.path.join(base, "chromium-*", "chrome-linux*", "chrome"),
        os.path.join(base, "chromium-*", "chrome-win*", "chrome.exe"),
        os.path.join(base, "chromium-*", "chrome-mac*", "Chromium.app", "Contents", "MacOS", "Chromium"),
    ]
    for pat in patterns:
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return ""


def _probe_with_driver() -> tuple[bool, str]:
    """Authoritative probe via the Playwright driver (must run off-loop)."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except Exception:  # noqa: BLE001 -- playwright not installed
        return False, INSTALL_HINT
    try:
        with sync_playwright() as pw:
            exe = getattr(pw.chromium, "executable_path", "")
        if not exe or not os.path.exists(exe):
            return False, INSTALL_HINT
    except Exception:  # noqa: BLE001 -- driver/driver-cache problems
        return False, INSTALL_HINT
    return True, ""


def _probe_availability() -> tuple[bool, str]:
    try:
        import playwright  # noqa: F401 -- presence check only
    except Exception:  # noqa: BLE001 -- playwright not installed
        return False, INSTALL_HINT
    if _find_chromium_binary():
        return True, ""
    # Custom install (channel/browsers-path): ask the driver in a plain
    # thread -- the sync API cannot run inside the engine's event loop.
    box: dict = {}

    def _run() -> None:
        box["res"] = _probe_with_driver()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(20)
    return box.get("res", (False, INSTALL_HINT))


def execute_sync(poc_url: str, needles: list[str] | None = None,
                 timeout_s: float = 25.0, settle_ms: int = 1200) -> BrowserResult:
    """Run one PoC URL in headless Chromium (blocking; call via thread)."""
    result = BrowserResult(url=poc_url)
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        result.hint = INSTALL_HINT
        result.error = "playwright is not installed"
        return result

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                def _on_dialog(dialog) -> None:  # pragma: no branch - trivial
                    result.dialogs.append({"type": dialog.type, "message": dialog.message})
                    try:
                        dialog.accept()
                    except Exception:  # noqa: BLE001 -- dialog may already be gone
                        pass

                page.on("dialog", _on_dialog)
                page.goto(poc_url, wait_until="load", timeout=int(timeout_s * 1000))
                page.wait_for_timeout(settle_ms)  # let sink scripts / websockets run
                # javascript: hrefs are INERT until the anchor is clicked (a
                # navigation to the javascript: URL happens on activation, not
                # on load). DOM labs that sink location.search into an anchor's
                # href (jQuery .attr('href', ...) family) therefore need the
                # click: fire it here, bounded, after the sink script ran.
                # IMPORTANT: on the real Academy pages the anchor starts with
                # NO href at all -- jQuery only applies it inside a
                # document-ready callback, which can fire AFTER the load
                # event (real jQuery download + ready queue). A fixed settle
                # races that; wait for the poisoned href to actually EXIST
                # before clicking.
                try:
                    page.wait_for_function(
                        "() => !!document.querySelector("
                        "\"a[href^='javascript:'], area[href^='javascript:']\")",
                        timeout=6000,
                    )
                except Exception:  # noqa: BLE001 -- no poisoned anchor; fall through
                    pass
                try:
                    # One-shot, quote-safe: click the elements directly via
                    # their handles (re-querying by attribute value would
                    # break on payloads containing quotes) and record what
                    # was clicked as execution evidence.
                    js_hrefs = page.eval_on_selector_all(
                        "a[href^='javascript:'], area[href^='javascript:']",
                        "els => els.slice(0, 5).map(e => { "
                        "const h = e.getAttribute('href'); try { e.click(); } "
                        "catch (err) {} return h; })",
                    ) or []
                    result.clicked_hrefs = [h for h in js_hrefs if h]
                    if result.clicked_hrefs:
                        page.wait_for_timeout(settle_ms)  # let clicked payloads run
                except Exception:  # noqa: BLE001 -- click phase is best-effort
                    pass
                result.page_title = page.title() or ""
                try:
                    content = page.content()
                except Exception:  # noqa: BLE001
                    content = ""
                if content and needles:
                    # Browsers re-quote attributes in the rendered DOM
                    # (onerror=alert(1) becomes onerror="alert(1)"), so the
                    # exact-payload check is quote-normalized on both sides.
                    norm = content.replace('"', "").replace("'", "")
                    result.payload_visible = any(
                        n in content or n.replace('"', "").replace("'", "") in norm
                        for n in needles if n
                    )
                result.ok = True
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 -- browser errors are evidence, not crashes
        result.error = f"{type(exc).__name__}: {exc}"[:300]
        if "Executable doesn't exist" in result.error or "playwright install" in result.error:
            result.hint = INSTALL_HINT
    return result


async def execute_payload(poc_url: str, needles: list[str] | None = None,
                          timeout_s: float = 25.0, settle_ms: int = 1200) -> BrowserResult:
    """Async wrapper: execute a PoC URL in the headless browser.

    Never raises. When the module is disabled (test suite) or the browser
    stack is missing, a descriptive non-executed :class:`BrowserResult` is
    returned so callers can degrade gracefully.
    """
    if not enabled:
        return BrowserResult(url=poc_url, error="headless-browser execution disabled")
    return await asyncio.to_thread(execute_sync, poc_url, needles, timeout_s, settle_ms)
