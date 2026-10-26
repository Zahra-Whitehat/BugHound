"""Shared test fixtures.

The headless-browser layer (bughound.browser_exec) is disabled for the whole
suite so tests stay hermetic: no Playwright import, no Chromium launch, no
network. Browser-specific tests re-enable the flag (or monkeypatch
``execute_payload``) inside their own bodies.
"""

from __future__ import annotations

import pytest

from bughound import browser_exec


@pytest.fixture(autouse=True)
def _no_headless_browser(monkeypatch):
    monkeypatch.setattr(browser_exec, "enabled", False)
    monkeypatch.setattr(browser_exec, "_AVAILABILITY_CACHE", None)
