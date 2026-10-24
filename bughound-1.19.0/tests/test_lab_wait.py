"""Tests for the --wait (dead-lab polling) feature added in 1.19.0.

A live Academy lab NEVER serves the gateway's 'cannot reach the lab
backend' 504 signature, so pre-flight probing can distinguish 'instance
stopped/expired' from ordinary transport errors. 1.19.0 adds
``ScanConfig.wait_for_lab``: instead of aborting instantly on that
signature, the engine polls every ~15s for up to N seconds and proceeds
the moment a fresh instance answers -- closing the spawn->copy->scan
race that made users read 'the solver does not work' when their instance
was simply dead or still booting.
"""

from __future__ import annotations

import asyncio

import pytest

from bughound.engine import LAB_WAIT_POLL_INTERVAL, wait_for_lab
from bughound.models import ScanConfig


def _cfg(wait: int) -> ScanConfig:
    return ScanConfig(
        target_url="https://0a0f001204af9113801f80ef006d0006.web-security-academy.net/",
        wait_for_lab=wait,
    )


def _probe_seq(*results):
    """Probe stub returning canned (ok, reason, dead) triples in order."""
    seq = list(results)

    async def _probe(client, url, emit):
        if not seq:
            raise AssertionError("probe called more times than scripted")
        return seq.pop(0)

    return _probe


def _no_sleep(_seconds):
    async def _sleep(_):
        return None

    return _sleep


def test_wait_returns_alive_on_first_poll():
    """A probe that goes alive immediately returns (ok, '', False)."""
    emit_lines: list[str] = []

    async def _run():
        return await wait_for_lab(
            None, _cfg(600), emit_lines.append,
            probe=_probe_seq((True, "", False)),
            sleep=_no_sleep(LAB_WAIT_POLL_INTERVAL),
        )

    ok, reason, dead = asyncio.run(_run())
    assert (ok, reason, dead) == (True, "", False)
    assert any("ALIVE on poll #1" in ln for ln in emit_lines)


def test_wait_polls_until_alive():
    """dead -> dead -> alive: the third poll wins and the scan proceeds."""
    emit_lines: list[str] = []
    dead_reason = "the gateway cannot reach the lab backend (HTTP 504: instance stopped or expired)"

    async def _run():
        return await wait_for_lab(
            None, _cfg(600), emit_lines.append,
            probe=_probe_seq(
                (False, dead_reason, True),
                (False, dead_reason, True),
                (True, "", False),
            ),
            sleep=_no_sleep(LAB_WAIT_POLL_INTERVAL),
        )

    ok, reason, dead = asyncio.run(_run())
    assert ok is True and dead is False
    assert any("poll #3" in ln for ln in emit_lines)


def test_wait_budget_exhausted():
    """A probe that never recovers returns (False, '<budget> exhausted', True)."""
    emit_lines: list[str] = []
    dead_reason = "the gateway cannot reach the lab backend (HTTP 504: instance stopped or expired)"

    # Fake clock advanced by the injected sleep so the deadline discipline
    # is exercised deterministically (no real waiting).
    clock = {"t": 1000.0}

    def fake_clock() -> float:
        return clock["t"]

    sleeps: list[float] = []

    async def _sleep(s):
        sleeps.append(s)
        clock["t"] += s

    async def _probe(client, url, emit):
        return (False, dead_reason, True)

    async def _run():
        return await wait_for_lab(
            None, _cfg(10), emit_lines.append,
            probe=_probe, sleep=_sleep, clock=fake_clock,
        )

    ok, reason, dead = asyncio.run(_run())
    assert ok is False and dead is True
    assert "10s" in reason and "--wait budget" in reason
    # Budget discipline: never slept past the deadline, and each snooze was
    # capped at the poll interval.
    assert sum(sleeps) <= 10 * 1.05
    assert all(s <= LAB_WAIT_POLL_INTERVAL for s in sleeps)


def test_wait_zero_budget_never_polls():
    """wait_for_lab=0 (legacy) is rejected before any polling happens."""

    async def _run():
        return await wait_for_lab(
            None, _cfg(0), lambda _m: None,
            probe=_probe_seq((True, "", False)),
            sleep=_no_sleep(LAB_WAIT_POLL_INTERVAL),
        )

    ok, reason, dead = asyncio.run(_run())
    assert ok is False and dead is True
    assert "0s" in reason


def test_wait_negative_budget_clamped():
    """Negative --wait values are clamped to the legacy no-wait path."""

    async def _run():
        return await wait_for_lab(
            None, _cfg(-5), lambda _m: None,
            probe=_probe_seq((True, "", False)),
            sleep=_no_sleep(LAB_WAIT_POLL_INTERVAL),
        )

    ok, _, dead = asyncio.run(_run())
    assert ok is False and dead is True


def test_wait_poll_interval_is_gentle():
    """15s cadence: fast enough to catch a boot, slow enough to be polite."""
    assert 10 <= LAB_WAIT_POLL_INTERVAL <= 30


def test_config_default_is_no_wait():
    """Backwards compatibility: omitting --wait keeps instant-abort."""
    cfg = ScanConfig(target_url="https://example.net/")
    assert cfg.wait_for_lab == 0


@pytest.mark.parametrize("raw,expected", [(-3, -3), (0, 0), (600, 600)])
def test_model_accepts_int_budgets(raw, expected):
    assert ScanConfig(target_url="https://example.net/", wait_for_lab=raw).wait_for_lab == expected
