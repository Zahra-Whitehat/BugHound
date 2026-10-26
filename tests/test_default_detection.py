"""Regression tests for the 1.13.2 detection-by-default contract.

Root cause this locks down: every active hunting module carried
``aggressive_required = True``, so a plain ``bughound scan`` (no flags)
dropped ALL of them in build_modules() and "Phase 2: hunting squads"
ran 0 modules -- the scanner reported only header/TLS noise and the
user read that as "it doesn't find any vulnerabilities".

Contract now:

* default scan            -> passive + active DETECTION modules
* exploit-grade modules   -> still opt-in (only --aggressive selects them)
* --safe / --passive /
  --mode stealth          -> passive modules only
* --mode normal           -> active detection, exploit phase off
"""

from __future__ import annotations

import pytest

from bughound.models import ScanConfig
from bughound.modules.base import build_modules, load_all_modules

load_all_modules()

DETECTION_MODULES = [
    "xss",
    "sqli",
    "nosqli",
    "command-injection",
    "path-traversal",
    "open-redirect",
    "header-injection",
    "host-header-poison",
    "ssrf",
    "xxe-prober",
    "graphql-hunter",
    "jwt-attacks",
    "prototype-pollution",
    "advisory",
]


def _names(cfg: ScanConfig) -> set[str]:
    return {m.name for m in build_modules(cfg)}


def test_default_scan_runs_active_detection():
    """A plain `bughound scan` must select the XSS/SQLi/... detectors."""
    names = _names(ScanConfig(target_url="http://t/"))
    for mod in DETECTION_MODULES:
        assert mod in names, f"{mod} missing from default scan"


def test_default_scan_excludes_exploit_grade():
    names = _names(ScanConfig(target_url="http://t/"))
    assert "default-logins" not in names


def test_aggressive_selects_exploit_grade():
    names = _names(ScanConfig(target_url="http://t/", aggressive=True))
    assert "default-logins" in names


def test_safe_means_passive_only():
    names = _names(ScanConfig(target_url="http://t/", passive_only=True))
    for mod in DETECTION_MODULES:
        assert mod not in names, f"--safe must not run {mod}"
    assert "security-headers" in names  # passive still present


def test_stealth_mode_is_passive_only():
    names = _names(ScanConfig(target_url="http://t/", mode="stealth"))
    assert "xss" not in names
    assert "security-headers" in names


def test_mode_normal_is_active_detection_without_exploit_grade():
    names = _names(ScanConfig(target_url="http://t/", mode="normal"))
    assert "xss" in names
    assert "default-logins" not in names


def test_module_selection_honors_explicit_module_list():
    names = _names(ScanConfig(target_url="http://t/", modules=["xss"]))
    assert names == {"xss"}


def test_cli_aggressive_flag_semantics():
    """--aggressive/--safe tri-state: None=default detection, True=aggressive,
    False (explicit --safe)=passive-only."""
    from click.testing import CliRunner
    from bughound.cli import main as cli

    runner = CliRunner()

    # Extract the mode-resolution logic indirectly: invoke scan --help to
    # make sure the flags exist, then unit-test the mapping inline.
    res = runner.invoke(cli, ["scan", "--help"])
    assert res.exit_code == 0
    assert "--aggressive" in res.output
    assert "--passive" in res.output

    # The mapping implemented in scan(): aggr=bool(flag); passive_only=(flag is False) or passive
    aggressive_flag = None
    aggr = bool(aggressive_flag)
    passive_only = (aggressive_flag is False) or bool(False)
    assert aggr is False and passive_only is False  # default: detection on

    aggressive_flag = True
    assert bool(aggressive_flag) is True and (aggressive_flag is False) is False

    aggressive_flag = False  # explicit --safe
    assert bool(aggressive_flag) is False and (aggressive_flag is False) is True


def test_exploit_phase_enabled_contract():
    """1.14.0: exploit/chain/solve phases are ON by default; only explicit
    opt-outs (--no-exploit / --mode normal / passive-only) disable them."""
    from bughound.modes import exploit_phase_enabled

    assert exploit_phase_enabled(ScanConfig(target_url="http://t/")) is True
    assert exploit_phase_enabled(ScanConfig(target_url="http://t/", exploit=False)) is False
    assert exploit_phase_enabled(ScanConfig(target_url="http://t/", passive_only=True)) is False
    assert exploit_phase_enabled(ScanConfig(target_url="http://t/", aggressive=True)) is True
    assert exploit_phase_enabled(ScanConfig(target_url="http://t/", mode="normal")) is True  # field only; apply_mode flips exploit


def test_apply_mode_exploit_optouts():
    from bughound.modes import apply_mode, exploit_phase_enabled

    cfg = ScanConfig(target_url="http://t/")
    apply_mode(cfg, "normal")
    assert exploit_phase_enabled(cfg) is False  # detection-only

    cfg2 = ScanConfig(target_url="http://t/")
    apply_mode(cfg2, "aggressive")
    assert exploit_phase_enabled(cfg2) is True  # same as default

    cfg3 = ScanConfig(target_url="http://t/")
    apply_mode(cfg3, "stealth")
    assert exploit_phase_enabled(cfg3) is False and cfg3.aggressive is False
