"""Scanner module base class and registry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..http_client import HttpClient
from ..models import Category, Finding, ScanConfig, Target


@dataclass
class RequestTarget:
    """A discovered injectable location (URL query or form)."""

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    source: str = ""  # e.g. "query", "form"
    # Raw-body targets (XML/JSON endpoints): the body template carries an
    # ``{INJ}`` marker where payloads are substituted; ``encoding`` names a
    # WAF-bypass payload encoding applied at the marker (e.g.
    # "xml-entities" -> numeric character references).
    body_template: str = ""
    content_type: str = ""
    encoding: str = ""


@dataclass
class ScanContext:
    client: HttpClient
    config: ScanConfig
    target: Target
    base_url: str
    # populated by the crawler:
    urls: list[str] = field(default_factory=list)
    request_targets: list[RequestTarget] = field(default_factory=list)
    # shared cache of the landing page response text/headers:
    seed_html: str = ""
    seed_headers: dict[str, str] = field(default_factory=dict)
    log: Callable[[str], None] = lambda msg: None
    # Shared, mutable recon dictionary. Passive recon modules write structured
    # attack-surface data here (subdomains, DNS records, tech stack, WAF,
    # discovered endpoints, emails, etc.); the engine merges it into
    # ``ScanResult.recon`` after every module finishes. Modules SHOULD guard
    # against clobbering keys written by earlier modules (use ``setdefault``
    # for lists/dicts).
    recon: dict[str, object] = field(default_factory=dict)


# Stable keys used in ``ScanContext.recon`` / ``ScanResult.recon``. The
# reporting layer uses this list to render the Reconnaissance section in a
# predictable order regardless of which modules ran.
RECON_KEYS: list[str] = [
    "subdomains",
    "subdomain_takeover_candidates",
    "dns_records",
    "whois",
    "favicon_hash",
    "wayback_urls",
    "wayback_interesting_urls",
    "email_security",      # SPF / DMARC / DKIM posture
    "tech_stack",          # {category: [products]}
    "waf",                 # str | None
    "http_methods",        # list[str]
    "js_endpoints",        # list[str]
    "emails",              # list[str]
    "admin_paths",         # list[str]
    "api_docs",            # list[str]
    "backup_files",        # list[str]
    "sourcemaps",          # list[str]
    "robots_txt",          # str
    "sitemap_urls",        # list[str]
    "security_txt",        # str
    "well_known_paths",    # list[str]
    "discovered_urls",     # URLs from katana/gau/waymore/httpx
    "secrets",             # leaked tokens / keys from recon tools
    "leaked_data",         # generic extracted artefacts
    "database_dumps",      # table/row extracts from sqlmap etc.
    "file_contents",       # retrieved file body snippets
]


class Module:
    """Base class for all scanner modules."""

    name: str = "base"
    categories: list[Category] = []
    #: passive modules never send attack payloads (safe against any target)
    passive: bool = True
    #: DEPRECATED alias kept for third-party module compat: 1.13.1 and older
    #: used this to keep ALL active detection out of default scans, which is
    #: why a plain `bughound scan` found nothing (Phase 2 ran 0 modules).
    #: build_modules() no longer reads it -- set :attr:`exploit_grade` instead.
    aggressive_required: bool = False
    #: exploit-grade payloads (credential brute force, state-changing proof
    #: exploits). These modules stay opt-in behind --aggressive/--brute;
    #: plain DETECTION modules (marker reflection, error-based SQLi, ...)
    #: run in every non-passive scan.
    exploit_grade: bool = False

    async def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if cls.name in REGISTRY:
        raise ValueError(f"Duplicate module name: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls


def load_all_modules() -> None:
    """Import module packages so their @register decorators run."""

    from . import active, passive  # noqa: F401


def build_modules(config: ScanConfig) -> list[Module]:
    """Select the modules a scan should run, honouring the mode contract.

    Selection rules (1.13.2+):

    * **Default** (plain ``bughound scan``) runs passive AND active
      *detection* modules.  A vulnerability scanner that ships no detection
      by default finds nothing, which users correctly read as "broken".
    * Exploit-grade modules (:attr:`Module.exploit_grade`, e.g. default
      credential brute force) still require ``config.aggressive``.
    * Passive-only scans (``--safe``, ``--mode stealth``, or
      ``config.passive_only``) run passive modules exclusively.
    """
    load_all_modules()
    selected = config.modules
    mode = (getattr(config, "mode", "") or "").strip().lower()
    passive_only = bool(getattr(config, "passive_only", False)) or mode == "stealth"
    modules: list[Module] = []
    for name, cls in sorted(REGISTRY.items()):
        if selected is not None and name not in selected:
            continue
        inst = cls()
        if passive_only and not inst.passive:
            continue
        if inst.exploit_grade and not config.aggressive:
            continue
        modules.append(inst)
    return modules
