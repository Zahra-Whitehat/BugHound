"""Wrappers around external bug-bounty / pentesting tools.

Every tool listed in the operator catalog has a runner. Each wrapper degrades
gracefully: if the binary is not installed the wrapper returns an empty list
and logs a skip note instead of failing the scan.

When a tool *is* available, every invocation is logged via the optional
``emit`` callback so the terminal shows exactly which tool is running:

    → using tool: subfinder  (subfinder -d example.com -silent)
    ✓ subfinder finished (ok)
    · skipping amass (not installed)

Tool groups
-----------
Reconnaissance / asset discovery
  amass, assetfinder, findomain, subfinder, subdomainx, chaos, metabigor,
  shodan, crt.sh (API), certstream, tldbrute, tldextract, waybackurls,
  waymore, gau, urlfinder, dnsgen, enumerepo, hakrevdns, hakoriginfinder,
  hakip2host, asnmap, cdncheck, mapcidr, puredns, shuffledns, massdns,
  dnsx, httpx, alterx, anew, gf, qsreplace, dsieve, smap, nmapurls,
  jsfinder2, jsleak, jsecret, roboxtractor, xalgorix

HTTP probing / crawling / web discovery
  httpx, httpx2, katana, hakrawler, ffuf, feroxbuster, gobuster, dirsearch,
  gowitness, whatweb, nikto, paramspider, Web-Cache-Vulnerability-Scanner,
  toxicache, misconfig-mapper, cmseek, tlsx, interactsh-client, notify

Web vulnerability testing
  nuclei, sqlmap, dalfox, kxss, Gxss, crlfuzz, flask-unsign, sisakulint,
  semgrep, pysemgrep, detect-secrets, betterleaks, trufflehog, gitleaks,
  kingfisher, s3scanner, cloudfox, grype, gosec

Network scanning
  nmap, masscan, rustscan, naabu, nping, ncat, nc, tshark, sharkd,
  randpkt, sshuttle

OSINT
  sherlock
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlencode, urlparse

from .models import Category, Finding, Severity

Emit = Optional[Callable[[str], None]]

SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}

# ---------------------------------------------------------------------------
# Full tool catalog
# ---------------------------------------------------------------------------

TOOL_CATALOG: dict[str, str] = {
    # --- Recon / asset discovery ---
    "amass": "OWASP Amass – subdomain & asset enumeration",
    "assetfinder": "Find related domains and subdomains",
    "findomain": "Fast subdomain finder",
    "subfinder": "Passive subdomain discovery (ProjectDiscovery)",
    "subdomainx": "Subdomain enumeration & takeover checks",
    "chaos": "ProjectDiscovery Chaos dataset client",
    "metabigor": "OSINT intelligence gathering",
    "shodan": "Shodan CLI / API search",
    "crtsh": "Certificate Transparency lookup (crt.sh API)",
    "certstream": "Live Certificate Transparency stream client",
    "tldbrute": "TLD / domain brute helper",
    "tldextract": "Extract registrable domain (Python lib / CLI)",
    "waybackurls": "Fetch URLs from the Wayback Machine",
    "waymore": "Expanded Wayback / CommonCrawl URL harvest",
    "gau": "Get All URLs (AlienVault, Wayback, CommonCrawl…)",
    "urlfinder": "URL extraction from responses / archives",
    "dnsgen": "DNS name permutation generator",
    "enumerepo": "Enumerate public GitHub/GitLab repos",
    "hakrevdns": "Reverse DNS lookup helper",
    "hakoriginfinder": "Discover origin IPs behind CDNs",
    "hakip2host": "IP → hostname resolution",
    "asnmap": "ASN → IP range mapping",
    "cdncheck": "Detect CDN fronting",
    "mapcidr": "CIDR expansion / manipulation",
    "puredns": "Fast DNS resolution & brute force",
    "shuffledns": "MassDNS wrapper with wildcard filtering",
    "massdns": "High-performance DNS stub resolver",
    "dnsx": "DNS toolkit (resolve, wildcard, etc.)",
    "httpx": "HTTP probe / tech detect (ProjectDiscovery)",
    "alterx": "Subdomain wordlist permutation",
    "anew": "Append unique lines to a file",
    "gf": "grep patterns for sensitive endpoints",
    "qsreplace": "Query-string parameter replace",
    "dsieve": "Domain sieve / filter",
    "smap": "Passive port scanner (Shodan-based)",
    "nmapurls": "Generate URLs from nmap output",
    "jsfinder2": "JavaScript endpoint / secret finder",
    "jsleak": "JS secret / leak scanner",
    "jsecret": "JavaScript secret extraction",
    "roboxtractor": "robots.txt path extractor",
    "xalgorix": "Algorithm / pattern discovery helper",
    # --- HTTP / web discovery ---
    "httpx2": "Alternate / extended httpx frontend",
    "katana": "Next-gen crawling & spidering",
    "hakrawler": "Simple web crawler for endpoints",
    "ffuf": "Fast web fuzzer",
    "feroxbuster": "Recursive content discovery",
    "gobuster": "Directory / DNS / vhost brute force",
    "dirsearch": "Web path scanner",
    "gowitness": "Screenshot & HTTP archive capture",
    "whatweb": "Web technology fingerprinting",
    "nikto": "Web server vulnerability scanner",
    "paramspider": "Parameter mining from archives",
    "wcvs": "Web-Cache-Vulnerability-Scanner",
    "toxicache": "Web cache poisoning helper",
    "misconfig-mapper": "Cloud / service misconfiguration mapper",
    "cmseek": "CMS detection & exploitation helper",
    "tlsx": "TLS handshake / cert inspection",
    "interactsh-client": "OAST / interactsh client",
    "notify": "Notification helper for findings",
    # --- Vuln testing ---
    "nuclei": "Template-based vulnerability scanner",
    "sqlmap": "Automatic SQL injection tool",
    "dalfox": "XSS scanning & parameter analysis",
    "kxss": "Reflected XSS parameter finder",
    "Gxss": "XSS parameter reflection checker",
    "crlfuzz": "CRLF injection fuzzer",
    "flask-unsign": "Flask session cookie unsigner",
    "sisakulint": "GitHub Actions workflow linter",
    "semgrep": "Static analysis / SAST",
    "pysemgrep": "Python Semgrep frontend",
    "detect-secrets": "Secret scanning (Yelp)",
    "betterleaks": "Secret / leak detection",
    "trufflehog": "Git / filesystem secret scanning",
    "gitleaks": "Git secret scanning",
    "kingfisher": "Cloud secret / misconfig scanner",
    "s3scanner": "Open S3 bucket scanner",
    "cloudfox": "AWS / cloud enumeration",
    "grype": "Container / filesystem vulnerability scan",
    "gosec": "Go source security checker",
    # --- Network ---
    "nmap": "Network mapper / port scanner",
    "masscan": "Very fast port scanner",
    "rustscan": "Modern fast port scanner",
    "naabu": "Port scanning (ProjectDiscovery)",
    "nping": "Packet generation / response analysis",
    "ncat": "Nmap's netcat",
    "nc": "netcat",
    "tshark": "Wireshark CLI packet analyzer",
    "sharkd": "Wireshark daemon mode",
    "randpkt": "Random packet generator",
    "sshuttle": "Transparent proxy / VPN over SSH",
    # --- OSINT ---
    "sherlock": "Username search across social networks",
}


# Logical groups for --tool-group filtering
TOOL_GROUPS: dict[str, frozenset[str]] = {
    "recon": frozenset({
        "amass", "assetfinder", "findomain", "subfinder", "subdomainx", "chaos",
        "metabigor", "shodan", "crtsh", "certstream", "tldbrute", "tldextract",
        "waybackurls", "waymore", "gau", "urlfinder", "dnsgen", "enumerepo",
        "hakrevdns", "hakoriginfinder", "hakip2host", "asnmap", "cdncheck",
        "mapcidr", "puredns", "shuffledns", "massdns", "dnsx", "alterx", "anew",
        "gf", "qsreplace", "dsieve", "smap", "nmapurls", "jsfinder2", "jsleak",
        "jsecret", "roboxtractor", "xalgorix",
    }),
    "http": frozenset({
        "httpx", "httpx2", "katana", "hakrawler", "ffuf", "feroxbuster",
        "gobuster", "dirsearch", "gowitness", "whatweb", "nikto", "paramspider",
        "wcvs", "toxicache", "misconfig-mapper", "cmseek", "tlsx",
        "interactsh-client", "notify",
    }),
    "vuln": frozenset({
        "nuclei", "sqlmap", "dalfox", "kxss", "Gxss", "crlfuzz", "flask-unsign",
        "sisakulint", "semgrep", "pysemgrep", "detect-secrets", "betterleaks",
        "trufflehog", "gitleaks", "kingfisher", "s3scanner", "cloudfox", "grype",
        "gosec",
    }),
    "network": frozenset({
        "nmap", "masscan", "rustscan", "naabu", "nping", "ncat", "nc", "tshark",
        "sharkd", "randpkt", "sshuttle",
    }),
    "osint": frozenset({"sherlock"}),
}


def groups_enabled(requested: list[str] | None) -> set[str]:
    """Normalize --tool-group values into the set of active group names."""
    if not requested:
        return set(TOOL_GROUPS.keys())
    norm = {g.strip().lower() for g in requested if g and g.strip()}
    if not norm or "all" in norm:
        return set(TOOL_GROUPS.keys())
    unknown = norm - set(TOOL_GROUPS.keys())
    return (norm & set(TOOL_GROUPS.keys())) or set(TOOL_GROUPS.keys())


def tool_in_groups(name: str, enabled: set[str]) -> bool:
    for g in enabled:
        if name in TOOL_GROUPS.get(g, ()):
            return True
    return False


# Tools we actively try during a scan (everything else is still in the
# catalog for status banners; runners exist for all).
ACTIVE_RUNNERS: tuple[str, ...] = tuple(TOOL_CATALOG.keys())

# Binary name overrides when the catalog key differs from argv[0]
BINARY_ALIASES: dict[str, str] = {
    "crtsh": "curl",  # API via curl/httpx; special-cased
    "wcvs": "Web-Cache-Vulnerability-Scanner",
    "httpx2": "httpx",
}


def tool_available(name: str) -> bool:
    if name == "crtsh":
        return True  # pure HTTP API
    binary = BINARY_ALIASES.get(name, name)
    return shutil.which(binary) is not None


def available_tools() -> list[str]:
    return [n for n in TOOL_CATALOG if tool_available(n)]


def missing_tools_note(names: tuple[str, ...] | None = None) -> list[str]:
    check = names or ACTIVE_RUNNERS
    return [name for name in check if not tool_available(name)]


def host_from_url(url: str) -> str:
    return urlparse(url).hostname or url


def registerable_domain(host: str) -> str:
    if not host or host.replace(".", "").isdigit():
        return host
    parts = host.strip(".").lower().split(".")
    if len(parts) <= 2:
        return host
    multi = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "net.au"}
    tail2 = ".".join(parts[-2:])
    if tail2 in multi and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


async def _run(
    cmd: list[str],
    timeout: float,
    emit: Emit = None,
    tool_label: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    label = tool_label or (cmd[0] if cmd else "tool")
    if emit:
        shown = " ".join(cmd[:8])
        if len(cmd) > 8:
            shown += "…"
        emit(f"  → using tool: {label}  ({shown})")
    full_env = None
    if env:
        full_env = {**os.environ, **env}
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=full_env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        if emit:
            emit(f"  ✗ {label} timed out after {timeout}s")
        return -1, "", f"timed out after {timeout}s"
    code = proc.returncode or 0
    if emit:
        status = "ok" if code == 0 else f"exit {code}"
        emit(f"  ✓ {label} finished ({status})")
    return code, out.decode(errors="replace"), err.decode(errors="replace")


def _skip(name: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  · skipping {name} (not installed)")
    return []


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _http_urls(text: str) -> list[str]:
    return sorted({ln for ln in _lines(text) if ln.startswith("http")})


def _hosts(text: str, domain: str | None = None) -> list[str]:
    out: set[str] = set()
    for ln in _lines(text):
        # strip scheme if present
        h = ln
        if "://" in h:
            h = urlparse(h).hostname or h
        h = h.split()[0].strip().lower().rstrip(".")
        if not h or " " in h:
            continue
        if domain and domain not in h:
            continue
        if "." in h:
            out.add(h)
    return sorted(out)


def _recon_finding(
    module: str,
    title: str,
    url: str,
    description: str,
    evidence: str,
    extracted: list[str] | None = None,
    severity: Severity = Severity.INFO,
    category: Category = Category.RECON,
) -> Finding:
    return Finding(
        category=category,
        title=title,
        severity=severity,
        confidence="firm",
        url=url,
        description=description,
        evidence=evidence[:2000],
        module=module,
        verified=True,
        extracted_data=(extracted or [])[:300],
    )


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


async def _run_line_tool(
    name: str,
    cmd: list[str],
    *,
    timeout: float,
    emit: Emit,
    domain_or_url: str,
    title_prefix: str,
    description: str,
    filter_http: bool = False,
    filter_hosts: bool = False,
    domain_filter: str | None = None,
    category: Category = Category.RECON,
    severity: Severity = Severity.INFO,
) -> tuple[list[str], list[Finding]]:
    if not tool_available(name):
        return [], _skip(name, emit)
    code, out, err = await _run(cmd, timeout, emit, name)
    if filter_http:
        items = _http_urls(out)
    elif filter_hosts:
        items = _hosts(out, domain_filter)
    else:
        items = _lines(out)
    findings: list[Finding] = []
    if items:
        findings.append(
            _recon_finding(
                name,
                f"[{name}] {title_prefix} ({len(items)})",
                domain_or_url,
                description,
                "\n".join(items[:50]),
                items,
                severity=severity,
                category=category,
            )
        )
    elif emit and (out or err) and code not in (0,):
        emit(f"  · {name}: no parseable results (stderr: {err[:120]!r})")
    return items, findings


# ---------------------------------------------------------------------------
# Recon runners
# ---------------------------------------------------------------------------


async def run_subfinder(domain: str, timeout: float = 180, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "subfinder",
        ["subfinder", "-d", domain, "-silent"],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="subdomains discovered",
        description="Passive subdomain enumeration via ProjectDiscovery subfinder.",
        filter_hosts=True,
        domain_filter=domain,
    )


async def run_amass(domain: str, timeout: float = 300, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "amass",
        ["amass", "enum", "-passive", "-d", domain, "-silent"],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="subdomains discovered (passive)",
        description="Passive asset enumeration via OWASP Amass.",
        filter_hosts=True,
        domain_filter=domain,
    )


async def run_assetfinder(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "assetfinder",
        ["assetfinder", "--subs-only", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="subdomains discovered",
        description="Related domain / subdomain discovery via assetfinder.",
        filter_hosts=True,
        domain_filter=domain,
    )


async def run_findomain(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "findomain",
        ["findomain", "-t", domain, "-q"],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="subdomains discovered",
        description="Fast subdomain discovery via findomain.",
        filter_hosts=True,
        domain_filter=domain,
    )


async def run_subdomainx(domain: str, timeout: float = 180, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "subdomainx",
        ["subdomainx", "-d", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="subdomains / takeover candidates",
        description="Subdomain enumeration and takeover checks via subdomainx.",
        filter_hosts=True,
        domain_filter=domain,
    )


async def run_chaos(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    # chaos requires CHAOS_KEY; still attempt so the operator sees the call
    return await _run_line_tool(
        "chaos",
        ["chaos", "-d", domain, "-silent"],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="subdomains from Chaos dataset",
        description="ProjectDiscovery Chaos dataset lookup (needs CHAOS_KEY).",
        filter_hosts=True,
        domain_filter=domain,
    )


async def run_metabigor(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "metabigor",
        ["metabigor", "net", "--domain", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="OSINT / net intelligence",
        description="OSINT intelligence gathering via metabigor.",
    )


async def run_shodan(host: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    if not tool_available("shodan"):
        return _skip("shodan", emit)
    cmd = ["shodan", "host", host]
    code, out, err = await _run(cmd, timeout, emit, "shodan")
    if not out.strip():
        return []
    return [
        _recon_finding(
            "shodan",
            f"[shodan] host intel for {host}",
            host,
            "Shodan host lookup.",
            out[:1500],
            _lines(out)[:50],
        )
    ]


async def run_crtsh(domain: str, timeout: float = 60, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    """Certificate Transparency via crt.sh JSON API (no binary required)."""
    if emit:
        emit(f"  → using tool: crtsh  (https://crt.sh/?q=%25.{domain}&output=json)")
    try:
        import urllib.request

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "bughound/1.11"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="replace")
        data = json.loads(body) if body.strip() else []
        subs: set[str] = set()
        for row in data if isinstance(data, list) else []:
            name = (row.get("name_value") or "").lower()
            for part in name.split("\n"):
                part = part.strip().lstrip("*.")
                if part.endswith(domain) and "*" not in part:
                    subs.add(part)
        items = sorted(subs)
        if emit:
            emit(f"  ✓ crtsh finished (ok, {len(items)} names)")
        findings: list[Finding] = []
        if items:
            findings.append(
                _recon_finding(
                    "crtsh",
                    f"[crtsh] {len(items)} name(s) from Certificate Transparency",
                    domain,
                    "crt.sh CT log query.",
                    "\n".join(items[:50]),
                    items,
                )
            )
        return items, findings
    except Exception as exc:  # noqa: BLE001
        if emit:
            emit(f"  ✗ crtsh failed: {exc}")
        return [], []


async def run_certstream(domain: str, timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("certstream"):
        return _skip("certstream", emit)
    # certstream is typically a long-lived stream; do a short bounded sample
    cmd = ["certstream", "--json"]
    code, out, err = await _run(cmd, timeout, emit, "certstream")
    matches = [ln for ln in _lines(out) if domain in ln.lower()]
    if not matches:
        return []
    return [
        _recon_finding(
            "certstream",
            f"[certstream] live CT hits for {domain}",
            domain,
            "Live Certificate Transparency stream sample.",
            "\n".join(matches[:30]),
            matches[:100],
        )
    ]


async def run_tldbrute(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "tldbrute",
        ["tldbrute", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="TLD brute results",
        description="TLD / domain brute-force helper.",
        filter_hosts=True,
    )


async def run_tldextract(domain: str, timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("tldextract"):
        # try python module
        try:
            import tldextract as _tld  # type: ignore

            if emit:
                emit(f"  → using tool: tldextract  (python module on {domain})")
            ext = _tld.extract(domain)
            reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain
            if emit:
                emit("  ✓ tldextract finished (ok)")
            return [
                _recon_finding(
                    "tldextract",
                    f"[tldextract] registrable domain = {reg}",
                    domain,
                    "Registrable domain extraction.",
                    reg,
                    [reg, ext.subdomain or "", ext.domain or "", ext.suffix or ""],
                )
            ]
        except Exception:
            return _skip("tldextract", emit)
    return (
        await _run_line_tool(
            "tldextract",
            ["tldextract", domain],
            timeout=timeout,
            emit=emit,
            domain_or_url=domain,
            title_prefix="registrable domain",
            description="tldextract CLI output.",
        )
    )[1]


async def run_waybackurls(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "waybackurls",
        ["waybackurls", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="archived URLs",
        description="URLs from the Internet Archive Wayback Machine.",
        filter_http=True,
    )


async def run_waymore(domain: str, timeout: float = 300, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if not tool_available("waymore"):
        return [], _skip("waymore", emit)
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "urls.txt"
        cmd = ["waymore", "-i", domain, "-mode", "U", "-oU", str(out_path)]
        code, out, err = await _run(cmd, timeout, emit, "waymore")
        urls: list[str] = []
        if out_path.exists():
            urls = _http_urls(out_path.read_text(errors="replace"))
    findings: list[Finding] = []
    if urls:
        findings.append(
            _recon_finding(
                "waymore",
                f"[waymore] {len(urls)} historical URL(s)",
                domain,
                "Expanded historical URL harvest (Wayback + CommonCrawl + more).",
                "\n".join(urls[:50]),
                urls,
            )
        )
    return urls, findings


async def run_gau(domain: str, timeout: float = 180, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "gau",
        ["gau", "--subs", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="historical URLs",
        description="URLs from AlienVault OTX, Wayback, CommonCrawl, etc.",
        filter_http=True,
    )


async def run_urlfinder(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "urlfinder",
        ["urlfinder", "-d", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="URLs extracted",
        description="URL extraction via urlfinder.",
        filter_http=True,
    )


async def run_dnsgen(domain: str, timeout: float = 60, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if not tool_available("dnsgen"):
        return [], _skip("dnsgen", emit)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(domain + "\n")
        path = fh.name
    try:
        cmd = ["dnsgen", path]
        code, out, err = await _run(cmd, timeout, emit, "dnsgen")
    finally:
        Path(path).unlink(missing_ok=True)
    items = _hosts(out)
    findings: list[Finding] = []
    if items:
        findings.append(
            _recon_finding(
                "dnsgen",
                f"[dnsgen] {len(items)} permuted name(s)",
                domain,
                "DNS name permutations.",
                "\n".join(items[:50]),
                items,
            )
        )
    return items, findings


async def run_enumerepo(domain: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "enumerepo",
        ["enumerepo", "-t", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="public repositories",
        description="Public GitHub/GitLab repo enumeration.",
    )
    return findings


async def run_hakrevdns(ip_or_host: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "hakrevdns",
        ["hakrevdns", ip_or_host],
        timeout=timeout,
        emit=emit,
        domain_or_url=ip_or_host,
        title_prefix="reverse DNS results",
        description="Reverse DNS via hakrevdns.",
        filter_hosts=True,
    )
    return findings


async def run_hakoriginfinder(host: str, timeout: float = 90, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "hakoriginfinder",
        ["hakoriginfinder", "-s", host],
        timeout=timeout,
        emit=emit,
        domain_or_url=host,
        title_prefix="origin IP candidates",
        description="Origin IP discovery behind CDNs.",
    )
    return findings


async def run_hakip2host(ip: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "hakip2host",
        ["hakip2host", ip],
        timeout=timeout,
        emit=emit,
        domain_or_url=ip,
        title_prefix="IP→host mappings",
        description="IP to hostname resolution.",
        filter_hosts=True,
    )
    return findings


async def run_asnmap(host: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "asnmap",
        ["asnmap", "-d", host, "-silent"],
        timeout=timeout,
        emit=emit,
        domain_or_url=host,
        title_prefix="ASN / IP ranges",
        description="ASN and related IP ranges from asnmap.",
    )
    return findings


async def run_cdncheck(host: str, timeout: float = 30, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "cdncheck",
        ["cdncheck", "-i", host, "-silent"],
        timeout=timeout,
        emit=emit,
        domain_or_url=host,
        title_prefix="CDN detection",
        description="CDN / WAF fronting detection.",
    )
    return findings


async def run_mapcidr(cidr: str, timeout: float = 30, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "mapcidr",
        ["mapcidr", "-cidr", cidr],
        timeout=timeout,
        emit=emit,
        domain_or_url=cidr,
        title_prefix="expanded addresses",
        description="CIDR expansion via mapcidr.",
    )
    return findings


async def run_puredns(domain: str, wordlist: list[str] | None = None, timeout: float = 180, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if not tool_available("puredns"):
        return [], _skip("puredns", emit)
    wl = wordlist or ["www", "mail", "api", "dev", "staging", "admin", "test", "vpn", "cdn"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for w in wl:
            fh.write(f"{w}.{domain}\n")
        path = fh.name
    try:
        cmd = ["puredns", "resolve", path, "-q"]
        code, out, err = await _run(cmd, timeout, emit, "puredns")
    finally:
        Path(path).unlink(missing_ok=True)
    items = _hosts(out, domain)
    findings: list[Finding] = []
    if items:
        findings.append(
            _recon_finding(
                "puredns",
                f"[puredns] {len(items)} resolved name(s)",
                domain,
                "Fast DNS resolution via puredns.",
                "\n".join(items[:50]),
                items,
            )
        )
    return items, findings


async def run_shuffledns(domain: str, timeout: float = 180, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "shuffledns",
        ["shuffledns", "-d", domain, "-silent"],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="resolved names",
        description="MassDNS wrapper with wildcard filtering.",
        filter_hosts=True,
        domain_filter=domain,
    )


async def run_massdns(domain: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if not tool_available("massdns"):
        return [], _skip("massdns", emit)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for w in ("www", "mail", "api", "dev", "admin"):
            fh.write(f"{w}.{domain}\n")
        path = fh.name
    try:
        cmd = ["massdns", "-r", "/dev/null", "-o", "S", path]
        code, out, err = await _run(cmd, timeout, emit, "massdns")
    finally:
        Path(path).unlink(missing_ok=True)
    items = _hosts(out, domain)
    findings: list[Finding] = []
    if items:
        findings.append(
            _recon_finding(
                "massdns",
                f"[massdns] {len(items)} resolution(s)",
                domain,
                "High-performance DNS stub resolver output.",
                "\n".join(items[:50]),
                items,
            )
        )
    return items, findings


async def run_dnsx(hosts: list[str], timeout: float = 120, emit: Emit = None) -> list[Finding]:
    if not tool_available("dnsx") or not hosts:
        return _skip("dnsx", emit) if not tool_available("dnsx") else []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for h in hosts[:1000]:
            fh.write(h.rstrip() + "\n")
        path = fh.name
    try:
        cmd = ["dnsx", "-l", path, "-silent", "-a", "-resp"]
        code, out, err = await _run(cmd, timeout, emit, "dnsx")
    finally:
        Path(path).unlink(missing_ok=True)
    resolved = _lines(out)
    if not resolved:
        return []
    return [
        _recon_finding(
            "dnsx",
            f"[dnsx] {len(resolved)} DNS resolution(s)",
            hosts[0],
            "DNS resolution results from dnsx.",
            "\n".join(resolved[:40]),
            resolved,
        )
    ]


async def run_alterx(domain: str, timeout: float = 60, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "alterx",
        ["alterx", "-l", domain, "-silent"],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="permuted subdomains",
        description="Subdomain wordlist permutation via alterx.",
        filter_hosts=True,
    )


async def run_anew(lines_in: list[str], timeout: float = 30, emit: Emit = None) -> list[str]:
    """Utility: dedupe lines via anew (returns unique list)."""
    if not tool_available("anew") or not lines_in:
        if emit and not tool_available("anew"):
            emit("  · skipping anew (not installed)")
        return list(dict.fromkeys(lines_in))
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for ln in lines_in:
            fh.write(ln.rstrip() + "\n")
        path = fh.name
    try:
        cmd = ["anew", path]
        # anew typically reads stdin; feed via echo pipeline approximation
        code, out, err = await _run(["bash", "-c", f"cat {path} | anew -"], timeout, emit, "anew")
    finally:
        Path(path).unlink(missing_ok=True)
    return _lines(out) or list(dict.fromkeys(lines_in))


async def run_gf(urls: list[str], pattern: str = "ssrf", timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("gf") or not urls:
        return _skip("gf", emit) if not tool_available("gf") else []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for u in urls[:2000]:
            fh.write(u.rstrip() + "\n")
        path = fh.name
    try:
        code, out, err = await _run(
            ["bash", "-c", f"cat {path} | gf {pattern}"],
            timeout,
            emit,
            "gf",
        )
    finally:
        Path(path).unlink(missing_ok=True)
    hits = _lines(out)
    if not hits:
        return []
    return [
        _recon_finding(
            "gf",
            f"[gf] {len(hits)} URL(s) matching pattern '{pattern}'",
            urls[0],
            f"gf pattern filter ({pattern}).",
            "\n".join(hits[:50]),
            hits,
        )
    ]


async def run_qsreplace(urls: list[str], payload: str = "FUZZ", timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("qsreplace") or not urls:
        return _skip("qsreplace", emit) if not tool_available("qsreplace") else []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for u in urls[:500]:
            fh.write(u.rstrip() + "\n")
        path = fh.name
    try:
        code, out, err = await _run(
            ["bash", "-c", f"cat {path} | qsreplace {payload}"],
            timeout,
            emit,
            "qsreplace",
        )
    finally:
        Path(path).unlink(missing_ok=True)
    items = _http_urls(out) or _lines(out)
    if not items:
        return []
    return [
        _recon_finding(
            "qsreplace",
            f"[qsreplace] {len(items)} parameterised URL(s)",
            urls[0],
            "Query-string parameter replacement.",
            "\n".join(items[:40]),
            items,
        )
    ]


async def run_dsieve(domains: list[str], timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("dsieve") or not domains:
        return _skip("dsieve", emit) if not tool_available("dsieve") else []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for d in domains[:2000]:
            fh.write(d.rstrip() + "\n")
        path = fh.name
    try:
        code, out, err = await _run(
            ["bash", "-c", f"cat {path} | dsieve"],
            timeout,
            emit,
            "dsieve",
        )
    finally:
        Path(path).unlink(missing_ok=True)
    items = _lines(out)
    if not items:
        return []
    return [
        _recon_finding(
            "dsieve",
            f"[dsieve] {len(items)} filtered domain(s)",
            domains[0],
            "Domain sieve / filter results.",
            "\n".join(items[:40]),
            items,
        )
    ]


async def run_smap(host: str, timeout: float = 90, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "smap",
        ["smap", host],
        timeout=timeout,
        emit=emit,
        domain_or_url=host,
        title_prefix="passive ports",
        description="Passive port scan (Shodan-based) via smap.",
    )
    return findings


async def run_nmapurls(nmap_out: str, timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("nmapurls"):
        return _skip("nmapurls", emit)
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as fh:
        fh.write(nmap_out or "")
        path = fh.name
    try:
        code, out, err = await _run(["nmapurls", path], timeout, emit, "nmapurls")
    finally:
        Path(path).unlink(missing_ok=True)
    urls = _http_urls(out)
    if not urls:
        return []
    return [
        _recon_finding(
            "nmapurls",
            f"[nmapurls] {len(urls)} URL(s) from nmap",
            urls[0],
            "URLs derived from nmap output.",
            "\n".join(urls[:40]),
            urls,
        )
    ]


async def run_jsfinder2(url: str, timeout: float = 90, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "jsfinder2",
        ["jsfinder2", "-u", url],
        timeout=timeout,
        emit=emit,
        domain_or_url=url,
        title_prefix="JS endpoints / secrets",
        description="JavaScript endpoint and secret finder.",
    )
    return findings


async def run_jsleak(url: str, timeout: float = 90, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "jsleak",
        ["jsleak", "-u", url],
        timeout=timeout,
        emit=emit,
        domain_or_url=url,
        title_prefix="JS leaks",
        description="JavaScript secret / leak scanner.",
        category=Category.INFO_DISCLOSURE,
        severity=Severity.MEDIUM,
    )
    return findings


async def run_jsecret(url: str, timeout: float = 90, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "jsecret",
        ["jsecret", url],
        timeout=timeout,
        emit=emit,
        domain_or_url=url,
        title_prefix="JS secrets",
        description="JavaScript secret extraction.",
        category=Category.CRYPTO,
        severity=Severity.MEDIUM,
    )
    return findings


async def run_roboxtractor(url: str, timeout: float = 30, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "roboxtractor",
        ["roboxtractor", "-u", url],
        timeout=timeout,
        emit=emit,
        domain_or_url=url,
        title_prefix="robots.txt paths",
        description="Paths extracted from robots.txt.",
    )
    return findings


async def run_xalgorix(target: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "xalgorix",
        ["xalgorix", target],
        timeout=timeout,
        emit=emit,
        domain_or_url=target,
        title_prefix="algorithm / pattern hits",
        description="Algorithm / pattern discovery helper.",
    )
    return findings


# ---------------------------------------------------------------------------
# HTTP / crawl / web discovery
# ---------------------------------------------------------------------------


async def run_httpx_probe(urls: list[str], timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("httpx") or not urls:
        return _skip("httpx", emit) if not tool_available("httpx") else []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for u in urls[:500]:
            fh.write(u.rstrip() + "\n")
        path = fh.name
    try:
        cmd = ["httpx", "-l", path, "-silent", "-status-code", "-title", "-tech-detect", "-json"]
        code, out, err = await _run(cmd, timeout, emit, "httpx")
    finally:
        Path(path).unlink(missing_ok=True)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = j.get("url") or j.get("input") or ""
        status = j.get("status_code") or j.get("status-code")
        title = j.get("title") or ""
        techs = j.get("tech") or j.get("technologies") or []
        if isinstance(techs, str):
            techs = [techs]
        evidence_parts = [f"status={status}", f"title={title!r}"]
        if techs:
            evidence_parts.append("tech=" + ", ".join(str(t) for t in techs[:8]))
        findings.append(
            _recon_finding(
                "httpx",
                f"[httpx] live host {url} ({status})",
                url or urls[0],
                "HTTP probe confirmed a live endpoint.",
                "; ".join(evidence_parts),
                [url] if url else [],
            )
        )
    return findings


async def run_httpx2(urls: list[str], timeout: float = 180, emit: Emit = None) -> list[Finding]:
    """Alias frontend; uses the same httpx binary if present."""
    if not tool_available("httpx2") and not tool_available("httpx"):
        return _skip("httpx2", emit)
    if emit:
        emit("  → using tool: httpx2  (httpx-compatible probe)")
    return await run_httpx_probe(urls, timeout=timeout, emit=emit)


async def run_katana(base_url: str, timeout: float = 180, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "katana",
        ["katana", "-u", base_url, "-silent", "-d", "2", "-jc"],
        timeout=timeout,
        emit=emit,
        domain_or_url=base_url,
        title_prefix="URLs crawled",
        description="Crawl results from ProjectDiscovery katana.",
        filter_http=True,
    )


async def run_hakrawler(base_url: str, timeout: float = 120, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "hakrawler",
        ["hakrawler", "-url", base_url, "-plain"],
        timeout=timeout,
        emit=emit,
        domain_or_url=base_url,
        title_prefix="endpoints crawled",
        description="Simple web crawler for endpoints (hakrawler).",
        filter_http=True,
    )


async def run_ffuf(base_url: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("ffuf"):
        return _skip("ffuf", emit)
    # Minimal wordlist for safe discovery
    words = ["admin", "login", "api", "backup", "config", "dashboard", "debug", "test", "uploads", "static"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(words) + "\n")
        path = fh.name
    try:
        target = base_url.rstrip("/") + "/FUZZ"
        cmd = ["ffuf", "-u", target, "-w", path, "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", "/dev/stdout", "-s"]
        code, out, err = await _run(cmd, timeout, emit, "ffuf")
    finally:
        Path(path).unlink(missing_ok=True)
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip().startswith("{") else {}
        results = data.get("results") or []
    except json.JSONDecodeError:
        results = []
    for r in results[:40]:
        url = r.get("url") or base_url
        status = r.get("status")
        findings.append(
            _recon_finding(
                "ffuf",
                f"[ffuf] {url} ({status})",
                url,
                "Content discovery hit from ffuf.",
                json.dumps(r)[:400],
                [url],
            )
        )
    return findings


async def run_feroxbuster(base_url: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("feroxbuster"):
        return _skip("feroxbuster", emit)
    words = ["admin", "login", "api", "backup", "config", "dashboard", "debug", "test"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(words) + "\n")
        path = fh.name
    try:
        cmd = ["feroxbuster", "-u", base_url, "-w", path, "-q", "--json"]
        code, out, err = await _run(cmd, timeout, emit, "feroxbuster")
    finally:
        Path(path).unlink(missing_ok=True)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = j.get("url") or base_url
        status = j.get("status") or j.get("status_code")
        findings.append(
            _recon_finding(
                "feroxbuster",
                f"[feroxbuster] {url} ({status})",
                url,
                "Recursive content discovery hit.",
                json.dumps(j)[:400],
                [url],
            )
        )
    return findings


async def run_gobuster(base_url: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("gobuster"):
        return _skip("gobuster", emit)
    words = ["admin", "login", "api", "backup", "config", "dashboard", "debug", "test"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(words) + "\n")
        path = fh.name
    try:
        cmd = ["gobuster", "dir", "-u", base_url, "-w", path, "-q", "-o", "/dev/stdout"]
        code, out, err = await _run(cmd, timeout, emit, "gobuster")
    finally:
        Path(path).unlink(missing_ok=True)
    hits = _lines(out)
    if not hits:
        return []
    return [
        _recon_finding(
            "gobuster",
            f"[gobuster] {len(hits)} path(s)",
            base_url,
            "Directory / path brute force results.",
            "\n".join(hits[:40]),
            hits,
        )
    ]


async def run_dirsearch(base_url: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("dirsearch"):
        return _skip("dirsearch", emit)
    cmd = ["dirsearch", "-u", base_url, "--format=json", "-q"]
    code, out, err = await _run(cmd, timeout, emit, "dirsearch")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip().startswith("{") or out.strip().startswith("[") else {}
    except json.JSONDecodeError:
        data = {}
    results = data.get("results") or data if isinstance(data, list) else []
    if isinstance(results, dict):
        results = list(results.values()) if results else []
    for r in (results or [])[:40]:
        if not isinstance(r, dict):
            continue
        url = r.get("url") or r.get("path") or base_url
        findings.append(
            _recon_finding(
                "dirsearch",
                f"[dirsearch] {url}",
                str(url),
                "Web path scanner hit.",
                json.dumps(r)[:400],
                [str(url)],
            )
        )
    if not findings and out:
        hits = [ln for ln in _lines(out) if "200" in ln or "301" in ln or "302" in ln]
        if hits:
            findings.append(
                _recon_finding(
                    "dirsearch",
                    f"[dirsearch] {len(hits)} path(s)",
                    base_url,
                    "Web path scanner results.",
                    "\n".join(hits[:40]),
                    hits,
                )
            )
    return findings


async def run_gowitness(url: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    if not tool_available("gowitness"):
        return _skip("gowitness", emit)
    with tempfile.TemporaryDirectory() as tmp:
        cmd = ["gowitness", "single", url, "--disable-db", "-D", tmp]
        code, out, err = await _run(cmd, timeout, emit, "gowitness")
        shots = list(Path(tmp).glob("**/*"))
    return [
        _recon_finding(
            "gowitness",
            f"[gowitness] screenshot capture for {url}",
            url,
            f"HTTP archive / screenshot attempt ({len(shots)} file(s) written).",
            out[:500] or err[:500] or "gowitness completed",
            [str(p.name) for p in shots[:20]],
        )
    ]


async def run_whatweb(url: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    if not tool_available("whatweb"):
        return _skip("whatweb", emit)
    cmd = ["whatweb", "--log-json=-", "-a", "1", url]
    code, out, err = await _run(cmd, timeout, emit, "whatweb")
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        plugins = j.get("plugins") or {}
        names = list(plugins.keys())[:30]
        if names:
            findings.append(
                _recon_finding(
                    "whatweb",
                    f"[whatweb] tech fingerprint ({len(names)} plugins)",
                    url,
                    "Technology fingerprint via WhatWeb.",
                    ", ".join(names),
                    names,
                )
            )
    return findings


async def run_nikto(url: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("nikto"):
        return _skip("nikto", emit)
    cmd = ["nikto", "-h", url, "-Format", "json", "-output", "-"]
    code, out, err = await _run(cmd, timeout, emit, "nikto")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip().startswith(("{", "[")) else None
    except json.JSONDecodeError:
        data = None
    vulnerabilities = []
    if isinstance(data, dict):
        vulnerabilities = data.get("vulnerabilities") or data.get("items") or []
    elif isinstance(data, list):
        vulnerabilities = data
    for item in vulnerabilities[:40]:
        if not isinstance(item, dict):
            continue
        msg = item.get("msg") or item.get("message") or str(item)
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[nikto] {msg[:80]}",
                severity=Severity.LOW,
                confidence="tentative",
                url=url,
                description=msg,
                evidence=json.dumps(item)[:600],
                module="nikto",
                verified=False,
            )
        )
    if not findings and out:
        for line in out.splitlines():
            if "+ " in line and ("OSVDB" in line or "CVE" in line or "interesting" in line.lower()):
                findings.append(
                    Finding(
                        category=Category.MISCONFIG,
                        title=f"[nikto] {line.strip()[:80]}",
                        severity=Severity.LOW,
                        confidence="tentative",
                        url=url,
                        description=line.strip(),
                        evidence=line.strip(),
                        module="nikto",
                        verified=False,
                    )
                )
    return findings


async def run_paramspider(domain: str, timeout: float = 180, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    return await _run_line_tool(
        "paramspider",
        ["paramspider", "-d", domain],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="parameterised URLs",
        description="Parameter mining from archives via paramspider.",
        filter_http=True,
    )


async def run_wcvs(url: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    binary = BINARY_ALIASES.get("wcvs", "Web-Cache-Vulnerability-Scanner")
    if not shutil.which(binary) and not shutil.which("wcvs"):
        return _skip("wcvs", emit)
    bin_name = binary if shutil.which(binary) else "wcvs"
    cmd = [bin_name, "-u", url]
    code, out, err = await _run(cmd, timeout, emit, "wcvs")
    hits = _lines(out)
    if not hits:
        return []
    return [
        Finding(
            category=Category.MISCONFIG,
            title="[wcvs] web cache vulnerability findings",
            severity=Severity.MEDIUM,
            confidence="tentative",
            url=url,
            description="Web-Cache-Vulnerability-Scanner results.",
            evidence="\n".join(hits[:40]),
            module="wcvs",
            verified=False,
            extracted_data=hits[:100],
        )
    ]


async def run_toxicache(url: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "toxicache",
        ["toxicache", "-u", url],
        timeout=timeout,
        emit=emit,
        domain_or_url=url,
        title_prefix="cache poisoning probes",
        description="Web cache poisoning helper results.",
        category=Category.MISCONFIG,
        severity=Severity.MEDIUM,
    )
    return findings


async def run_misconfig_mapper(target: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "misconfig-mapper",
        ["misconfig-mapper", "-t", target],
        timeout=timeout,
        emit=emit,
        domain_or_url=target,
        title_prefix="misconfiguration mappings",
        description="Cloud / service misconfiguration mapper.",
        category=Category.MISCONFIG,
        severity=Severity.MEDIUM,
    )
    return findings


async def run_cmseek(url: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("cmseek"):
        return _skip("cmseek", emit)
    cmd = ["cmseek", "-u", url, "--batch"]
    code, out, err = await _run(cmd, timeout, emit, "cmseek")
    hits = _lines(out)
    if not hits:
        return []
    return [
        _recon_finding(
            "cmseek",
            f"[cmseek] CMS detection for {url}",
            url,
            "CMS detection & exploitation helper.",
            "\n".join(hits[:40]),
            hits[:100],
        )
    ]


async def run_tlsx(host: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    if not tool_available("tlsx"):
        return _skip("tlsx", emit)
    cmd = ["tlsx", "-host", host, "-silent", "-json", "-san", "-cn"]
    code, out, err = await _run(cmd, timeout, emit, "tlsx")
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        sans = j.get("subject_an") or j.get("san") or []
        cn = j.get("subject_cn") or j.get("cn") or ""
        extracted = []
        if cn:
            extracted.append(f"CN={cn}")
        extracted.extend(str(s) for s in sans[:30])
        findings.append(
            Finding(
                category=Category.TLS,
                title=f"[tlsx] certificate for {host}",
                severity=Severity.INFO,
                confidence="firm",
                url=host,
                description="TLS certificate details from tlsx.",
                evidence=json.dumps(
                    {k: j.get(k) for k in ("subject_cn", "subject_an", "issuer_cn", "not_after") if k in j}
                )[:600],
                module="tlsx",
                verified=True,
                extracted_data=extracted,
            )
        )
    return findings


async def run_interactsh_client(timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("interactsh-client"):
        return _skip("interactsh-client", emit)
    cmd = ["interactsh-client", "-silent", "-json"]
    code, out, err = await _run(cmd, min(timeout, 15), emit, "interactsh-client")
    # Usually long-lived; capture any payload URL printed
    urls = re.findall(r"[a-z0-9]+\.oast\.[a-z.]+", out + err)
    if not urls:
        return []
    return [
        _recon_finding(
            "interactsh-client",
            "[interactsh-client] OAST payload host issued",
            urls[0],
            "Out-of-band interaction host from interactsh-client.",
            "\n".join(urls[:10]),
            urls[:20],
        )
    ]


async def run_notify(message: str, timeout: float = 15, emit: Emit = None) -> list[Finding]:
    if not tool_available("notify"):
        return _skip("notify", emit)
    cmd = ["notify", "-silent", "-data", message[:500]]
    await _run(cmd, timeout, emit, "notify")
    return []


# ---------------------------------------------------------------------------
# Vulnerability runners
# ---------------------------------------------------------------------------


async def run_nuclei(base_url: str, timeout: float = 600, emit: Emit = None) -> list[Finding]:
    if not tool_available("nuclei"):
        return _skip("nuclei", emit)
    cmd = ["nuclei", "-u", base_url, "-jsonl", "-silent", "-timeout", "10"]
    code, out, err = await _run(cmd, timeout, emit, "nuclei")
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info", {})
        sev = SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[nuclei] {info.get('name', j.get('template-id', 'finding'))}",
                severity=sev,
                confidence="firm",
                url=j.get("matched-at") or j.get("host") or base_url,
                description=info.get("description", "") or "Reported by a nuclei template.",
                evidence=f"template-id={j.get('template-id')} matcher={j.get('matcher-name', '')}",
                remediation=(info.get("remediation") or "See the nuclei template reference."),
                references=info.get("reference", []) or [],
                module="nuclei",
                verified=True,
            )
        )
    return findings


async def run_sqlmap(
    url: str,
    method: str,
    params: dict[str, str],
    timeout: float = 300,
    emit: Emit = None,
) -> list[Finding]:
    if not tool_available("sqlmap") or not params:
        return _skip("sqlmap", emit) if not tool_available("sqlmap") else []
    cmd = [
        "sqlmap",
        "-u",
        f"{url}?{urlencode(params)}" if method.upper() == "GET" else url,
        "--batch",
        "--level",
        "2",
        "--risk",
        "1",
        "--smart",
        "--flush-session",
    ]
    if method.upper() == "POST":
        cmd += ["--data", urlencode(params)]
    code, out, err = await _run(cmd, timeout, emit, "sqlmap")
    findings: list[Finding] = []
    if "is vulnerable" in out or "sqlmap identified the following injection point" in out:
        findings.append(
            Finding(
                category=Category.SQLI,
                title="SQL injection confirmed by sqlmap",
                severity=Severity.CRITICAL,
                confidence="confirmed",
                url=url,
                description="sqlmap confirmed an injectable parameter.",
                evidence=out[-800:],
                remediation="Use parameterized queries; validate and least-privilege the DB account.",
                cwe="CWE-89",
                module="sqlmap",
                verified=True,
                extracted_data=[line.strip() for line in out.splitlines() if line.strip()][-20:],
            )
        )
    return findings


async def run_dalfox(url: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("dalfox"):
        return _skip("dalfox", emit)
    cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
    code, out, err = await _run(cmd, timeout, emit, "dalfox")
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            try:
                arr = json.loads(out)
                if isinstance(arr, list):
                    for item in arr:
                        if isinstance(item, dict):
                            findings.append(
                                Finding(
                                    category=Category.XSS,
                                    title=f"[dalfox] XSS: {item.get('type', 'reflected')}",
                                    severity=Severity.HIGH,
                                    confidence="firm",
                                    url=item.get("data") or url,
                                    description=str(item.get("message") or item.get("payload") or "XSS finding"),
                                    evidence=json.dumps(item)[:800],
                                    module="dalfox",
                                    verified=True,
                                    extracted_data=[str(item.get("payload", ""))],
                                )
                            )
                break
            except json.JSONDecodeError:
                continue
            continue
        findings.append(
            Finding(
                category=Category.XSS,
                title=f"[dalfox] XSS: {j.get('type', 'reflected')}",
                severity=Severity.HIGH,
                confidence="firm",
                url=j.get("data") or url,
                description=str(j.get("message") or j.get("payload") or "XSS finding"),
                evidence=json.dumps(j)[:800],
                module="dalfox",
                verified=True,
                extracted_data=[str(j.get("payload", ""))],
            )
        )
    return findings


async def run_kxss(urls: list[str], timeout: float = 120, emit: Emit = None) -> list[Finding]:
    if not tool_available("kxss") or not urls:
        return _skip("kxss", emit) if not tool_available("kxss") else []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for u in urls[:200]:
            fh.write(u.rstrip() + "\n")
        path = fh.name
    try:
        code, out, err = await _run(["bash", "-c", f"cat {path} | kxss"], timeout, emit, "kxss")
    finally:
        Path(path).unlink(missing_ok=True)
    hits = _lines(out)
    if not hits:
        return []
    return [
        Finding(
            category=Category.XSS,
            title=f"[kxss] {len(hits)} reflected parameter(s)",
            severity=Severity.MEDIUM,
            confidence="tentative",
            url=urls[0],
            description="Reflected XSS parameter finder results.",
            evidence="\n".join(hits[:40]),
            module="kxss",
            verified=False,
            extracted_data=hits[:100],
        )
    ]


async def run_gxss(urls: list[str], timeout: float = 120, emit: Emit = None) -> list[Finding]:
    name = "Gxss"
    if not tool_available(name) and not tool_available("gxss"):
        return _skip("Gxss", emit)
    binary = "Gxss" if tool_available("Gxss") else "gxss"
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for u in urls[:200]:
            fh.write(u.rstrip() + "\n")
        path = fh.name
    try:
        code, out, err = await _run(["bash", "-c", f"cat {path} | {binary}"], timeout, emit, "Gxss")
    finally:
        Path(path).unlink(missing_ok=True)
    hits = _lines(out)
    if not hits:
        return []
    return [
        Finding(
            category=Category.XSS,
            title=f"[Gxss] {len(hits)} reflection(s)",
            severity=Severity.MEDIUM,
            confidence="tentative",
            url=urls[0],
            description="XSS parameter reflection checker.",
            evidence="\n".join(hits[:40]),
            module="Gxss",
            verified=False,
            extracted_data=hits[:100],
        )
    ]


async def run_crlfuzz(url: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    if not tool_available("crlfuzz"):
        return _skip("crlfuzz", emit)
    cmd = ["crlfuzz", "-u", url, "-s"]
    code, out, err = await _run(cmd, timeout, emit, "crlfuzz")
    hits = _lines(out)
    if not hits:
        return []
    return [
        Finding(
            category=Category.MISCONFIG,
            title=f"[crlfuzz] CRLF injection candidate(s)",
            severity=Severity.MEDIUM,
            confidence="tentative",
            url=url,
            description="CRLF injection fuzzer results.",
            evidence="\n".join(hits[:40]),
            module="crlfuzz",
            verified=False,
            extracted_data=hits[:50],
        )
    ]


async def run_flask_unsign(cookie: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    if not tool_available("flask-unsign"):
        return _skip("flask-unsign", emit)
    cmd = ["flask-unsign", "--decode", "--cookie", cookie]
    code, out, err = await _run(cmd, timeout, emit, "flask-unsign")
    if not out.strip():
        return []
    return [
        Finding(
            category=Category.CRYPTO,
            title="[flask-unsign] decoded Flask session cookie",
            severity=Severity.MEDIUM,
            confidence="firm",
            url="(cookie)",
            description="Flask session cookie decoded.",
            evidence=out[:800],
            module="flask-unsign",
            verified=True,
            extracted_data=_lines(out)[:20],
        )
    ]


async def run_sisakulint(path: str, timeout: float = 60, emit: Emit = None) -> list[Finding]:
    if not tool_available("sisakulint"):
        return _skip("sisakulint", emit)
    cmd = ["sisakulint", path]
    code, out, err = await _run(cmd, timeout, emit, "sisakulint")
    hits = _lines(out + "\n" + err)
    if not hits:
        return []
    return [
        Finding(
            category=Category.MISCONFIG,
            title="[sisakulint] workflow lint findings",
            severity=Severity.LOW,
            confidence="tentative",
            url=path,
            description="GitHub Actions workflow linter results.",
            evidence="\n".join(hits[:40]),
            module="sisakulint",
            verified=False,
            extracted_data=hits[:50],
        )
    ]


async def run_semgrep(path: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("semgrep"):
        return _skip("semgrep", emit)
    cmd = ["semgrep", "--json", "--quiet", path]
    code, out, err = await _run(cmd, timeout, emit, "semgrep")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        data = {}
    for r in (data.get("results") or [])[:50]:
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[semgrep] {r.get('check_id', 'finding')}",
                severity=SEVERITY_MAP.get(str(r.get("extra", {}).get("severity", "info")).lower(), Severity.INFO),
                confidence="firm",
                url=r.get("path") or path,
                description=(r.get("extra") or {}).get("message") or "Semgrep finding",
                evidence=json.dumps(r)[:600],
                module="semgrep",
                verified=True,
            )
        )
    return findings


async def run_pysemgrep(path: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("pysemgrep"):
        return _skip("pysemgrep", emit)
    cmd = ["pysemgrep", "--json", path]
    code, out, err = await _run(cmd, timeout, emit, "pysemgrep")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        data = {}
    for r in (data.get("results") or [])[:50]:
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[pysemgrep] {r.get('check_id', 'finding')}",
                severity=Severity.INFO,
                confidence="firm",
                url=r.get("path") or path,
                description=str(r.get("extra", {}).get("message") or "pysemgrep finding"),
                evidence=json.dumps(r)[:600],
                module="pysemgrep",
                verified=True,
            )
        )
    return findings


async def run_detect_secrets(path: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    if not tool_available("detect-secrets"):
        return _skip("detect-secrets", emit)
    cmd = ["detect-secrets", "scan", path]
    code, out, err = await _run(cmd, timeout, emit, "detect-secrets")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip().startswith("{") else {}
    except json.JSONDecodeError:
        data = {}
    results = data.get("results") or {}
    for file_path, secrets in results.items():
        for s in secrets[:20]:
            findings.append(
                Finding(
                    category=Category.CRYPTO,
                    title=f"[detect-secrets] {s.get('type', 'secret')} in {file_path}",
                    severity=Severity.HIGH,
                    confidence="firm",
                    url=file_path,
                    description="Potential secret detected.",
                    evidence=json.dumps(s)[:500],
                    module="detect-secrets",
                    verified=True,
                    extracted_data=[s.get("hashed_secret") or s.get("secret") or ""],
                )
            )
    return findings


async def run_betterleaks(path: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "betterleaks",
        ["betterleaks", path],
        timeout=timeout,
        emit=emit,
        domain_or_url=path,
        title_prefix="leaks",
        description="Secret / leak detection via betterleaks.",
        category=Category.CRYPTO,
        severity=Severity.HIGH,
    )
    return findings


async def run_trufflehog(path: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("trufflehog"):
        return _skip("trufflehog", emit)
    cmd = ["trufflehog", "filesystem", path, "--json"]
    code, out, err = await _run(cmd, timeout, emit, "trufflehog")
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(
            Finding(
                category=Category.CRYPTO,
                title=f"[trufflehog] {j.get('DetectorName') or j.get('DetectorType') or 'secret'}",
                severity=Severity.HIGH,
                confidence="firm",
                url=str((j.get("SourceMetadata") or {}).get("Data") or path),
                description="Secret found by trufflehog.",
                evidence=json.dumps(j)[:600],
                module="trufflehog",
                verified=True,
                extracted_data=[str(j.get("Raw") or j.get("Redacted") or "")[:200]],
            )
        )
    return findings


async def run_gitleaks(path: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("gitleaks"):
        return _skip("gitleaks", emit)
    cmd = ["gitleaks", "detect", "-s", path, "-r", "/dev/stdout", "-f", "json", "--no-banner"]
    code, out, err = await _run(cmd, timeout, emit, "gitleaks")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip().startswith("[") else []
    except json.JSONDecodeError:
        data = []
    for item in data[:40]:
        findings.append(
            Finding(
                category=Category.CRYPTO,
                title=f"[gitleaks] {item.get('RuleID') or item.get('Description') or 'secret'}",
                severity=Severity.HIGH,
                confidence="firm",
                url=item.get("File") or path,
                description=item.get("Description") or "Secret found by gitleaks.",
                evidence=json.dumps(item)[:600],
                module="gitleaks",
                verified=True,
                extracted_data=[str(item.get("Secret") or item.get("Match") or "")[:200]],
            )
        )
    return findings


async def run_kingfisher(target: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "kingfisher",
        ["kingfisher", target],
        timeout=timeout,
        emit=emit,
        domain_or_url=target,
        title_prefix="cloud secrets / misconfigs",
        description="Cloud secret / misconfig scanner.",
        category=Category.MISCONFIG,
        severity=Severity.MEDIUM,
    )
    return findings


async def run_s3scanner(domain: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    items, findings = await _run_line_tool(
        "s3scanner",
        ["s3scanner", "scan", "--buckets-file", "/dev/stdin"],
        timeout=timeout,
        emit=emit,
        domain_or_url=domain,
        title_prefix="S3 bucket findings",
        description="Open S3 bucket scanner (bucket names derived from domain).",
        category=Category.MISCONFIG,
        severity=Severity.HIGH,
    )
    # Better invocation: pass domain-derived bucket guesses via echo
    if not tool_available("s3scanner"):
        return findings
    guesses = "\n".join(
        [
            domain.replace(".", "-"),
            domain.split(".")[0],
            f"{domain.split('.')[0]}-backup",
            f"{domain.split('.')[0]}-assets",
        ]
    )
    code, out, err = await _run(
        ["bash", "-c", f"echo '{guesses}' | s3scanner scan --buckets-file /dev/stdin"],
        timeout,
        emit,
        "s3scanner",
    )
    hits = _lines(out)
    if hits:
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[s3scanner] bucket scan for {domain}",
                severity=Severity.HIGH,
                confidence="tentative",
                url=domain,
                description="Open S3 bucket scanner results.",
                evidence="\n".join(hits[:40]),
                module="s3scanner",
                verified=False,
                extracted_data=hits[:50],
            )
        )
    return findings


async def run_cloudfox(profile: str = "default", timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("cloudfox"):
        return _skip("cloudfox", emit)
    cmd = ["cloudfox", "aws", "all-checks", "--profile", profile]
    code, out, err = await _run(cmd, timeout, emit, "cloudfox")
    hits = _lines(out)
    if not hits:
        return []
    return [
        Finding(
            category=Category.MISCONFIG,
            title="[cloudfox] AWS enumeration results",
            severity=Severity.MEDIUM,
            confidence="tentative",
            url="aws",
            description="AWS / cloud enumeration via cloudfox.",
            evidence="\n".join(hits[:50]),
            module="cloudfox",
            verified=False,
            extracted_data=hits[:100],
        )
    ]


async def run_grype(path: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("grype"):
        return _skip("grype", emit)
    cmd = ["grype", path, "-o", "json"]
    code, out, err = await _run(cmd, timeout, emit, "grype")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        data = {}
    for m in (data.get("matches") or [])[:40]:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[grype] {vuln.get('id', 'CVE')} in {art.get('name', '?')}",
                severity=SEVERITY_MAP.get(str(vuln.get("severity", "info")).lower(), Severity.INFO),
                confidence="firm",
                url=path,
                description=vuln.get("description") or "Vulnerability from grype.",
                evidence=json.dumps(m)[:600],
                module="grype",
                verified=True,
            )
        )
    return findings


async def run_gosec(path: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("gosec"):
        return _skip("gosec", emit)
    cmd = ["gosec", "-fmt=json", path]
    code, out, err = await _run(cmd, timeout, emit, "gosec")
    findings: list[Finding] = []
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        data = {}
    for issue in (data.get("Issues") or [])[:40]:
        findings.append(
            Finding(
                category=Category.MISCONFIG,
                title=f"[gosec] {issue.get('rule_id') or issue.get('details', 'issue')}",
                severity=SEVERITY_MAP.get(str(issue.get("severity", "info")).lower(), Severity.INFO),
                confidence="firm",
                url=issue.get("file") or path,
                description=issue.get("details") or "gosec finding",
                evidence=json.dumps(issue)[:600],
                module="gosec",
                verified=True,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Network runners
# ---------------------------------------------------------------------------


async def run_nmap(host: str, timeout: float = 300, emit: Emit = None) -> list[Finding]:
    if not tool_available("nmap"):
        return _skip("nmap", emit)
    cmd = ["nmap", "-Pn", "-T4", "--top-ports", "200", "-sV", host]
    code, out, err = await _run(cmd, timeout, emit, "nmap")
    findings: list[Finding] = []
    risky = {
        "21": "FTP",
        "23": "Telnet",
        "3306": "MySQL",
        "5432": "Postgres",
        "6379": "Redis",
        "27017": "MongoDB",
        "9200": "Elasticsearch",
        "5900": "VNC",
        "3389": "RDP",
        "2375": "Docker API",
    }
    open_ports: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0]
            open_ports.append(line)
            if port in risky:
                findings.append(
                    Finding(
                        category=Category.MISCONFIG,
                        title=f"Sensitive service exposed: {risky[port]} (port {port})",
                        severity=Severity.MEDIUM,
                        confidence="firm",
                        url=f"{host}:{port}",
                        description=f"nmap found {risky[port]} exposed on port {port}.",
                        evidence=line,
                        remediation="Restrict the service via firewall/VPN; do not expose datastores/admin ports publicly.",
                        module="nmap",
                        verified=True,
                        extracted_data=[line],
                    )
                )
    if open_ports and not findings:
        findings.append(
            _recon_finding(
                "nmap",
                f"[nmap] open ports on {host}",
                host,
                "Port scan summary.",
                "\n".join(open_ports[:40]),
                open_ports,
            )
        )
    return findings


async def run_masscan(host: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("masscan"):
        return _skip("masscan", emit)
    cmd = ["masscan", host, "-p1-1024", "--rate", "1000", "-oL", "-"]
    code, out, err = await _run(cmd, timeout, emit, "masscan")
    hits = [ln for ln in _lines(out) if "open" in ln.lower()]
    if not hits:
        return []
    return [
        _recon_finding(
            "masscan",
            f"[masscan] open ports on {host}",
            host,
            "Fast port scan results.",
            "\n".join(hits[:40]),
            hits,
        )
    ]


async def run_rustscan(host: str, timeout: float = 120, emit: Emit = None) -> list[Finding]:
    if not tool_available("rustscan"):
        return _skip("rustscan", emit)
    cmd = ["rustscan", "-a", host, "--ulimit", "5000", "-g"]
    code, out, err = await _run(cmd, timeout, emit, "rustscan")
    hits = _lines(out)
    if not hits:
        return []
    return [
        _recon_finding(
            "rustscan",
            f"[rustscan] open ports on {host}",
            host,
            "Modern fast port scanner results.",
            "\n".join(hits[:40]),
            hits,
        )
    ]


async def run_naabu(host: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("naabu"):
        return _skip("naabu", emit)
    cmd = ["naabu", "-host", host, "-silent", "-top-ports", "100"]
    code, out, err = await _run(cmd, timeout, emit, "naabu")
    ports = _lines(out)
    if not ports:
        return []
    return [
        _recon_finding(
            "naabu",
            f"[naabu] open ports on {host}",
            host,
            "Port scan results from ProjectDiscovery naabu.",
            "\n".join(ports[:50]),
            ports,
        )
    ]


async def run_nping(host: str, timeout: float = 30, emit: Emit = None) -> list[Finding]:
    if not tool_available("nping"):
        return _skip("nping", emit)
    cmd = ["nping", "--tcp", "-p", "80,443", "-c", "2", host]
    code, out, err = await _run(cmd, timeout, emit, "nping")
    return [
        _recon_finding(
            "nping",
            f"[nping] probe of {host}",
            host,
            "Packet generation / response analysis.",
            (out or err)[:800],
            _lines(out)[:20],
        )
    ]


async def run_ncat(host: str, port: int = 80, timeout: float = 15, emit: Emit = None) -> list[Finding]:
    if not tool_available("ncat"):
        return _skip("ncat", emit)
    cmd = ["ncat", "-z", "-v", host, str(port)]
    code, out, err = await _run(cmd, timeout, emit, "ncat")
    text = (out + err).strip()
    if not text:
        return []
    return [
        _recon_finding(
            "ncat",
            f"[ncat] connect test {host}:{port}",
            f"{host}:{port}",
            "Nmap netcat connectivity probe.",
            text[:500],
            [text[:200]],
        )
    ]


async def run_nc(host: str, port: int = 80, timeout: float = 15, emit: Emit = None) -> list[Finding]:
    if not tool_available("nc"):
        return _skip("nc", emit)
    cmd = ["nc", "-zv", host, str(port)]
    code, out, err = await _run(cmd, timeout, emit, "nc")
    text = (out + err).strip()
    if not text:
        return []
    return [
        _recon_finding(
            "nc",
            f"[nc] connect test {host}:{port}",
            f"{host}:{port}",
            "netcat connectivity probe.",
            text[:500],
            [text[:200]],
        )
    ]


async def run_tshark(timeout: float = 20, emit: Emit = None) -> list[Finding]:
    if not tool_available("tshark"):
        return _skip("tshark", emit)
    # Capture a short sample if possible; otherwise just version probe
    cmd = ["tshark", "-v"]
    code, out, err = await _run(cmd, timeout, emit, "tshark")
    return [
        _recon_finding(
            "tshark",
            "[tshark] available for packet analysis",
            "local",
            "Wireshark CLI present; use offline capture analysis as needed.",
            (out or err)[:400],
            _lines(out)[:10],
        )
    ]


async def run_sharkd(timeout: float = 10, emit: Emit = None) -> list[Finding]:
    if not tool_available("sharkd"):
        return _skip("sharkd", emit)
    if emit:
        emit("  · sharkd is a daemon interface; presence noted, not long-run in scan")
    return [
        _recon_finding(
            "sharkd",
            "[sharkd] available",
            "local",
            "Wireshark sharkd daemon binary present.",
            "sharkd on PATH",
            ["sharkd"],
        )
    ]


async def run_randpkt(timeout: float = 10, emit: Emit = None) -> list[Finding]:
    if not tool_available("randpkt"):
        return _skip("randpkt", emit)
    if emit:
        emit("  · randpkt generates packets; presence noted only (not fired at target)")
    return [
        _recon_finding(
            "randpkt",
            "[randpkt] available",
            "local",
            "Random packet generator present (not executed against target).",
            "randpkt on PATH",
            ["randpkt"],
        )
    ]


async def run_sshuttle(timeout: float = 10, emit: Emit = None) -> list[Finding]:
    if not tool_available("sshuttle"):
        return _skip("sshuttle", emit)
    if emit:
        emit("  · sshuttle is a VPN helper; presence noted only")
    return [
        _recon_finding(
            "sshuttle",
            "[sshuttle] available",
            "local",
            "Transparent proxy / VPN over SSH present (operator-driven).",
            "sshuttle on PATH",
            ["sshuttle"],
        )
    ]


# ---------------------------------------------------------------------------
# OSINT
# ---------------------------------------------------------------------------


async def run_sherlock(username: str, timeout: float = 180, emit: Emit = None) -> list[Finding]:
    if not tool_available("sherlock"):
        return _skip("sherlock", emit)
    cmd = ["sherlock", username, "--print-found", "--no-color"]
    code, out, err = await _run(cmd, timeout, emit, "sherlock")
    found = [ln.strip() for ln in out.splitlines() if "http" in ln.lower()]
    if not found:
        return []
    return [
        _recon_finding(
            "sherlock",
            f"[sherlock] username '{username}' found on {len(found)} site(s)",
            username,
            "Username presence across social / public platforms.",
            "\n".join(found[:40]),
            found,
        )
    ]


# ---------------------------------------------------------------------------
# Orchestrators used by the engine
# ---------------------------------------------------------------------------


async def run_recon_tools(
    base_url: str,
    emit: Emit = None,
    aggressive: bool = False,
    groups: list[str] | None = None,
) -> tuple[list[Finding], dict[str, object]]:
    """Run recon + http external tools, filtered by ``groups``."""
    enabled = groups_enabled(groups)
    do_recon = "recon" in enabled
    do_http = "http" in enabled
    if not do_recon and not do_http:
        if emit:
            emit("Skipping recon/http external tools (not in --tool-group).")
        return [], {}

    host = host_from_url(base_url)
    domain = registerable_domain(host)
    findings: list[Finding] = []
    recon: dict[str, object] = {}
    all_subs: set[str] = set()
    all_urls: set[str] = set()

    if emit:
        bits = []
        if do_recon:
            bits.append("recon")
        if do_http:
            bits.append("http")
        emit(f"Running external tools for group(s): {', '.join(bits)}…")

    if do_recon:
        sub_coros = [
            run_subfinder(domain, emit=emit),
            run_amass(domain, emit=emit),
            run_assetfinder(domain, emit=emit),
            run_findomain(domain, emit=emit),
            run_subdomainx(domain, emit=emit),
            run_chaos(domain, emit=emit),
            run_crtsh(domain, emit=emit),
            run_dnsgen(domain, emit=emit),
            run_alterx(domain, emit=emit),
            run_puredns(domain, emit=emit),
            run_shuffledns(domain, emit=emit),
            run_massdns(domain, emit=emit),
        ]
        for result in await asyncio.gather(*sub_coros, return_exceptions=True):
            if isinstance(result, Exception):
                if emit:
                    emit(f"  ✗ recon tool error: {result}")
                continue
            subs, finds = result
            all_subs.update(subs)
            findings.extend(finds)

        for coro in (
            run_metabigor(domain, emit=emit),
            run_shodan(host, emit=emit),
            run_certstream(domain, emit=emit),
            run_tldbrute(domain, emit=emit),
            run_tldextract(domain, emit=emit),
            run_enumerepo(domain, emit=emit),
            run_asnmap(domain, emit=emit),
            run_cdncheck(host, emit=emit),
            run_smap(host, emit=emit),
            run_hakoriginfinder(host, emit=emit),
            run_hakrevdns(host, emit=emit),
            run_dnsx(sorted(all_subs)[:200] or [host], emit=emit),
            run_jsfinder2(base_url, emit=emit),
            run_jsleak(base_url, emit=emit),
            run_jsecret(base_url, emit=emit),
            run_roboxtractor(base_url, emit=emit),
            run_xalgorix(base_url, emit=emit),
        ):
            try:
                res = await coro
                if isinstance(res, tuple):
                    findings.extend(res[1])
                else:
                    findings.extend(res)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ recon helper error: {exc}")

        # Historical URL harvest is recon-oriented
        url_coros = [
            run_gau(domain, emit=emit),
            run_waybackurls(domain, emit=emit),
            run_waymore(domain, emit=emit),
            run_urlfinder(domain, emit=emit),
        ]
        for result in await asyncio.gather(*url_coros, return_exceptions=True):
            if isinstance(result, Exception):
                if emit:
                    emit(f"  ✗ URL-harvest tool error: {result}")
                continue
            urls, finds = result
            all_urls.update(urls)
            findings.extend(finds)

        url_list = sorted(all_urls)[:500] or [base_url]
        for coro in (
            run_gf(url_list, emit=emit),
            run_qsreplace(url_list, emit=emit),
            run_dsieve(sorted(all_subs)[:500] or [domain], emit=emit),
        ):
            try:
                findings.extend(await coro)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ URL filter error: {exc}")

    if do_http:
        # Crawl / probe / content discovery
        url_coros = [
            run_paramspider(domain, emit=emit),
            run_katana(base_url, emit=emit),
            run_hakrawler(base_url, emit=emit),
        ]
        for result in await asyncio.gather(*url_coros, return_exceptions=True):
            if isinstance(result, Exception):
                if emit:
                    emit(f"  ✗ crawl tool error: {result}")
                continue
            urls, finds = result
            all_urls.update(urls)
            findings.extend(finds)

        probe_targets = [base_url] + [f"https://{s}" for s in sorted(all_subs)[:40]]
        for coro in (
            run_httpx_probe(probe_targets, emit=emit),
            run_httpx2(probe_targets[:20], emit=emit),
            run_tlsx(host, emit=emit),
            run_whatweb(base_url, emit=emit),
            run_nikto(base_url, emit=emit),
            run_cmseek(base_url, emit=emit),
            run_interactsh_client(emit=emit),
            run_wcvs(base_url, emit=emit),
            run_toxicache(base_url, emit=emit),
            run_misconfig_mapper(host, emit=emit),
        ):
            try:
                findings.extend(await coro)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ http probe error: {exc}")

        for coro in (
            run_ffuf(base_url, emit=emit),
            run_feroxbuster(base_url, emit=emit),
            run_gobuster(base_url, emit=emit),
            run_dirsearch(base_url, emit=emit),
            run_gowitness(base_url, emit=emit),
        ):
            try:
                findings.extend(await coro)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ content-discovery error: {exc}")

    if all_subs:
        recon["subdomains"] = sorted(all_subs)
    if all_urls:
        recon["wayback_urls"] = sorted(all_urls)[:500]
        recon.setdefault("discovered_urls", sorted(all_urls)[:500])

    return findings, recon


async def run_vuln_tools(
    base_url: str,
    request_targets: list | None = None,
    emit: Emit = None,
    aggressive: bool = False,
    groups: list[str] | None = None,
) -> list[Finding]:
    """Run vulnerability, network, and OSINT tools filtered by ``groups``."""
    enabled = groups_enabled(groups)
    do_vuln = "vuln" in enabled
    do_network = "network" in enabled
    do_osint = "osint" in enabled
    if not (do_vuln or do_network or do_osint):
        if emit:
            emit("Skipping vuln/network/osint external tools (not in --tool-group).")
        return []

    findings: list[Finding] = []
    host = host_from_url(base_url)

    if emit:
        bits = [g for g, on in (("vuln", do_vuln), ("network", do_network), ("osint", do_osint)) if on]
        emit(f"Running external tools for group(s): {', '.join(bits)}…")

    if do_vuln:
        base_tasks = [
            run_nuclei(base_url, emit=emit),
            run_crlfuzz(base_url, emit=emit),
            run_s3scanner(registerable_domain(host), emit=emit),
            run_kingfisher(host, emit=emit),
        ]
        for group in await asyncio.gather(*base_tasks, return_exceptions=True):
            if isinstance(group, Exception):
                if emit:
                    emit(f"  ✗ vuln tool error: {group}")
                continue
            findings.extend(group)

        if aggressive:
            if emit:
                emit("Aggressive mode: dalfox / kxss / Gxss / sqlmap / secret scanners…")
            url_list = [base_url]
            for rt in (request_targets or [])[:10]:
                url_list.append(rt.url)
            agg_tasks: list = [
                run_dalfox(base_url, emit=emit),
                run_kxss(url_list, emit=emit),
                run_gxss(url_list, emit=emit),
            ]
            for rt in (request_targets or [])[:3]:
                agg_tasks.append(run_sqlmap(rt.url, rt.method, rt.params, emit=emit))
            cwd = str(Path.cwd())
            agg_tasks.extend(
                [
                    run_detect_secrets(cwd, emit=emit),
                    run_betterleaks(cwd, emit=emit),
                    run_trufflehog(cwd, emit=emit),
                    run_gitleaks(cwd, emit=emit),
                    run_semgrep(cwd, emit=emit),
                    run_pysemgrep(cwd, emit=emit),
                    run_grype(cwd, emit=emit),
                    run_gosec(cwd, emit=emit),
                    run_sisakulint(cwd, emit=emit),
                    run_cloudfox(emit=emit),
                ]
            )
            for group in await asyncio.gather(*agg_tasks, return_exceptions=True):
                if isinstance(group, Exception):
                    if emit:
                        emit(f"  ✗ aggressive tool error: {group}")
                    continue
                findings.extend(group)

    if do_network:
        net_tasks = [
            run_nmap(host, emit=emit),
            run_naabu(host, emit=emit),
            run_masscan(host, emit=emit),
            run_rustscan(host, emit=emit),
            run_nping(host, emit=emit),
            run_ncat(host, emit=emit),
            run_nc(host, emit=emit),
            run_tshark(emit=emit),
            run_sharkd(emit=emit),
            run_randpkt(emit=emit),
            run_sshuttle(emit=emit),
        ]
        for group in await asyncio.gather(*net_tasks, return_exceptions=True):
            if isinstance(group, Exception):
                if emit:
                    emit(f"  ✗ network tool error: {group}")
                continue
            findings.extend(group)

    if do_osint:
        label = registerable_domain(host).split(".")[0]
        if label and label not in {"www", "localhost"}:
            try:
                findings.extend(await run_sherlock(label, emit=emit))
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ sherlock error: {exc}")

    return findings


def tool_status_banner(emit: Emit = None) -> list[str]:
    """Return (and optionally print) which catalog tools are installed."""
    present = available_tools()
    missing = [n for n in TOOL_CATALOG if n not in present]
    lines = [
        f"External tools available: {len(present)}/{len(TOOL_CATALOG)} in catalog",
        f"  installed: {', '.join(present) if present else '(none)'}",
    ]
    if missing:
        # Keep banner readable
        shown = missing[:25]
        extra = len(missing) - len(shown)
        msg = ", ".join(shown) + (f", … +{extra} more" if extra else "")
        lines.append(f"  missing: {msg}")
    if emit:
        for ln in lines:
            emit(ln)
    return lines
