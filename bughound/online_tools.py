"""Online / web-API substitutes for local bug-bounty binaries.

When the operator chooses "online" (or "both"), bughound calls public web
services that offer equivalent recon functionality instead of (or in addition
to) local CLI tools.

Each entry maps a local tool name → service URL + async runner. Runners always
log ``→ using online tool: <name> via <service>`` so the terminal shows the
source.

Public services used (no API key required for the free tier unless noted):

  crt.sh              Certificate Transparency
  web.archive.org     Wayback CDX API (waybackurls / gau-like)
  dns.google          DNS-over-HTTPS (dnsx-like)
  api.hackertarget.com  DNS, reverse DNS, whois, header check, page links
  urlscan.io          URL / domain scan (httpx-like surface)
  otxt.alienvault.com AlienVault OTX passive DNS / URLs
  securityheaders.com Header grade (informational)
  webtech_api / built-in header fingerprint (whatweb-like)
  phishtank / none    limited OSINT

Tools with no ethical free online equivalent (active scanners like sqlmap,
nuclei template runs against arbitrary targets, masscan, etc.) are reported
as "no online backend — install locally" rather than silently skipped.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Callable, Optional
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .models import Category, Finding, Severity

Emit = Optional[Callable[[str], None]]

# Catalog: local tool → human-facing online service description + homepage
ONLINE_CATALOG: dict[str, dict[str, str]] = {
    # Recon
    "amass": {"service": "crt.sh + OTX passive DNS", "url": "https://crt.sh / https://otx.alienvault.com"},
    "assetfinder": {"service": "crt.sh CT logs", "url": "https://crt.sh"},
    "findomain": {"service": "crt.sh CT logs", "url": "https://crt.sh"},
    "subfinder": {"service": "crt.sh + HackerTarget hostsearch", "url": "https://crt.sh / https://api.hackertarget.com"},
    "subdomainx": {"service": "crt.sh CT logs", "url": "https://crt.sh"},
    "chaos": {"service": "crt.sh CT logs (Chaos needs API key)", "url": "https://crt.sh"},
    "metabigor": {"service": "HackerTarget AS lookup", "url": "https://api.hackertarget.com"},
    "shodan": {"service": "HackerTarget / urlscan (Shodan needs API key)", "url": "https://urlscan.io"},
    "crtsh": {"service": "crt.sh", "url": "https://crt.sh"},
    "certstream": {"service": "crt.sh (snapshot, not live stream)", "url": "https://crt.sh"},
    "waybackurls": {"service": "Wayback Machine CDX API", "url": "https://web.archive.org"},
    "waymore": {"service": "Wayback Machine CDX API", "url": "https://web.archive.org"},
    "gau": {"service": "Wayback CDX + AlienVault OTX", "url": "https://web.archive.org / https://otx.alienvault.com"},
    "urlfinder": {"service": "Wayback CDX API", "url": "https://web.archive.org"},
    "dnsgen": {"service": "(local permutation only — no online equivalent)", "url": ""},
    "enumerepo": {"service": "GitHub code search (public)", "url": "https://github.com/search"},
    "hakrevdns": {"service": "HackerTarget reverse DNS", "url": "https://api.hackertarget.com/reversedns/"},
    "hakoriginfinder": {"service": "HackerTarget IP lookup", "url": "https://api.hackertarget.com"},
    "hakip2host": {"service": "HackerTarget reverse DNS", "url": "https://api.hackertarget.com/reversedns/"},
    "asnmap": {"service": "HackerTarget AS lookup", "url": "https://api.hackertarget.com/aslookup/"},
    "cdncheck": {"service": "Header / CNAME heuristics via HackerTarget", "url": "https://api.hackertarget.com"},
    "dnsx": {"service": "Google DNS-over-HTTPS", "url": "https://dns.google/resolve"},
    "puredns": {"service": "Google DNS-over-HTTPS", "url": "https://dns.google/resolve"},
    "shuffledns": {"service": "Google DNS-over-HTTPS", "url": "https://dns.google/resolve"},
    "massdns": {"service": "Google DNS-over-HTTPS", "url": "https://dns.google/resolve"},
    "httpx": {"service": "urlscan.io + direct probe", "url": "https://urlscan.io"},
    "httpx2": {"service": "urlscan.io + direct probe", "url": "https://urlscan.io"},
    "alterx": {"service": "(local permutation only)", "url": ""},
    "anew": {"service": "(local utility)", "url": ""},
    "gf": {"service": "(local pattern filter)", "url": ""},
    "qsreplace": {"service": "(local utility)", "url": ""},
    "dsieve": {"service": "(local utility)", "url": ""},
    "smap": {"service": "HackerTarget nmap (limited)", "url": "https://api.hackertarget.com/nmap/"},
    "jsfinder2": {"service": "HackerTarget page links + script heuristic", "url": "https://api.hackertarget.com/pagelinks/"},
    "jsleak": {"service": "(no free online equivalent — install locally)", "url": ""},
    "jsecret": {"service": "(no free online equivalent — install locally)", "url": ""},
    "roboxtractor": {"service": "Direct robots.txt fetch", "url": "https://<target>/robots.txt"},
    "xalgorix": {"service": "(no free online equivalent)", "url": ""},
    "tldbrute": {"service": "(no free online equivalent)", "url": ""},
    "tldextract": {"service": "Built-in registrable-domain parse", "url": ""},
    "mapcidr": {"service": "(local utility)", "url": ""},
    "nmapurls": {"service": "(local utility)", "url": ""},
    # HTTP
    "katana": {"service": "HackerTarget page links (shallow crawl)", "url": "https://api.hackertarget.com/pagelinks/"},
    "hakrawler": {"service": "HackerTarget page links", "url": "https://api.hackertarget.com/pagelinks/"},
    "ffuf": {"service": "(active fuzzing — install locally; no safe public fuzzer)", "url": ""},
    "feroxbuster": {"service": "(active fuzzing — install locally)", "url": ""},
    "gobuster": {"service": "(active fuzzing — install locally)", "url": ""},
    "dirsearch": {"service": "(active fuzzing — install locally)", "url": ""},
    "gowitness": {"service": "urlscan.io screenshot", "url": "https://urlscan.io"},
    "whatweb": {"service": "HTTP header / tech fingerprint", "url": "direct probe"},
    "nikto": {"service": "(active scanner — install locally)", "url": ""},
    "paramspider": {"service": "Wayback CDX parameter mining", "url": "https://web.archive.org"},
    "wcvs": {"service": "(active scanner — install locally)", "url": ""},
    "toxicache": {"service": "(active scanner — install locally)", "url": ""},
    "misconfig-mapper": {"service": "(install locally)", "url": ""},
    "cmseek": {"service": "HTTP fingerprint heuristics", "url": "direct probe"},
    "tlsx": {"service": "crt.sh cert metadata", "url": "https://crt.sh"},
    "interactsh-client": {"service": "(OAST client — install locally or use Burp Collaborator)", "url": ""},
    "notify": {"service": "(local notifier)", "url": ""},
    # Vuln — most require local install for ethical/active testing
    "nuclei": {"service": "(template scanner — install locally)", "url": "https://github.com/projectdiscovery/nuclei"},
    "sqlmap": {"service": "(SQLi tool — install locally; never use random online SQLi sites)", "url": "https://sqlmap.org"},
    "dalfox": {"service": "(XSS scanner — install locally)", "url": ""},
    "kxss": {"service": "(install locally)", "url": ""},
    "Gxss": {"service": "(install locally)", "url": ""},
    "crlfuzz": {"service": "(install locally)", "url": ""},
    "flask-unsign": {"service": "(install locally)", "url": ""},
    "sisakulint": {"service": "(install locally)", "url": ""},
    "semgrep": {"service": "semgrep.dev playground (manual)", "url": "https://semgrep.dev/playground"},
    "pysemgrep": {"service": "semgrep.dev playground (manual)", "url": "https://semgrep.dev/playground"},
    "detect-secrets": {"service": "(install locally)", "url": ""},
    "betterleaks": {"service": "(install locally)", "url": ""},
    "trufflehog": {"service": "(install locally)", "url": ""},
    "gitleaks": {"service": "(install locally)", "url": ""},
    "kingfisher": {"service": "(install locally)", "url": ""},
    "s3scanner": {"service": "(install locally)", "url": ""},
    "cloudfox": {"service": "(install locally)", "url": ""},
    "grype": {"service": "(install locally)", "url": ""},
    "gosec": {"service": "(install locally)", "url": ""},
    # Network
    "nmap": {"service": "HackerTarget nmap (top ports, rate-limited)", "url": "https://api.hackertarget.com/nmap/"},
    "masscan": {"service": "(install locally — no public masscan API)", "url": ""},
    "rustscan": {"service": "(install locally)", "url": ""},
    "naabu": {"service": "HackerTarget nmap", "url": "https://api.hackertarget.com/nmap/"},
    "nping": {"service": "(install locally)", "url": ""},
    "ncat": {"service": "(install locally)", "url": ""},
    "nc": {"service": "(install locally)", "url": ""},
    "tshark": {"service": "(install locally)", "url": ""},
    "sharkd": {"service": "(install locally)", "url": ""},
    "randpkt": {"service": "(install locally)", "url": ""},
    "sshuttle": {"service": "(install locally)", "url": ""},
    # OSINT
    "sherlock": {"service": "WhatsMyName / manual check (no free bulk API)", "url": "https://whatsmyname.app"},
}


def _http_get(url: str, timeout: float = 25.0, headers: dict | None = None) -> tuple[int, str]:
    hdrs = {"User-Agent": "bughound/1.11 (authorized-scan; online-tools)"}
    if headers:
        hdrs.update(headers)
    req = Request(url, headers=hdrs)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


async def _aget(url: str, timeout: float = 25.0, headers: dict | None = None) -> tuple[int, str]:
    return await asyncio.to_thread(_http_get, url, timeout, headers)


def _finding(
    module: str,
    title: str,
    url: str,
    description: str,
    evidence: str,
    extracted: list[str] | None = None,
    category: Category = Category.RECON,
    severity: Severity = Severity.INFO,
) -> Finding:
    return Finding(
        category=category,
        title=title,
        severity=severity,
        confidence="firm",
        url=url,
        description=description,
        evidence=(evidence or "")[:2000],
        module=f"online:{module}",
        verified=True,
        extracted_data=(extracted or [])[:300],
        references=[ONLINE_CATALOG.get(module, {}).get("url", "")] if ONLINE_CATALOG.get(module, {}).get("url") else [],
    )


def _host(url_or_host: str) -> str:
    if "://" in url_or_host:
        return urlparse(url_or_host).hostname or url_or_host
    return url_or_host.split("/")[0]


def _domain(host: str) -> str:
    parts = host.strip(".").lower().split(".")
    if len(parts) <= 2:
        return host
    multi = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk"}
    tail2 = ".".join(parts[-2:])
    if tail2 in multi and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


# ---------------------------------------------------------------------------
# Individual online backends
# ---------------------------------------------------------------------------


async def online_crtsh(domain: str, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if emit:
        emit(f"  → using online tool: crtsh  via https://crt.sh/?q=%25.{domain}&output=json")
    code, body = await _aget(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", timeout=45)
    if code != 200:
        if emit:
            emit(f"  ✗ crtsh online failed ({code}): {body[:120]}")
        return [], []
    try:
        data = json.loads(body) if body.strip() else []
    except json.JSONDecodeError:
        data = []
    subs: set[str] = set()
    for row in data if isinstance(data, list) else []:
        for part in (row.get("name_value") or "").lower().split("\n"):
            part = part.strip().lstrip("*.")
            if part.endswith(domain) and "*" not in part:
                subs.add(part)
    items = sorted(subs)
    if emit:
        emit(f"  ✓ crtsh online finished ({len(items)} names)")
    findings = []
    if items:
        findings.append(
            _finding(
                "crtsh",
                f"[online:crtsh] {len(items)} CT name(s)",
                domain,
                "Certificate Transparency via crt.sh",
                "\n".join(items[:50]),
                items,
            )
        )
    return items, findings


async def online_hackertarget_hostsearch(domain: str, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if emit:
        emit(f"  → using online tool: subfinder/amass-equivalent  via api.hackertarget.com/hostsearch/")
    code, body = await _aget(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}", timeout=30)
    if code != 200 or "error" in body.lower()[:80]:
        if emit:
            emit(f"  ✗ hackertarget hostsearch: {body[:120]}")
        return [], []
    subs: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        host = line.split(",", 1)[0].strip().lower()
        if domain in host:
            subs.add(host)
    items = sorted(subs)
    if emit:
        emit(f"  ✓ hackertarget hostsearch finished ({len(items)} hosts)")
    findings = []
    if items:
        findings.append(
            _finding(
                "subfinder",
                f"[online:hackertarget] {len(items)} host(s)",
                domain,
                "Host search via api.hackertarget.com (subfinder/amass-like).",
                "\n".join(items[:50]),
                items,
            )
        )
    return items, findings


async def online_wayback(domain: str, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if emit:
        emit(f"  → using online tool: waybackurls/gau  via web.archive.org CDX API")
    cdx = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={quote(domain)}/*&output=json&fl=original&collapse=urlkey&limit=200"
    )
    code, body = await _aget(cdx, timeout=45)
    urls: list[str] = []
    if code == 200 and body.strip():
        try:
            data = json.loads(body)
            # first row is header
            for row in data[1:] if isinstance(data, list) and data else []:
                if row and isinstance(row, list):
                    urls.append(row[0])
                elif isinstance(row, str):
                    urls.append(row)
        except json.JSONDecodeError:
            urls = [ln.strip() for ln in body.splitlines() if ln.startswith("http")]
    urls = sorted(set(urls))
    if emit:
        emit(f"  ✓ wayback CDX finished ({len(urls)} URLs)")
    findings = []
    if urls:
        findings.append(
            _finding(
                "waybackurls",
                f"[online:wayback] {len(urls)} archived URL(s)",
                domain,
                "Wayback Machine CDX API (waybackurls / gau equivalent).",
                "\n".join(urls[:50]),
                urls,
            )
        )
    return urls, findings


async def online_otx(domain: str, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if emit:
        emit(f"  → using online tool: gau/OTX  via otx.alienvault.com")
    code, body = await _aget(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/url_list?limit=100",
        timeout=30,
    )
    urls: list[str] = []
    if code == 200:
        try:
            data = json.loads(body)
            for item in data.get("url_list") or []:
                u = item.get("url") if isinstance(item, dict) else None
                if u:
                    urls.append(u)
        except json.JSONDecodeError:
            pass
    urls = sorted(set(urls))
    if emit:
        emit(f"  ✓ OTX finished ({len(urls)} URLs)")
    findings = []
    if urls:
        findings.append(
            _finding(
                "gau",
                f"[online:otx] {len(urls)} URL(s)",
                domain,
                "AlienVault OTX URL list (gau-like).",
                "\n".join(urls[:50]),
                urls,
            )
        )
    return urls, findings


async def online_dnsx(host: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: dnsx  via dns.google/resolve?name={host}")
    code, body = await _aget(f"https://dns.google/resolve?name={quote(host)}&type=A", timeout=15)
    records: list[str] = []
    if code == 200:
        try:
            data = json.loads(body)
            for ans in data.get("Answer") or []:
                records.append(f"{ans.get('name', host)} {ans.get('type')} {ans.get('data')}")
        except json.JSONDecodeError:
            pass
    if emit:
        emit(f"  ✓ dns.google finished ({len(records)} records)")
    if not records:
        return []
    return [
        _finding(
            "dnsx",
            f"[online:dns.google] DNS for {host}",
            host,
            "DNS-over-HTTPS via dns.google (dnsx equivalent).",
            "\n".join(records),
            records,
        )
    ]


async def online_hackertarget_dns(domain: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: dns  via api.hackertarget.com/dnslookup/")
    code, body = await _aget(f"https://api.hackertarget.com/dnslookup/?q={quote(domain)}", timeout=20)
    if code != 200 or not body.strip() or body.lower().startswith("error"):
        if emit:
            emit(f"  ✗ hackertarget dns: {body[:100]}")
        return []
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    if emit:
        emit(f"  ✓ hackertarget dns finished ({len(lines)} lines)")
    return [
        _finding(
            "dnsx",
            f"[online:hackertarget-dns] records for {domain}",
            domain,
            "DNS lookup via api.hackertarget.com.",
            "\n".join(lines[:40]),
            lines,
        )
    ]


async def online_hackertarget_whois(domain: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: whois  via api.hackertarget.com/whois/")
    code, body = await _aget(f"https://api.hackertarget.com/whois/?q={quote(domain)}", timeout=25)
    if code != 200 or not body.strip():
        return []
    if emit:
        emit("  ✓ hackertarget whois finished")
    return [
        _finding(
            "metabigor",
            f"[online:whois] registration for {domain}",
            domain,
            "WHOIS via api.hackertarget.com.",
            body[:1500],
            [ln.strip() for ln in body.splitlines() if ln.strip()][:40],
        )
    ]


async def online_hackertarget_headers(url: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: whatweb/headers  via api.hackertarget.com/httpheaders/")
    code, body = await _aget(f"https://api.hackertarget.com/httpheaders/?q={quote(url)}", timeout=20)
    if code != 200 or not body.strip() or body.lower().startswith("error"):
        return []
    if emit:
        emit("  ✓ hackertarget headers finished")
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    return [
        _finding(
            "whatweb",
            f"[online:headers] HTTP headers for {url}",
            url,
            "HTTP header fetch via api.hackertarget.com (whatweb-like).",
            "\n".join(lines[:40]),
            lines,
        )
    ]


async def online_hackertarget_pagelinks(url: str, emit: Emit = None) -> tuple[list[str], list[Finding]]:
    if emit:
        emit(f"  → using online tool: katana/hakrawler  via api.hackertarget.com/pagelinks/")
    code, body = await _aget(f"https://api.hackertarget.com/pagelinks/?q={quote(url)}", timeout=25)
    if code != 200 or body.lower().startswith("error"):
        if emit:
            emit(f"  ✗ pagelinks: {body[:100]}")
        return [], []
    links = sorted({ln.strip() for ln in body.splitlines() if ln.strip().startswith("http")})
    if emit:
        emit(f"  ✓ pagelinks finished ({len(links)} links)")
    findings = []
    if links:
        findings.append(
            _finding(
                "katana",
                f"[online:pagelinks] {len(links)} link(s)",
                url,
                "Page link extraction via api.hackertarget.com (katana/hakrawler-like).",
                "\n".join(links[:50]),
                links,
            )
        )
    return links, findings


async def online_hackertarget_nmap(host: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: nmap/naabu  via api.hackertarget.com/nmap/")
    code, body = await _aget(f"https://api.hackertarget.com/nmap/?q={quote(host)}", timeout=60)
    if code != 200 or not body.strip() or body.lower().startswith("error"):
        if emit:
            emit(f"  ✗ online nmap: {body[:120]}")
        return []
    if emit:
        emit("  ✓ hackertarget nmap finished")
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    return [
        _finding(
            "nmap",
            f"[online:nmap] port scan for {host}",
            host,
            "Port scan via api.hackertarget.com/nmap/ (rate-limited free tier).",
            "\n".join(lines[:50]),
            lines,
            category=Category.RECON,
        )
    ]


async def online_hackertarget_reversedns(host: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: hakrevdns  via api.hackertarget.com/reversedns/")
    code, body = await _aget(f"https://api.hackertarget.com/reversedns/?q={quote(host)}", timeout=25)
    if code != 200 or not body.strip() or body.lower().startswith("error"):
        return []
    if emit:
        emit("  ✓ reversedns finished")
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    return [
        _finding(
            "hakrevdns",
            f"[online:reversedns] results for {host}",
            host,
            "Reverse DNS via api.hackertarget.com.",
            "\n".join(lines[:40]),
            lines,
        )
    ]


async def online_urlscan(domain: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: httpx/gowitness  via urlscan.io/api/v1/search/")
    code, body = await _aget(
        f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=10",
        timeout=30,
    )
    if code != 200:
        if emit:
            emit(f"  ✗ urlscan: {body[:120]}")
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    results = data.get("results") or []
    if emit:
        emit(f"  ✓ urlscan finished ({len(results)} results)")
    if not results:
        return []
    extracted = []
    for r in results[:20]:
        page = r.get("page") or {}
        extracted.append(f"{page.get('url') or r.get('task', {}).get('url')} [{page.get('status')}]")
    return [
        _finding(
            "httpx",
            f"[online:urlscan] {len(results)} result(s) for {domain}",
            domain,
            "urlscan.io search (httpx / gowitness-like surface).",
            "\n".join(extracted[:30]),
            extracted,
        )
    ]


async def online_robots(url: str, emit: Emit = None) -> list[Finding]:
    base = url.rstrip("/")
    robots_url = f"{base}/robots.txt" if "://" in base else f"https://{base}/robots.txt"
    if emit:
        emit(f"  → using online tool: roboxtractor  via {robots_url}")
    code, body = await _aget(robots_url, timeout=15)
    if code != 200 or not body.strip():
        if emit:
            emit("  · robots.txt not found / empty")
        return []
    if emit:
        emit("  ✓ robots.txt fetched")
    paths = re.findall(r"(?i)(?:allow|disallow)\s*:\s*(\S+)", body)
    return [
        _finding(
            "roboxtractor",
            f"[online:robots] {len(paths)} path(s) in robots.txt",
            robots_url,
            "Direct robots.txt fetch (roboxtractor equivalent).",
            body[:1500],
            paths,
        )
    ]


async def online_direct_probe(url: str, emit: Emit = None) -> list[Finding]:
    if emit:
        emit(f"  → using online tool: httpx/whatweb  via direct HTTPS probe")
    code, body = await _aget(url, timeout=20)
    if not code:
        if emit:
            emit(f"  ✗ direct probe failed: {body[:100]}")
        return []
    if emit:
        emit(f"  ✓ direct probe finished (HTTP {code})")
    # crude tech hints from body
    techs = []
    low = body[:5000].lower()
    for needle, name in (
        ("wp-content", "WordPress"),
        ("shopify", "Shopify"),
        ("react", "React"),
        ("next.js", "Next.js"),
        ("django", "Django"),
        ("laravel", "Laravel"),
        ("jquery", "jQuery"),
    ):
        if needle in low:
            techs.append(name)
    return [
        _finding(
            "httpx",
            f"[online:probe] {url} → HTTP {code}",
            url,
            "Direct HTTP probe (httpx / whatweb-like).",
            f"status={code}; techs={techs or 'n/a'}; body_len={len(body)}",
            [f"status={code}"] + techs,
        )
    ]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_online_tools(
    base_url: str,
    emit: Emit = None,
    groups: list[str] | None = None,
) -> tuple[list[Finding], dict[str, object]]:
    """Run online backends for the selected tool groups."""
    from .integrations import groups_enabled

    enabled = groups_enabled(groups)
    host = _host(base_url)
    domain = _domain(host)
    findings: list[Finding] = []
    recon: dict[str, object] = {}
    all_subs: set[str] = set()
    all_urls: set[str] = set()

    if emit:
        emit(f"Online tools mode — using public web APIs for groups: {', '.join(sorted(enabled))}")
        emit("  (Active scanners like sqlmap/nuclei/ffuf have no safe public online API;")
        emit("   install those locally if needed.)")

    # Always useful CT + DNS + archives for recon/http
    if "recon" in enabled or "http" in enabled:
        for coro in (
            online_crtsh(domain, emit=emit),
            online_hackertarget_hostsearch(domain, emit=emit),
        ):
            try:
                subs, finds = await coro
                all_subs.update(subs)
                findings.extend(finds)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ online subdomain error: {exc}")

        for coro in (
            online_wayback(domain, emit=emit),
            online_otx(domain, emit=emit),
        ):
            try:
                urls, finds = await coro
                all_urls.update(urls)
                findings.extend(finds)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ online URL harvest error: {exc}")

        for coro in (
            online_dnsx(host, emit=emit),
            online_hackertarget_dns(domain, emit=emit),
            online_hackertarget_whois(domain, emit=emit),
            online_hackertarget_reversedns(host, emit=emit),
        ):
            try:
                findings.extend(await coro)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ online DNS/whois error: {exc}")

    if "http" in enabled or "recon" in enabled:
        for coro in (
            online_hackertarget_headers(base_url, emit=emit),
            online_hackertarget_pagelinks(base_url, emit=emit),
            online_urlscan(domain, emit=emit),
            online_robots(base_url, emit=emit),
            online_direct_probe(base_url, emit=emit),
        ):
            try:
                res = await coro
                if isinstance(res, tuple):
                    urls, finds = res
                    all_urls.update(urls)
                    findings.extend(finds)
                else:
                    findings.extend(res)
            except Exception as exc:  # noqa: BLE001
                if emit:
                    emit(f"  ✗ online http tool error: {exc}")

    if "network" in enabled:
        try:
            findings.extend(await online_hackertarget_nmap(host, emit=emit))
        except Exception as exc:  # noqa: BLE001
            if emit:
                emit(f"  ✗ online nmap error: {exc}")

    if "vuln" in enabled and emit:
        emit("  · online vuln scanners (nuclei/sqlmap/dalfox/…): not available via public API")
        emit("    → install locally: https://github.com/projectdiscovery/nuclei  https://sqlmap.org")
        for name in ("nuclei", "sqlmap", "dalfox", "ffuf", "dirsearch"):
            meta = ONLINE_CATALOG.get(name, {})
            if meta.get("url"):
                emit(f"    · {name}: {meta.get('service')} — {meta['url']}")

    if "osint" in enabled and emit:
        emit("  · sherlock: use https://whatsmyname.app in a browser, or install sherlock locally")

    if all_subs:
        recon["subdomains"] = sorted(all_subs)
    if all_urls:
        recon["wayback_urls"] = sorted(all_urls)[:500]
        recon["discovered_urls"] = sorted(all_urls)[:500]

    return findings, recon


def print_online_catalog(emit: Emit = None) -> None:
    """List local tool → online service mapping in the terminal."""
    lines = ["Online tool map (local binary → web service):", ""]
    for name, meta in sorted(ONLINE_CATALOG.items()):
        svc = meta.get("service") or "(none)"
        url = meta.get("url") or ""
        line = f"  {name:20s} → {svc}"
        if url:
            line += f"  [{url}]"
        lines.append(line)
    if emit:
        for ln in lines:
            emit(ln)
    else:
        print("\n".join(lines))
