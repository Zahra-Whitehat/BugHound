"""Shared helpers for the passive recon modules.

These utilities are intentionally dependency-free: they go through the same
``HttpClient`` the rest of bughound uses (so the denylist still applies) and
fall back to public DNS-over-HTTPS (DoH) resolvers for DNS record lookups so
the agent does not need ``dnspython`` or system ``dig``/``nslookup`` binaries.

All functions are network-tolerant: on any error they return an empty / None
value rather than raising, so a flaky resolver never aborts a scan.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

# Public DoH endpoints. We try them in order; the first that returns a valid
# JSON answer wins. Both Cloudflare and Google are free, fast, and CORS-open.
DOH_ENDPOINTS: list[str] = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# DNS record types we care about for recon. ``CAA`` reveals certificate
# issuers allowed for the domain (useful for subdomain-takeover triage);
# ``SOA`` reveals the primary nameserver; ``MX``/``TXT`` reveal mail posture
# (SPF/DMARC live in TXT records).
DNS_RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "TXT", "NS", "CAA", "SOA"]


def register_domain_of(url: str) -> str:
    """Return the eTLD+1 (registerable domain) for ``url``.

    Falls back to the bare hostname when no public suffix list is available --
    correct for the common single-label / private-DNS case bughound is usually
    pointed at. Examples: ``https://api.www.example.com`` -> ``example.com``;
    ``http://localhost:8081`` -> ``localhost``.
    """

    host = (urlparse(url if "://" in url else f"http://{url}").hostname or url).lower()
    if host in {"localhost", "127.0.0.1", "::1"} or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    parts = host.split(".")
    # Heuristic eTLD+1: last two labels (works for example.com, fails for
    # co.uk-style TLDs; acceptable trade-off for a dependency-free impl).
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def is_same_registerable(subhost: str, registerable: str) -> bool:
    """True if ``subhost`` ends in ``.registerable`` or equals it."""
    subhost = subhost.lower().rstrip(".")
    registerable = registerable.lower()
    return subhost == registerable or subhost.endswith("." + registerable)


async def doh_lookup(
    name: str,
    rtype: str,
    fetch: Callable[[str, dict[str, str]], Awaitable[tuple[bool, str, dict[str, str]]]],
) -> list[str]:
    """Resolve ``name`` / ``rtype`` via DNS-over-HTTPS.

    ``fetch(url, headers) -> (ok, body, headers)`` is the HTTP primitive the
    caller supplies (normally ``HttpClient.request`` wrapped in a shim) so this
    helper stays decoupled from the concrete HTTP client and the denylist
    keeps applying transparently.

    Returns a list of stringified answers (e.g. IPs for A, ``10 mail.example.com.``
    for MX, raw TXT strings). Empty on any failure.
    """

    # Cloudflare requires the DoH JSON accept header; Google accepts plain JSON.
    # We attempt Cloudflare first (POST is also accepted, but GET with ?type= is
    # the simplest path), then Google's resolve endpoint as a fallback.
    for endpoint in DOH_ENDPOINTS:
        try:
            if "cloudflare" in endpoint:
                url = f"{endpoint}?name={name}&type={rtype}"
                headers = {"accept": "application/dns-json"}
            else:  # Google
                url = f"{endpoint}?name={name}&type={rtype}"
                headers = {"accept": "application/dns-json"}
            ok, body, _ = await fetch(url, headers)
            if not ok or not body:
                continue
            data = json.loads(body)
            answers = data.get("Answer") or []
            return [str(a.get("data", "")) for a in answers if a.get("data")]
        except Exception:  # noqa: BLE001 - never raise from recon helpers
            continue
    return []


async def crt_sh_subdomains(
    domain: str,
    fetch: Callable[[str], Awaitable[tuple[bool, str]]],
) -> list[str]:
    """Query crt.sh's Certificate Transparency log for subdomains of ``domain``.

    ``fetch(url) -> (ok, body)`` is supplied by the caller (HttpClient wrapper).

    Returns a de-duplicated list of subdomain hostnames. Empty on any failure
    (crt.sh is sometimes slow / rate-limited; we treat that as "no data" rather
    than an error so the rest of the scan proceeds).
    """

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        ok, body = await fetch(url)
        if not ok or not body:
            return []
        # crt.sh returns a JSON array of objects with a ``name_value`` field
        # containing one or more newline-separated SAN entries.
        entries = json.loads(body)
    except Exception:  # noqa: BLE001
        return []

    found: set[str] = set()
    for entry in entries:
        names = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for name in str(names).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name and is_same_registerable(name, domain):
                found.add(name)
    return sorted(found)


# A small, curated fingerprint catalog inspired by Wappalyzer. Each entry is
# (category, product-name, list-of-header-key-needle triples, optional-cookie-
# name-needle, optional-html-needle). Keep entries tolerant to false positives:
# prefer distinctive strings over generic ones.
TECH_FINGERPRINTS: list[tuple[str, str, list[tuple[str, str]], str | None, str | None]] = [
    # (category, product, [(header, needle)], cookie, html_needle)
    ("Web server", "nginx", [("server", "nginx")], None, None),
    ("Web server", "Apache", [("server", "apache")], None, None),
    ("Web server", "Microsoft IIS", [("server", "microsoft-iis")], None, None),
    ("Web server", "LiteSpeed", [("server", "litespeed")], None, None),
    ("Language", "PHP", [("x-powered-by", "php")], "PHPSESSID", None),
    ("Language", "ASP.NET", [("x-powered-by", "asp.net"), ("x-aspnet-version", "")], "ASP.NET_SessionId", None),
    ("Language", "Java", [("x-powered-by", "jsp"), ("server", "tomcat")], "JSESSIONID", None),
    ("Language", "Python", [("server", "gunicorn"), ("server", "uvicorn"), ("server", "werkzeug")], None, None),
    ("Language", "Ruby", [("server", "ruby"), ("x-powered-by", "ruby")], None, None),
    ("Language", "Node.js", [("x-powered-by", "express")], None, None),
    ("Framework", "Django", [("x-frame-options", "")], "csrftoken", 'name="csrfmiddlewaretoken"'),
    ("Framework", "Ruby on Rails", [("x-powered-by", "rails")], "_rails_session", 'name="authenticity_token"'),
    ("Framework", "Laravel", [], "laravel_session", None),
    ("Framework", "Symfony", [], None, "symfony"),
    ("Framework", "Spring", [], "JSESSIONID", None),
    ("Framework", "ASP.NET MVC", [("x-aspnetmvc-version", "")], None, None),
    ("Framework", "Express", [("x-powered-by", "express")], None, None),
    ("Framework", "Next.js", [("x-powered-by", "next")], None, "__next"),
    ("Framework", "Nuxt", [("x-powered-by", "nuxt")], None, "__nuxt"),
    ("CMS", "WordPress", [], "wordpress", 'content="WordPress'),
    ("CMS", "Drupal", [], None, 'name="form_build_id"'),
    ("CMS", "Joomla", [], None, "joomla"),
    ("CMS", "Ghost", [("x-ghost-cache-status", "")], "ghost-admin-api-session", None),
    ("CMS", "Magento", [], None, "Mage.Cookies"),
    ("CMS", "Shopify", [("x-shopify-stage", ""), ("x-shopid", "")], None, "cdn.shopify.com"),
    ("CMS", "Hugo", [], None, 'meta name="generator" content="Hugo'),
    ("CMS", "Jekyll", [], None, 'meta name="generator" content="Jekyll'),
    ("E-commerce", "WooCommerce", [], None, "woocommerce"),
    ("Analytics", "Google Analytics", [], None, "google-analytics.com"),
    ("Analytics", "Google Tag Manager", [], None, "googletagmanager.com"),
    ("Analytics", "Matomo/Piwik", [], None, "matomo"),
    ("Analytics", "Mixpanel", [], None, "mixpanel"),
    ("CDN", "Cloudflare", [("server", "cloudflare"), ("cf-ray", "")], "__cf_bm", None),
    ("CDN", "Fastly", [("x-served-by", "cache-"), ("x-fastly", "")], None, None),
    ("CDN", "Akamai", [("x-akamai-transformed", ""), ("x-akamai-request-id", "")], None, None),
    ("CDN", "AWS CloudFront", [("via", "cloudfront"), ("x-amz-cf-id", "")], None, None),
    ("CDN", "Vercel", [("server", "vercel"), ("x-vercel-id", "")], None, None),
    ("CDN", "Netlify", [("server", "netlify")], None, None),
    ("CDN", "GitHub Pages", [("server", "github.io")], None, None),
    ("OS", "Ubuntu", [("server", "ubuntu")], None, None),
    ("OS", "Debian", [("server", "debian")], None, None),
    ("Database proxy", "phpMyAdmin", [], None, "phpmyadmin"),
    ("Database proxy", "Adminer", [], None, "adminer"),
    ("Reverse proxy", "Traefik", [("server", "traefik")], None, None),
    ("Reverse proxy", "HAProxy", [("server", "haproxy")], None, None),
    ("Reverse proxy", "Envoy", [("server", "envoy")], None, None),
    ("Reverse proxy", "Caddy", [("server", "caddy")], None, None),
    ("Container orchestrator", "Kubernetes", [], None, "kubernetes"),
    ("JS framework", "React", [], None, "react"),
    ("JS framework", "Vue", [], None, "vue"),
    ("JS framework", "Angular", [], None, "ng-app"),
    ("JS framework", "Svelte", [], None, "svelte"),
    ("JS framework", "Ember", [], None, 'id="ember"'),
    ("JS framework", "Backbone", [], None, "backbone"),
    ("JS library", "jQuery", [], None, "jquery"),
    ("JS library", "lodash", [], None, "lodash"),
    ("JS library", "Bootstrap", [], None, "bootstrap"),
    ("JS library", "Tailwind CSS", [], None, "tailwind"),
    ("JS library", "Bulma", [], None, "bulma"),
    ("JS library", "Moment.js", [], None, "moment"),
    ("JS library", "Axios", [], None, "axios"),
    ("Webmail", "Roundcube", [], None, "roundcube"),
    ("Webmail", "SquirrelMail", [], None, "squirrelmail"),
    ("Forum", "phpBB", [], None, "phpbb"),
    ("Forum", "Discourse", [], None, "discourse"),
    ("CRM/CMS", "Salesforce", [], None, "salesforce"),
    ("CRM/CMS", "HubSpot", [], None, "hubspot"),
    ("CRM/CMS", "Drupal Commerce", [], None, "commerce"),
    ("Statically rendered", "Gatsby", [], None, 'meta name="generator" content="Gatsby'),
    ("Statically rendered", "Astro", [], None, 'meta name="generator" content="Astro'),
    ("Statically rendered", "Docusaurus", [], None, "docusaurus"),
]

# WAF / CDN detection signatures (header -> product).
WAF_SIGNATURES: list[tuple[str, str, str]] = [
    # (header_lower, needle, product)
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("server", "cloudfront", "AWS CloudFront"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-akamai-transformed", "", "Akamai"),
    ("x-akamai-request-id", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    ("x-served-by", "cache-", "Fastly"),
    ("server", "imperva", "Imperva Incapsula"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("server", "sucuri", "Sucuri"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "f5 big-ip", "F5 BIG-IP ASM"),
    ("x-waf-event-id", "", "AWS WAF"),
    ("x-amzn-waf", "", "AWS WAF"),
    ("server", "barracuda", "Barracuda"),
    ("server", "fortinet", "Fortinet FortiWeb"),
    ("server", "fortiweb", "Fortinet FortiWeb"),
    ("x-cdn", "sucuri", "Sucuri"),
    ("x-cdn", "stackpath", "StackPath"),
    ("server", "stackpath", "StackPath"),
    ("server", "ddos-guard", "DDoS-Guard"),
    ("server", "arvancloud", "ArvanCloud"),
    ("server", "qcdn", "Qrator"),
    ("server", "edgecast", "Verizon Edgecast"),
    ("server", "yundun", "Alibaba Cloud WAF"),
    ("x-yd-info", "", "Alibaba Cloud WAF"),
    ("server", "tengine", "Alibaba Tengine"),
    ("x-cache", "akamai", "Akamai"),
    ("server", "section.io", "section.io"),
    ("x-section-io-id", "", "section.io"),
]
