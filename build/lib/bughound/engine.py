"""Scan orchestrator: authorization -> crawl -> modules -> external tools."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import integrations
from .authorization import Scope, authorize
from .crawler import crawl
from .codemapper import map_all_findings
from .exploits import run_exploit_phase
from .http_client import HttpClient
from .models import Category, Finding, ScanConfig, ScanResult, Severity, Target
from .modules.base import RequestTarget, ScanContext, build_modules
from .verification import run_verification_phase


def _make_target(url: str, note: str) -> Target:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    return Target(
        url=url,
        scheme=scheme,
        host=parsed.hostname or "",
        port=port,
        authorized=True,
        authorization_note=note,
    )


async def _probe_seed(client: HttpClient, url: str, emit) -> tuple[bool, str]:
    """Pre-flight the target URL with a single GET.

    Returns (ok, reason). On failure ``reason`` is a human-readable string the
    operator can act on. We do this BEFORE the main crawl so we can:

      1. Detect a slow / asleep target (PortSwigger labs, serverless cold
         starts) early and retry once with a longer per-request timeout.
      2. Surface a TLS error, DNS error, or 4xx/5xx at the very top of the
         scan log instead of letting the crawl silently return "0 URLs"
         and every module silently fail afterwards.
    """
    resp = await client.get(url, follow_redirects=True)
    if resp.ok:
        return True, ""
    if resp.error:
        return False, resp.error
    return False, f"HTTP {resp.status}"


async def run_scan(
    config: ScanConfig,
    scope: Scope,
    confirmed: bool,
    progress=None,
) -> ScanResult:
    """Run a full scan. Raises AuthorizationError if the target is out of scope."""

    def emit(msg: str) -> None:
        if progress:
            progress(msg)

    note = authorize(config.target_url, scope, confirmed)
    target = _make_target(config.target_url, note)
    result = ScanResult(target=target, config=config)

    client = HttpClient(
        timeout=config.timeout,
        user_agent=config.user_agent,
        extra_headers=config.extra_headers,
        blocked=scope.url_denied,
    )
    try:
        if scope.denied_hosts or scope.denied_urls:
            emit(
                f"Denylist active: {len(scope.denied_hosts)} host pattern(s), "
                f"{len(scope.denied_urls)} URL prefix(es) will never be contacted."
            )

        # Pre-flight probe: catch unreachable / asleep / TLS-broken targets
        # before the crawl. This is the fix for the silent "0 URLs" case.
        emit(f"Probing target {config.target_url} (timeout {config.timeout}s)...")
        ok, reason = await _probe_seed(client, config.target_url, emit)
        if not ok:
            # First probe failed. The most common cause for an authorized
            # target is a sleeping lab / cold start (PortSwigger academy,
            # serverless) that wakes up on the first hit. Retry once with
            # a longer timeout before giving up.
            emit(f"  initial probe failed: {reason}")
            emit("  retrying once with 2x timeout (target may be waking up)...")
            # Temporarily raise the timeout on the underlying httpx client.
            old_timeout = client._client.timeout
            try:
                client._client.timeout = config.timeout * 2
                ok, reason = await _probe_seed(client, config.target_url, emit)
            finally:
                client._client.timeout = old_timeout
        if not ok:
            # Target still unreachable -- record a clear top-of-scan error
            # so the operator knows exactly what to fix, instead of running
            # 18 modules against an empty context and producing nothing.
            msg = (
                f"Target unreachable after retry: {reason}. "
                "Suggestions: (1) open the URL in a browser to confirm it is "
                "live; (2) pass --timeout 60 (labs / serverless may need >15s "
                "to wake up); (3) pass --user-agent '<browser UA>' if the host "
                "blocks non-browser agents; (4) verify the host is in your "
                "authorized scope."
            )
            result.errors.append(msg)
            emit("Target unreachable -- aborting scan (see report for details).")
            return result
        emit("  probe OK, target is reachable. Crawling...")

        urls, request_targets, seed_html, seed_headers = await crawl(
            client,
            config.target_url,
            config.max_urls,
            config.max_depth,
            is_denied=scope.url_denied,
            log=emit,
        )
        ctx = ScanContext(
            client=client,
            config=config,
            target=target,
            base_url=config.target_url,
            urls=urls,
            request_targets=request_targets,
            seed_html=seed_html,
            seed_headers=seed_headers,
            log=emit,
        )
        result.stats = {"urls_crawled": len(urls), "injectable_targets": len(request_targets)}
        emit(f"Discovered {len(urls)} URLs, {len(request_targets)} injectable targets.")

        # Direct-exploit mode: --exploit-endpoint URLs are registered as
        # request targets and seeded as findings so the exploit phase works
        # them even when the crawler cannot see the parameter (cookie-only
        # labs, non-linked endpoints, obfuscated HTML...).
        if config.exploit_endpoints:
            _register_direct_targets(config, ctx, result, emit)

        modules = build_modules(config)
        sem = asyncio.Semaphore(max(1, config.concurrency))

        async def run_module(mod):
            async with sem:
                emit(f"Running module: {mod.name}")
                try:
                    return mod.name, await mod.run(ctx)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"{mod.name}: {type(exc).__name__}: {exc}")
                    return mod.name, []

        for name, findings in await asyncio.gather(*(run_module(m) for m in modules)):
            result.modules_run.append(name)
            for f in findings:
                result.add(f)

        # Merge any structured reconnaissance data the modules wrote into the
        # shared context. Modules run concurrently via ``asyncio.gather`` -- if
        # one module needs data produced by another it must fetch that data
        # itself rather than relying on ctx.recon (which is best-effort and
        # populated only when this loop completes).
        result.recon.update(ctx.recon)

        # Exploit phase: when aggressive mode is on (and not disabled via
        # --no-exploit), re-target each finding with a safe proof exploit so
        # the report demonstrates real impact instead of just asserting it.
        # Runs inside the same client/scope guardrails as everything else.
        if config.aggressive and config.exploit and result.findings:
            await run_exploit_phase(ctx, result.findings, emit)

        # False-positive verification: control experiments (negative
        # controls, repeat consistency, baseline cleanliness, fresh
        # canaries) for every finding the exploit phase could NOT prove --
        # a succeeded exploit is its own false-positive disproof.
        if config.aggressive and result.findings:
            to_verify = [f for f in result.findings if f.exploit_status != "succeeded" and f.category != Category.RECON]
            if to_verify:
                vstats = await run_verification_phase(ctx, to_verify, emit)
                result.stats["fp_verified"] = vstats.get("verified", 0)
                result.stats["fp_flagged"] = vstats.get("flagged", 0)

        # Code-location evidence: pin every finding to the vulnerable sink
        # (source mapping when --source-dir is given, inferred sink pattern
        # otherwise) so the report shows WHERE in the code the bug lives.
        mapped = map_all_findings(result, emit)
        if mapped:
            result.stats["code_mapped"] = mapped

        if config.use_external_tools:
            await _run_external(config, ctx, result, emit, scope)
    finally:
        await client.aclose()

    result.finished_at = datetime.now(timezone.utc)
    result.stats["findings"] = len(result.findings)
    result.stats["exploited"] = sum(1 for f in result.findings if f.exploit_status == "succeeded")
    return result


def _register_direct_targets(config: ScanConfig, ctx: ScanContext, result: ScanResult, emit) -> None:
    """Register --exploit-endpoint URLs as request targets + seed findings."""
    from urllib.parse import parse_qsl, urlparse

    for ep in config.exploit_endpoints:
        # Resolve bare paths ("/product/stock", "product/stock") against the
        # scan target so the direct target always carries scheme + host.
        # Previously "http://" + "/product/stock" produced the hostless URL
        # "http:///product/stock", whose every request fails silently (the
        # HTTP client maps invalid URLs to a status-0 response) and the whole
        # exploit chain quietly did nothing.
        if "://" in ep:
            parsed_ep = urlparse(ep)
        else:
            tgt = urlparse(config.target_url)
            path = ep if ep.startswith("/") else f"/{ep}"
            parsed_ep = urlparse(f"{tgt.scheme or 'http'}://{tgt.netloc}{path}")
        base = f"{parsed_ep.scheme}://{parsed_ep.netloc}{parsed_ep.path or '/'}"
        qs = dict(parse_qsl(parsed_ep.query))

        if config.exploit_body:
            # Raw-body mode (XML/JSON endpoints behind input filters): the
            # body template carries the {INJ} marker; payloads are substituted
            # there and optionally entity-encoded to bypass the filter.
            param = config.exploit_param or "INJ"
            base_value = qs.get(param, "1")  # numeric default fits lab-style ids
            rt = RequestTarget(
                url=base,
                method=(config.exploit_method or "POST").upper(),
                params={"INJ": base_value},
                source="direct",
                body_template=config.exploit_body,
                content_type=config.exploit_content_type
                or ("application/xml" if config.exploit_body.lstrip().startswith("<") else ""),
                encoding=config.exploit_encode or "",
            )
            ctx.request_targets = [t for t in ctx.request_targets if t.url != base] + [rt]
            finding = Finding(
                category=Category.SQLI,
                title=f"Direct-exploit target: injection surface in '{param}' (raw body)",
                severity=Severity.CRITICAL,
                confidence="firm",
                url=base,
                description=(
                    f"Operator-designated exploitation target: the raw-body parameter '{param}' "
                    f"on {base} (body template with {{INJ}} marker"
                    + (f", '{config.exploit_encode}' encoding" if config.exploit_encode else "")
                    + ") is worked through the full exploit chain (UNION extraction, "
                    "tautology reveal, boolean-blind extraction + credential login)."
                ),
                evidence=(
                    "designated by the operator via --exploit-endpoint --exploit-body; "
                    "exploit chain attempts logged below"
                ),
                request=f"{rt.method} {base} (body: {config.exploit_body} with {{INJ}}=<payload>)",
                remediation="Use parameterized queries / prepared statements; never build SQL from input.",
                cwe="CWE-89",
                module="direct-exploit",
                verified=False,
            )
            result.add(finding)
            emit(
                f"  [direct] registered raw-body exploitation target: {base} "
                f"(encode={config.exploit_encode or 'none'})"
            )
            continue

        param = config.exploit_param or (next(iter(qs), None))
        params = qs or ({param: "test"} if param else {})
        if not param:
            emit(f"  [direct] {ep}: no parameter given (use --exploit-param); skipping")
            continue
        rt = RequestTarget(
            url=base,
            method=(config.exploit_method or "GET").upper(),
            params=params,
            source="direct",
        )
        # Replace any duplicate discovered target for the same path.
        ctx.request_targets = [t for t in ctx.request_targets if t.url != base] + [rt]
        finding = Finding(
            category=Category.SQLI,
            title=f"Direct-exploit target: injection surface in '{param}'",
            severity=Severity.CRITICAL,
            confidence="firm",
            url=base,
            description=(
                f"Operator-designated exploitation target: parameter '{param}' on {base} "
                "is worked through the full exploit chain (UNION extraction, tautology "
                "reveal, boolean-blind extraction + credential login)."
            ),
            evidence="designated by the operator via --exploit-endpoint; exploit chain attempts logged below",
            request=f"{rt.method} {base} ({param}=<payload>)",
            remediation="Use parameterized queries / prepared statements; never build SQL from input.",
            cwe="CWE-89",
            module="direct-exploit",
            verified=False,
        )
        result.add(finding)
        emit(f"  [direct] registered exploitation target: {base} (param '{param}')")


async def _run_external(config, ctx, result, emit, scope) -> None:
    if scope.url_denied(config.target_url):
        result.errors.append("External tools skipped: target is on the denylist.")
        return
    host = integrations.host_from_url(config.target_url)
    missing = integrations.missing_tools_note()
    if missing:
        result.errors.append(f"External tools not installed (skipped): {', '.join(missing)}")

    tasks = [integrations.run_nuclei(config.target_url)]
    if config.aggressive:
        if not scope.host_denied(host):
            tasks.append(integrations.run_nmap(host))
        for rt in ctx.request_targets[:3]:
            if not scope.url_denied(rt.url):
                tasks.append(integrations.run_sqlmap(rt.url, rt.method, rt.params))
    emit("Running external tools (nuclei/nmap/sqlmap where available)...")
    for group in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(group, Exception):
            result.errors.append(f"external tool error: {group}")
            continue
        for f in group:
            result.add(f)
            if f.module not in result.modules_run:
                result.modules_run.append(f.module)
