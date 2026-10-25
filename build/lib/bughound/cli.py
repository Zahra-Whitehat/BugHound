"""Command-line interface for bughound."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table

from .authorization import AuthorizationError, load_scope
from .engine import run_scan
from .models import ScanConfig
from .modules.base import REGISTRY, load_all_modules
from .reporting import to_json, to_markdown

console = Console()


def _normalize_host_entry(raw: str) -> str:
    """Normalize an --authorize-host entry to a bare hostname/glob.

    Operators paste URLs ('https://host/'), host:port, or trailing slashes;
    all of them must match the plain hostname the authorization gate compares
    against. Globs ('*.example.com') pass through untouched.
    """
    h = (raw or "").strip()
    if not h:
        return ""
    if "://" in h or "/" in h:
        from urllib.parse import urlparse

        h = urlparse(h if "://" in h else f"http://{h}").hostname or ""
    elif ":" in h and "*" not in h:
        h = h.split(":", 1)[0]  # host:port (not a glob)
    return (h or "").strip().lower()


@click.group()
@click.version_option()
def main() -> None:
    """bughound: authorized web-vulnerability hunting agent."""


@main.command("list-modules")
def list_modules() -> None:
    """List available scanner modules."""

    load_all_modules()
    table = Table(title="bughound modules")
    table.add_column("Name")
    table.add_column("Mode")
    table.add_column("Categories")
    for name, cls in sorted(REGISTRY.items()):
        mode = "aggressive" if cls.aggressive_required else ("passive" if cls.passive else "active")
        cats = ", ".join(c.value for c in cls.categories)
        table.add_row(name, mode, cats)
    console.print(table)


@main.command()
@click.argument("url")
@click.option("--scope", "scope_file", type=click.Path(exists=True), help="YAML scope file.")
@click.option("--authorize-host", "authorize_hosts", multiple=True, help="Host/glob you are authorized to test.")
@click.option("--deny-host", "deny_hosts", multiple=True, help="Host/glob that is forbidden and must never be contacted (overrides scope).")
@click.option("--deny-url", "deny_urls", multiple=True, help="URL/prefix that is forbidden and must never be contacted (overrides scope).")
@click.option("--i-am-authorized", is_flag=True, help="Confirm you are authorized to test this target.")
@click.option("--aggressive/--safe", default=False, help="Enable active exploitation payloads (authorized only).")
@click.option(
    "--no-exploit",
    is_flag=True,
    help="Disable the exploit phase (detection-only). Exploits only ever run together with --aggressive.",
)
@click.option("--max-urls", default=40, show_default=True)
@click.option("--max-depth", default=2, show_default=True)
@click.option(
    "--timeout",
    default=30.0,
    show_default=True,
    help="Per-request HTTP timeout in seconds. Increase for slow / asleep targets (labs, serverless).",
)
@click.option(
    "--user-agent",
    "user_agent",
    default=None,
    help="Override the User-Agent string (default: a recent Chrome UA). Some sites block non-browser agents.",
)
@click.option("--module", "modules", multiple=True, help="Only run these modules.")
@click.option("--no-external", is_flag=True, help="Do not run external tools (nuclei/nmap/sqlmap).")
@click.option("--out", "out_dir", default="reports", show_default=True, help="Output directory.")
@click.option("--header", "headers", multiple=True, help="Extra request header 'Name: value'.")
@click.option(
    "--source-dir",
    "source_dir",
    type=click.Path(file_okay=False),
    default="",
    help="Path to the target application's source code. Pinpoints the vulnerable file/line/sink for every finding in the report.",
)
@click.option(
    "--exploit-endpoint",
    "exploit_endpoints",
    multiple=True,
    help="Operator-designated URL to push through the full exploit chain (use when you already know the vulnerable endpoint, e.g. a lab's /filter). Repeatable.",
)
@click.option(
    "--exploit-param",
    "exploit_param",
    default="",
    help="Parameter name to inject on --exploit-endpoint targets (e.g. category). Defaults to the first query parameter in the URL.",
)
@click.option(
    "--exploit-method",
    "exploit_method",
    default="",
    help="HTTP method for --exploit-endpoint targets (default: GET, or POST when --exploit-body is given).",
)
@click.option(
    "--exploit-body",
    "exploit_body",
    default="",
    help=(
        "Raw request body template for --exploit-endpoint targets (XML/JSON endpoints). "
        "Put {INJ} where the payload goes, e.g. '<stockCheck><productId>1</productId>"
        "<storeId>{INJ}</storeId></stockCheck>'. Implies POST."
    ),
)
@click.option(
    "--exploit-content-type",
    "exploit_content_type",
    default="",
    help="Content-Type for --exploit-body (e.g. application/xml). Default: application/xml when the body starts with '<'.",
)
@click.option(
    "--exploit-encode",
    "exploit_encode",
    type=click.Choice(["", "none", "xml-entities"], case_sensitive=False),
    default="",
    help=(
        "Payload encoding applied at the {INJ} position. 'xml-entities' = numeric "
        "character references (bypasses filters that scan the raw body for SQL keywords)."
    ),
)
@click.option(
    "--debug",
    is_flag=True,
    help="Verbose logging: print every request URL + status + failure reason.",
)
def scan(url, scope_file, authorize_hosts, deny_hosts, deny_urls, i_am_authorized, aggressive,
         no_exploit, max_urls, max_depth, timeout, user_agent, modules, no_external, out_dir, headers,
         source_dir, exploit_endpoints, exploit_param, exploit_method, exploit_body,
         exploit_content_type, exploit_encode, debug) -> None:
    """Scan a URL for vulnerabilities, exploit findings to prove impact, and write reports."""

    extra_headers = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    # Normalize operator-supplied hosts so 'https://host/', 'host:443' and
    # bare 'host' all authorize identically.
    cli_hosts = [h for h in (_normalize_host_entry(x) for x in authorize_hosts) if h]

    # Auto-scope fallback: --i-am-authorized asserts authorization for the
    # target the operator typed. Requiring a *second* flag (--authorize-host)
    # repeated the same host and produced a confusing 'not in authorized
    # scope' error whenever it was forgotten. When NO scope source is given,
    # the target host is therefore added automatically (denylist still
    # overrides; an explicit --authorize-host/--scope/env always wins).
    env_hosts = [h.strip() for h in os.environ.get("BUGHOUND_AUTHORIZED_HOSTS", "").split(",") if h.strip()]
    if i_am_authorized and not cli_hosts and not scope_file and not env_hosts:
        from .authorization import host_of

        target_host = host_of(url)
        cli_hosts = [target_host]
        console.print(
            f"[yellow]No --authorize-host/--scope given: auto-scoping to the target host "
            f"{target_host!r} (--i-am-authorized). Pass --authorize-host explicitly to "
            f"declare a wider scope.[/yellow]"
        )

    scope = load_scope(
        scope_file=scope_file,
        explicit_hosts=cli_hosts,
        denied_hosts=list(deny_hosts),
        denied_urls=list(deny_urls),
    )
    enc = (exploit_encode or "").strip().lower()
    enc = "" if enc in ("", "none") else enc
    config = ScanConfig(
        target_url=url,
        max_urls=max_urls,
        max_depth=max_depth,
        timeout=timeout,
        aggressive=aggressive,
        exploit=not no_exploit,
        modules=list(modules) or None,
        extra_headers=extra_headers,
        use_external_tools=not no_external,
        user_agent=user_agent or ScanConfig.model_fields["user_agent"].default,
        source_dir=source_dir,
        exploit_endpoints=list(exploit_endpoints),
        exploit_param=exploit_param,
        exploit_method=exploit_method,
        exploit_body=exploit_body,
        exploit_content_type=exploit_content_type,
        exploit_encode=enc,
    )

    exploit_on = aggressive and config.exploit
    console.print(f"[bold]bughound[/bold] scanning [cyan]{url}[/cyan] "
                  f"({'aggressive' if aggressive else 'safe'} mode, "
                  f"exploit phase {'on' if exploit_on else 'off'}, "
                  f"timeout={config.timeout}s)")
    if exploit_endpoints and exploit_on:
        for ep in exploit_endpoints:
            extra = ""
            if exploit_body:
                extra = f" (body template, encode={config.exploit_encode or 'none'})"
            elif exploit_param:
                extra = f" (param: {exploit_param})"
            console.print(f"  [magenta]direct exploit target:[/magenta] {ep}{extra}")
    if not aggressive:
        console.print(
            "[yellow]Safe mode: active detection AND the exploit phase are "
            "disabled.[/yellow] To detect and prove vulnerabilities "
            "(credential extraction, hidden-data reveal, account-takeover "
            "proofs), re-run with:\n"
            f"  bughound scan {url} --authorize-host <host> --i-am-authorized --aggressive"
        )
    if exploit_endpoints and not exploit_on:
        console.print(
            "[yellow]--exploit-endpoint was given but the exploit phase is OFF "
            "(safe mode or --no-exploit). The designated targets will NOT be "
            "exploited. Re-run with --aggressive to enable exploitation.[/yellow]"
        )

    try:
        result = asyncio.run(
            run_scan(config, scope, confirmed=i_am_authorized, progress=lambda m: console.log(m))
        )
    except AuthorizationError as exc:
        console.print(f"[bold red]Authorization error:[/bold red] {exc}")
        sys.exit(2)

    _print_summary(result)

    # Exploit outcomes: a dedicated block so exploitation results are
    # impossible to miss in the console.
    exploited = [f for f in result.findings if f.exploit_status == "succeeded"]
    if exploited:
        console.print("\n[bold green]Exploit results (details in the report):[/bold green]")
        for f in exploited:
            extra = f"; extracted {len(f.extracted_data)} artifact(s)" if f.extracted_data else ""
            console.print(f"  [green]\u2713[/green] {f.title}{extra}")
    if result.stats.get("fp_flagged"):
        console.print(
            f"[yellow]False-positive verification flagged {result.stats['fp_flagged']} "
            "finding(s) -- see the 'False-positive analysis' section in the report.[/yellow]"
        )

    # If the target was unreachable / produced zero findings AND zero errors
    # in the module list, surface a hint so the operator knows what to try
    # next instead of staring at an empty table.
    if not result.findings and not result.modules_run:
        console.print(
            "\n[yellow]No findings and no modules ran.[/yellow] The target was "
            "unreachable. See the errors section above for the exact failure "
            "reason. Common fixes: pass --timeout 60 (labs / serverless may "
            "need >15s to wake up), or --user-agent '<a browser UA>' if the "
            "host blocks non-browser agents."
        )

    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    host = result.target.host or "target"
    base = os.path.join(out_dir, f"{host}-{stamp}")
    with open(base + ".json", "w") as fh:
        fh.write(to_json(result))
    with open(base + ".md", "w") as fh:
        fh.write(to_markdown(result))
    console.print(f"\n[green]Reports written:[/green] {base}.md , {base}.json")


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True)
def serve(host, port) -> None:
    """Run the web service + dashboard."""

    import uvicorn

    uvicorn.run("bughound.web:app", host=host, port=port, reload=False)


# Row color by severity -- brightest/boldest for what needs attention first.
SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _print_summary(result) -> None:
    table = Table(title="Findings")
    table.add_column("Module")
    table.add_column("Sev")
    table.add_column("Class")
    table.add_column("Title")
    table.add_column("URL", overflow="fold")
    table.add_column("Verified")

    # Group rows by the module that produced them, most-severe first within
    # each group. A visible section divider separates one module's block of
    # findings from the next.
    findings = sorted(result.sorted_findings, key=lambda f: (f.module, -f.severity.rank))

    current_module = None
    for f in findings:
        if current_module is not None and f.module != current_module:
            table.add_section()
        current_module = f.module

        style = SEVERITY_STYLES.get(f.severity.value.lower(), "")
        verified_cell = "yes" if f.verified else f.confidence
        if f.fp_risk and f.fp_risk != "low":
            verified_cell += f" (FP-risk: {f.fp_risk})"
        table.add_row(
            f.module,
            f.severity.value.upper(),
            f.category.value,
            f.title,
            f.url,
            verified_cell,
            style=style,
        )
    console.print(table)
    if result.errors:
        console.print("[yellow]Notes:[/yellow]")
        for e in result.errors:
            console.print(f"  - {e}")


if __name__ == "__main__":
    main()
