"""Command-line interface for bughound."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.markup import escape as _rich_escape
from rich.table import Table

from .authorization import AuthorizationError, load_scope
from .engine import run_scan
from .modes import exploit_phase_enabled
from .models import ScanConfig
from .modules.base import REGISTRY, load_all_modules
from .reporting import to_json, to_markdown

console = Console()


def _run_single_scan(url: str, config: ScanConfig, scope, confirmed: bool, out_dir: str,
                     workspace: str = ""):
    """Run one scan and write its reports; shared by `scan` and `recon`."""
    try:
        result = asyncio.run(
            run_scan(config, scope, confirmed=confirmed, progress=lambda m: console.log(m))
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

    # Attack chains: the exploit-chainer's combined-impact findings.
    chained = [f for f in result.findings if f.chain_of]
    if chained:
        console.print("\n[bold magenta]Attack chains (combined-impact findings):[/bold magenta]")
        for f in chained:
            console.print(f"  [magenta]\u2693[/magenta] {_rich_escape(f.title)}")

    if not result.findings and not result.modules_run:
        console.print(
            "\n[yellow]No findings and no modules ran.[/yellow] The target was "
            "unreachable. See the errors section above for the exact failure "
            "reason. Common fixes: pass --timeout 60 (labs / serverless may "
            "need >15s to wake up), or --user-agent '<a browser UA>' if the "
            "host blocks non-browser agents."
        )

    # Sn1per-style workspaces: reports land under reports/<workspace>/ and a
    # 'latest' copy is kept for the diff-based continuous-monitoring flow.
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    host = result.target.host or "target"
    base = os.path.join(out_dir, f"{host}-{stamp}")
    with open(base + ".json", "w") as fh:
        fh.write(to_json(result))
    with open(base + ".md", "w") as fh:
        fh.write(to_markdown(result))
    console.print(f"\n[green]Reports written:[/green] {base}.md , {base}.json")
    if workspace:
        latest = os.path.join(out_dir, f"{host}-latest.json")
        with open(latest, "w") as fh:
            fh.write(to_json(result))
        console.print(
            f"[green]Workspace:[/green] {workspace} -- latest snapshot for "
            f"diffing: {latest} (run `bughound diff <old.json> {latest}` on the next run)"
        )
    return result


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


def _version() -> str:
    """Package version that works WITHOUT installing the package.

    click's default version_option imports metadata for the distribution,
    which raises ``RuntimeError: 'bughound' is not installed`` when the tool
    is run from an unzipped source tree (``python -m bughound``) -- the single
    most common way operators run it. Read the package's own __version__ and
    only fall back to the installed metadata.
    """
    from . import __version__

    return __version__


@click.group()
@click.version_option(version=_version(), prog_name="bughound")
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
        mode = "exploit-grade" if cls.exploit_grade else ("passive" if cls.passive else "active")
        cats = ", ".join(c.value for c in cls.categories)
        table.add_row(name, mode, cats)
    console.print(table)


@main.command("check")
@click.argument("url")
@click.option("--timeout", default=30.0, show_default=True, help="Per-request timeout (seconds).")
@click.option(
    "--wait",
    "wait_for_lab",
    type=int,
    default=0,
    metavar="SECONDS",
    help=(
        "Poll every 15s for up to SECONDS until the instance answers -- exits 0 "
        "the moment it is alive. Handy right after spawning a fresh lab."
    ),
)
def check_cmd(url: str, timeout: float, wait_for_lab: int) -> None:
    """Instant liveness verdict for a URL -- run this BEFORE a full scan.

    Answers the single question that kills most lab runs: is this
    PortSwigger Academy instance actually ALIVE? An expired instance
    (HTTP 504 "Gateway Timeout (0) connecting to ...") can never be
    solved -- check prints the verdict and the exact next steps.

    With --wait N a dead instance is re-probed every 15s for up to N
    seconds; the command exits 0 (alive) the moment the instance answers.
    """
    import time as _time

    from .http_client import HttpClient, lab_dead_response
    from .solving import detect_lab_html, is_academy_url

    async def _probe_once() -> tuple[str, str, str]:
        client = HttpClient(timeout=timeout)
        try:
            resp = await client.get(url, follow_redirects=True)
        finally:
            await client.aclose()
        if resp.error:
            return "unreachable", resp.error, ""
        if lab_dead_response(resp):
            return (
                "dead",
                f"the gateway cannot reach the lab backend (HTTP {resp.status}: "
                "instance stopped or expired)",
                "",
            )
        lab = detect_lab_html(resp.text or "")
        if resp.status_ok:
            if lab:
                status = "SOLVED" if lab.get("solved") else "not solved yet"
                return "alive", f"lab detected: {lab.get('title', 'unknown')} ({status})", ""
            note = "host is up, but no Academy lab banner was found" if is_academy_url(url) else ""
            return "alive", f"HTTP {resp.status}", note
        return "error", f"HTTP {resp.status}", ""

    async def _check() -> tuple[str, str, str]:
        verdict, detail, note = await _probe_once()
        budget = max(0, int(wait_for_lab or 0))
        if budget <= 0 or verdict == "alive":
            return verdict, detail, note
        # --wait N: keep polling a dead/booting instance until it answers.
        deadline = _time.monotonic() + budget
        poll_no = 0
        while verdict != "alive":
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                return verdict, detail + (
                    f" (still not alive after the {budget}s --wait budget)"
                ), note
            snooze = min(15.0, remaining)
            console.print(
                f"[yellow]--wait {budget}s:[/yellow] poll #{poll_no + 1}: {verdict}"
                f" -- re-probing in {snooze:.0f}s "
                f"({max(0, int(remaining))}s of budget left)..."
            )
            await asyncio.sleep(snooze)
            poll_no += 1
            verdict, detail, note = await _probe_once()
        console.print(f"[green]instance is ALIVE on poll #{poll_no + 1}.[/green]")
        return verdict, detail, note

    verdict, detail, note = asyncio.run(_check())
    console.print("")
    # Browser-stack verdict: DOM-XSS labs can only be solved when a real
    # browser executes the payload -- surface availability BEFORE the scan.
    from . import browser_exec as _bx
    bx_ok, bx_hint = _bx.browser_available()
    console.print(
        "[bold green]Headless browser (needed to solve DOM-XSS labs): AVAILABLE[/bold green]"
        if bx_ok
        else f"[bold yellow]Headless browser (needed to solve DOM-XSS labs): MISSING[/bold yellow] -- {bx_hint}"
    )
    console.print("")
    if verdict == "alive":
        console.print(f"[bold green]ALIVE[/bold green] -- {detail}")
        if note:
            console.print(f"[yellow]{note}[/yellow]")
        console.print("Next: [bold]python -m bughound scan '<URL>' --i-am-authorized --timeout 60 --solve-budget 300[/bold]")
    elif verdict == "dead":
        console.print(f"[bold red]DEAD / EXPIRED LAB[/bold red] -- {detail}")
        console.print("[bold red]No scanner and no exploit can solve a dead lab.[/bold red]")
        console.print("Next steps:")
        console.print("  1. Open the lab page on portswigger.net and click [bold]'Access the lab'[/bold] (or 'Restart the lab').")
        console.print("  2. Copy the [bold]NEW[/bold] URL from the browser address bar (every fresh instance gets a NEW random subdomain).")
        console.print("  3. Re-run [bold]python -m bughound check '<NEW-URL>'[/bold] until it says ALIVE.")
        console.print("  4. Keep the lab browser tab OPEN while scanning -- instances stop shortly after the browser session ends.")
    elif verdict == "unreachable":
        console.print(f"[bold red]UNREACHABLE[/bold red] -- {detail}")
        console.print("Next: check the URL, your network/VPN, and try [bold]--timeout 60[/bold] on the scan (labs may need time to wake up).")
    else:
        console.print(f"[bold yellow]HTTP ERROR[/bold yellow] -- {detail}")
        console.print("The host answered with an error status; a proxy/WAF may be blocking the scanner. Try the scan with [bold]--user-agent '<browser UA>'[/bold].")
    console.print("")
    sys.exit(0 if verdict == "alive" else 1)


@main.command("golden")
@click.argument("url")
@click.option("--out", "out_dir", default="reports", show_default=True,
              help="Directory for the JSONL diagnostic log.")
def golden_cmd(url: str, out_dir: str) -> None:
    """Fast fully-logged golden-path solver for a known lab family.

    Skips the full pipeline: detect -> fire -> poll -> login -> verify in
    ~2 minutes, with EVERY request/poll/decision appended to a JSONL log so
    even a mid-flight lab death leaves complete diagnostics.

    Currently implemented: 'Blind SQL injection with out-of-band data
    exfiltration' (Burp Collaborator channel -> administrator login).
    """
    from .golden import golden_exfil

    rc = golden_exfil(url, out_dir=out_dir)
    if rc == 0:
        console.print("[bold green]GOLDEN PATH: lab SOLVED[/bold green] "
                      "(banner verified; full trace in the JSONL log)")
    elif rc == 1:
        console.print("[bold green]Lab was already solved.[/bold green]")
    elif rc == 3:
        console.print("[bold red]Golden path aborted: lab dead or not a lab.[/bold red] "
                      "Run [bold]python -m bughound check '<URL>'[/bold] first.")
    else:
        console.print("[bold yellow]Golden path did NOT solve the lab "
                      "(exit 2).[/bold yellow] The JSONL log in the reports "
                      "directory holds the complete request/poll trace -- "
                      "share it for diagnosis.")
    sys.exit(rc)


@main.command()
@click.argument("url")
@click.option("--scope", "scope_file", type=click.Path(exists=True), help="YAML scope file.")
@click.option("--authorize-host", "authorize_hosts", multiple=True, help="Host/glob you are authorized to test.")
@click.option("--deny-host", "deny_hosts", multiple=True, help="Host/glob that is forbidden and must never be contacted (overrides scope).")
@click.option("--deny-url", "deny_urls", multiple=True, help="URL/prefix that is forbidden and must never be contacted (overrides scope).")
@click.option("--i-am-authorized", is_flag=True, help="Confirm you are authorized to test this target.")
@click.option("--aggressive/--safe", default=None,
              help="--aggressive unlocks exploit-grade modules (default-credential checks). The full pipeline (detect + exploit + lab solve) already runs by DEFAULT; an explicit --safe means passive-only (no active probes, no exploitation); --no-exploit keeps detection but skips the exploit phase.")
@click.option("--passive", "passive", is_flag=True,
              help="Passive-only scan: never send an attack payload (same as --safe / --mode stealth).")
@click.option(
    "--no-exploit",
    is_flag=True,
    help="Disable the exploit phase (detection-only). Exploits only ever run together with --aggressive.",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help=(
        "Disable headless-browser PoC execution (optional Playwright layer). "
        "When a Chromium is available, final PoC URLs are additionally EXECUTED "
        "in a real browser to prove in-browser execution (dialog capture) and to "
        "solve alert()-gated labs. Never auto-installs anything."
    ),
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
@click.option(
    "--tool-group",
    "tool_groups",
    multiple=True,
    type=click.Choice(
        ["all", "recon", "http", "vuln", "network", "osint"],
        case_sensitive=False,
    ),
    help=(
        "External-tool group(s) to run. Repeatable. "
        "recon = subdomain/CT/URL harvest; http = probing/crawl/fuzz; "
        "vuln = nuclei/sqlmap/dalfox/secrets; network = nmap/masscan/naabu; "
        "osint = sherlock. Default (omit) = all groups. Use with external tools enabled."
    ),
)
@click.option(
    "--tools-source",
    "tools_source",
    type=click.Choice(["ask", "installed", "online", "both"], case_sensitive=False),
    default="ask",
    show_default=True,
    help=(
        "Where external tools come from. "
        "ask = prompt in the terminal (installed vs online vs both); "
        "installed = local binaries only; "
        "online = public web APIs (crt.sh, Wayback, HackerTarget, urlscan, dns.google, …); "
        "both = local + online."
    ),
)
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
    "--mode",
    "mode",
    type=click.Choice(["", "stealth", "normal", "aggressive", "nuke"], case_sensitive=False),
    default="",
    help=(
        "Sn1per-style scan mode. The PLAIN DEFAULT is the full pipeline: "
        "detect + exploit + lab solve. stealth = passive only, low-and-slow; "
        "normal = detection without the exploit phase; aggressive = full "
        "pipeline (same as the default); nuke = aggressive + default-credential "
        "checks + external tools. Overrides --aggressive/--no-exploit when given."
    ),
)
@click.option("--workspace", "workspace", default="", help="Workspace name (Sn1per -w): reports land in <out>/<workspace>/ and a latest snapshot is kept for `bughound diff`.")
@click.option(
    "--solve-budget",
    "solve_budget",
    type=int,
    default=220,
    show_default=True,
    help="Request budget for the lab objective-completion (solve) phase.",
)
@click.option(
    "--wait",
    "wait_for_lab",
    type=int,
    default=0,
    metavar="SECONDS",
    help=(
        "If the target is a DEAD/just-spawned Academy instance, keep re-probing "
        "for up to SECONDS (poll every 15s) and start solving the moment it "
        "answers. Use after clicking 'Access the lab': --wait 600 covers the "
        "boot window and any respawn under the same URL. Default 0 = abort "
        "immediately on a dead instance."
    ),
)
@click.option("--brute", "brute", is_flag=True, help="Enable opt-in default-credential checks on discovered login forms (max 4 pairs, baseline-verified; also enabled by nuke mode).")
@click.option(
    "--targets-file",
    "targets_file",
    type=click.Path(exists=True),
    default=None,
    help="Airstrike mode (Sn1per -f): scan every URL in the file (one per line), each authorized against the same scope, and write a combined summary.",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Verbose logging: print every request URL + status + failure reason.",
)
def scan(url, scope_file, authorize_hosts, deny_hosts, deny_urls, i_am_authorized, aggressive,
         passive, no_exploit, no_browser, max_urls, max_depth, timeout, user_agent, modules, no_external,
         tool_groups, tools_source, out_dir, headers,
         source_dir, exploit_endpoints, exploit_param, exploit_method, exploit_body,
         exploit_content_type, exploit_encode, mode, workspace, solve_budget, wait_for_lab,
         brute, targets_file, debug) -> None:
    """Scan a URL for vulnerabilities, exploit findings to prove impact, and write reports."""

    # Mode resolution (1.13.2): --aggressive now means "exploit phase on".
    # Active DETECTION runs by default (a scanner that hides its detectors
    # behind a flag finds nothing, which reads as broken); an explicit
    # --safe / --passive / --mode stealth is what suppresses active probes.
    aggr = bool(aggressive)
    passive_only = (aggressive is False) or bool(passive)

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

    # Airstrike: multi-target file (Sn1per -f targets.txt). Every line is
    # scanned with the same scope/denylist; each target is authorized
    # individually so a single out-of-scope line aborts only that line.
    if targets_file:
        with open(targets_file) as fh:
            targets = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        console.print(f"[bold]Airstrike:[/bold] {len(targets)} target(s) from {targets_file}")
        ws_dir = os.path.join(out_dir, workspace) if workspace else out_dir
        summary_lines = ["# Airstrike summary", "", f"- Targets: {len(targets)}", ""]
        for i, target_url in enumerate(targets, 1):
            console.rule(f"[{i}/{len(targets)}] {target_url}")
            target_scope = load_scope(
                scope_file=scope_file,
                explicit_hosts=cli_hosts,
                denied_hosts=list(deny_hosts),
                denied_urls=list(deny_urls),
            )
            cfg = _build_config(
                url=target_url, aggressive=aggr, passive_only=passive_only,
                no_exploit=no_exploit, no_browser=no_browser,
                max_urls=max_urls, max_depth=max_depth, timeout=timeout,
                user_agent=user_agent, modules=modules, no_external=no_external,
                tool_groups=tool_groups, tools_source=tools_source,
                headers=headers, source_dir=source_dir, exploit_endpoints=exploit_endpoints,
                exploit_param=exploit_param, exploit_method=exploit_method,
                exploit_body=exploit_body, exploit_content_type=exploit_content_type,
                exploit_encode=exploit_encode, mode=mode, brute=brute, workspace=workspace,
                solve_budget=solve_budget, wait_for_lab=wait_for_lab,
            )
            try:
                res = asyncio.run(
                    run_scan(cfg, target_scope, confirmed=i_am_authorized,
                             progress=lambda m: console.log(m))
                )
            except AuthorizationError as exc:
                console.print(f"[bold red]Authorization error:[/bold red] {exc}")
                summary_lines.append(f"## {target_url}")
                summary_lines.append(f"- SKIPPED (authorization): {exc}")
                summary_lines.append("")
                continue
            sev = _count_by_severity(res)
            summary_lines.append(f"## {target_url}")
            summary_lines.append(
                f"- Findings: {len(res.findings)} (critical {sev.get('critical', 0)}, "
                f"high {sev.get('high', 0)}, medium {sev.get('medium', 0)}, low {sev.get('low', 0)}, "
                f"info {sev.get('info', 0)}), exploited {res.stats.get('exploited', 0)}, "
                f"chains {res.stats.get('chains', 0)}"
            )
            summary_lines.append("")
        os.makedirs(ws_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        summary_path = os.path.join(ws_dir, f"airstrike-summary-{stamp}.md")
        with open(summary_path, "w") as fh:
            fh.write("\n".join(summary_lines))
        console.print(f"\n[green]Airstrike summary:[/green] {summary_path}")
        return

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
        aggressive=aggr,
        passive_only=passive_only,
        exploit=not no_exploit,
        browser_exec=not no_browser,
        modules=list(modules) or None,
        extra_headers=extra_headers,
        use_external_tools=not no_external,
        tool_groups=[g.lower() for g in tool_groups] if tool_groups else [],
        tools_source=(tools_source or "ask").strip().lower(),
        user_agent=user_agent or ScanConfig.model_fields["user_agent"].default,
        source_dir=source_dir,
        exploit_endpoints=list(exploit_endpoints),
        exploit_param=exploit_param,
        exploit_method=exploit_method,
        exploit_body=exploit_body,
        exploit_content_type=exploit_content_type,
        exploit_encode=enc,
        mode=(mode or "").strip().lower(),
        bruteforce=brute,
        workspace=workspace,
        solve_budget=solve_budget,
        wait_for_lab=max(0, int(wait_for_lab or 0)),
    )
    if workspace:
        out_dir = os.path.join(out_dir, workspace)

    exploit_on = exploit_phase_enabled(config)
    mode_note = f", mode={config.mode}" if config.mode else ""
    if config.passive_only:
        kind = "passive-only"
    elif exploit_on:
        kind = "full pipeline"
    else:
        kind = "detection-only"
    console.print(f"[bold]bughound[/bold] scanning [cyan]{url}[/cyan] "
                  f"({kind} mode{mode_note}, "
                  f"exploit phase {'on' if exploit_on else 'off'}, "
                  f"timeout={config.timeout}s)")
    if exploit_endpoints and exploit_on:
        for ep in exploit_endpoints:
            extra = ""
            if exploit_body:
                extra = f" (body template, encode={config.exploit_encode or 'none'})"
            elif exploit_param:
                extra = f" (param: {exploit_param})"
            console.print(f"  [magenta]direct exploit target:[/magenta] {_rich_escape(ep)}{extra}")
    if config.passive_only:
        console.print(
            "[yellow]Passive-only mode: no active probes will be sent, so "
            "injection-class vulnerabilities CANNOT be found.[/yellow] For active "
            "detection run:\n"
            f"  bughound scan {url} --i-am-authorized\n"
            "(add --aggressive to also exploit the findings and prove impact)"
        )
    elif exploit_on:
        from . import browser_exec as _bx

        bx_ok, _bx_hint = _bx.browser_available()
        if bx_ok and config.browser_exec:
            bx_note = "headless-browser PoC execution: on"
        else:
            reason = "--no-browser" if not config.browser_exec else "Playwright/Chromium not found"
            bx_note = (
                f"[bold yellow]headless-browser PoC execution: OFF ({reason}) -- "
                "DOM-XSS labs CANNOT be solved without it; enable (never automatic): "
                "pip install playwright && python -m playwright install chromium[/bold yellow]"
            )
        console.print(
            "[dim]Full pipeline: findings will be detected AND exploited to prove "
            "real impact (cookie replay, credential capture, CSRF bypass, lab "
            "solve), and recovered secrets are written into the report. "
            + bx_note +
            ". Use [bold]--no-exploit[/bold] for detection-only or [bold]--safe[/bold] "
            "for passive-only.[/dim]"
        )
    else:
        console.print(
            "[yellow]Detection-only mode (--no-exploit or --mode normal): findings "
            "will be reported but NOT exploited and the lab solve phase is "
            "disabled.[/yellow] For the full pipeline run:\n"
            f"  bughound scan {url} --i-am-authorized"
        )
    if exploit_endpoints and not exploit_on:
        console.print(
            "[yellow]--exploit-endpoint was given but the exploit phase is OFF "
            "(detection mode or --no-exploit). The designated targets will NOT be "
            "exploited. Re-run with --aggressive to enable exploitation.[/yellow]"
        )

    try:
        _run_single_scan(url, config, scope, confirmed=i_am_authorized, out_dir=out_dir,
                         workspace=workspace)
    except AuthorizationError as exc:
        console.print(f"[bold red]Authorization error:[/bold red] {exc}")
        sys.exit(2)


def _build_config(*, url, aggressive, no_exploit, no_browser: bool = False, max_urls, max_depth, timeout, user_agent,
                  modules, no_external, headers, source_dir, exploit_endpoints, exploit_param,
                  exploit_method, exploit_body, exploit_content_type, exploit_encode, mode,
                  brute, workspace, solve_budget: int = 220, wait_for_lab: int = 0,
                  tool_groups=(),
                  tools_source: str = "ask", passive_only: bool = False) -> ScanConfig:
    """ScanConfig builder shared by single-target and airstrike paths."""
    extra_headers = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()
    enc = (exploit_encode or "").strip().lower()
    enc = "" if enc in ("", "none") else enc
    return ScanConfig(
        target_url=url,
        max_urls=max_urls,
        max_depth=max_depth,
        timeout=timeout,
        aggressive=bool(aggressive),
        passive_only=bool(passive_only),
        exploit=not no_exploit,
        browser_exec=not no_browser,
        modules=list(modules) or None,
        extra_headers=extra_headers,
        use_external_tools=not no_external,
        tool_groups=[g.lower() for g in tool_groups] if tool_groups else [],
        tools_source=(tools_source or "ask").strip().lower(),
        user_agent=user_agent or ScanConfig.model_fields["user_agent"].default,
        source_dir=source_dir,
        exploit_endpoints=list(exploit_endpoints),
        exploit_param=exploit_param,
        exploit_method=exploit_method,
        exploit_body=exploit_body,
        exploit_content_type=exploit_content_type,
        exploit_encode=enc,
        mode=(mode or "").strip().lower(),
        bruteforce=brute,
        workspace=workspace,
        solve_budget=solve_budget,
        wait_for_lab=max(0, int(wait_for_lab or 0)),
    )


def _count_by_severity(result) -> dict[str, int]:
    from collections import Counter

    return dict(Counter(f.severity.value for f in result.findings))


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True)
def serve(host, port) -> None:
    """Run the web service + dashboard."""

    import uvicorn

    uvicorn.run("bughound.web:app", host=host, port=port, reload=False)


@main.command("recon")
@click.argument("url")
@click.option("--scope", "scope_file", type=click.Path(exists=True), help="YAML scope file.")
@click.option("--authorize-host", "authorize_hosts", multiple=True, help="Host/glob you are authorized to test.")
@click.option("--deny-host", "deny_hosts", multiple=True, help="Forbidden host/glob -- never contacted.")
@click.option("--deny-url", "deny_urls", multiple=True, help="Forbidden URL prefix -- never contacted.")
@click.option("--i-am-authorized", is_flag=True, help="Confirm you are authorized to test this target.")
@click.option("--max-urls", default=25, show_default=True)
@click.option("--timeout", default=30.0, show_default=True)
@click.option("--out", "out_dir", default="reports", show_default=True, help="Output directory.")
def recon(url, scope_file, authorize_hosts, deny_hosts, deny_urls, i_am_authorized,
          max_urls, timeout, out_dir) -> None:
    """Recon-only pass (Sn1per recon phase): attack-surface map, no attack payloads.

    Runs just the RECON + CONFIG squads (subdomains, DNS, tech fingerprint,
    WAF, admin panels, API docs, JS endpoints, backups, source maps,
    wayback, headers/TLS posture...) and writes the recon-focused report.
    Equivalent to `scan --mode stealth` minus the config-squad vuln checks.
    """

    cli_hosts = [h for h in (_normalize_host_entry(x) for x in authorize_hosts) if h]
    scope = load_scope(
        scope_file=scope_file,
        explicit_hosts=cli_hosts,
        denied_hosts=list(deny_hosts),
        denied_urls=list(deny_urls),
    )
    recon_squad = []
    from .agents.squads import SQUADS

    recon_squad = SQUADS["RECON SQUAD"]
    config = ScanConfig(
        target_url=url,
        max_urls=max_urls,
        timeout=timeout,
        aggressive=False,
        use_external_tools=False,
        modules=recon_squad,
    )
    console.print(f"[bold]bughound recon[/bold] on [cyan]{url}[/cyan] (recon squad only, passive)")
    result = _run_single_scan(url, config, scope, confirmed=i_am_authorized, out_dir=out_dir)

    # Console-focused recon summary: the table shows findings, this shows
    # the structured surface numbers.
    r = result.recon or {}
    subdomains = r.get("subdomains") or []
    stack = r.get("tech_stack") or {}
    lines = ["", "[bold]Attack-surface summary[/bold]"]
    lines.append(f"  subdomains: {len(subdomains)}" + (f" ({', '.join(subdomains[:8])})" if subdomains else ""))
    lines.append(f"  tech stack: {', '.join(sorted({p for v in stack.values() for p in v})) or 'none detected'}")
    waf = r.get("waf")
    lines.append(f"  WAF: {waf or 'none detected'}")
    for key in ("admin_paths", "api_docs", "js_endpoints", "backup_files", "sourcemaps", "emails"):
        items = r.get(key) or []
        if items:
            lines.append(f"  {key.replace('_', ' ')}: {len(items)}" + f" (e.g. {', '.join(str(i) for i in items[:5])})")
    for line in lines:
        console.print(line)


@main.command()
@click.argument("old_json", type=click.Path(exists=True))
@click.argument("new_json", type=click.Path(exists=True))
@click.option("--out", "out_file", default="", help="Also write the diff as Markdown to this path.")
def diff(old_json, new_json, out_file) -> None:
    """Diff two scan reports (Sn1per-style continuous monitoring).

    Point this at the previous run's JSON report and the current run's
    JSON report for the same host: bughound prints what changed -- new
    findings, resolved findings, newly-exploited proofs and attack-surface
    additions/removals.
    """
    from .diff import diff_files, diff_markdown

    d = diff_files(old_json, new_json)
    md = diff_markdown(d, old_json, new_json)

    # Colored console rendering.
    console.print(f"[bold]Attack-surface diff[/bold] for [cyan]{d.host or 'target'}[/cyan]")
    if not d.has_changes:
        console.print("[green]No changes detected between the two reports.[/green]")
    if d.new_findings:
        console.print(f"\n[bold red]New findings ({len(d.new_findings)}):[/bold red]")
        for f in d.new_findings:
            sev = str(f.get("severity", "?")).upper()
            style = SEVERITY_STYLES.get(sev.lower(), "")
            console.print(f"  + [{sev}] {f.get('title', '?')} -- {f.get('url', '?')}", style=style)
    if d.resolved_findings:
        console.print(f"\n[bold green]Resolved findings ({len(d.resolved_findings)}):[/bold green]")
        for f in d.resolved_findings:
            console.print(f"  - {f.get('title', '?')} -- {f.get('url', '?')}", style="green")
    if d.now_exploited:
        console.print(f"\n[bold magenta]Newly exploited ({len(d.now_exploited)}):[/bold magenta]")
        for f in d.now_exploited:
            console.print(f"  \u2713 {f.get('title', '?')}", style="magenta")
    if d.recon_added:
        console.print("\n[bold yellow]Attack-surface additions:[/bold yellow]")
        for key, items in d.recon_added.items():
            console.print(f"  + {key}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))
    if d.recon_removed:
        console.print("\n[bold yellow]Attack-surface removals:[/bold yellow]")
        for key, items in d.recon_removed.items():
            console.print(f"  - {key}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))

    if out_file:
        with open(out_file, "w") as fh:
            fh.write(md)
        console.print(f"\n[green]Diff report written:[/green] {out_file}")


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
            _rich_escape(f.module),
            f.severity.value.upper(),
            _rich_escape(f.category.value),
            _rich_escape(f.title),
            _rich_escape(f.url),
            verified_cell,
            style=style,
        )
    console.print(table)
    if result.errors:
        console.print("[yellow]Notes:[/yellow]")
        for e in result.errors:
            console.print(f"  - {_rich_escape(e)}")


if __name__ == "__main__":
    main()
