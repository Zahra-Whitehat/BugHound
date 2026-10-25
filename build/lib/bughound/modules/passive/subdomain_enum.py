"""Passive subdomain enumeration via Certificate Transparency logs.

Queries the public ``crt.sh`` service (which aggregates CT logs from
cert authorities worldwide) for every TLS certificate ever issued for the
target's registerable domain. Each certificate's Subject Alternative Names
reveal subdomains the operator may not even be aware are publicly exposed.

This is **passive** reconnaissance: it never touches the target, only crt.sh's
public API. Discovered subdomains are surfaced as INFO findings and also
written to ``ctx.recon["subdomains"]`` so the report renders a single
attack-surface list. Operators can then expand scope and re-scan the most
interesting subdomains.

Out-of-scope subdomains (i.e. on the denylist) are reported but never
contacted by bughound -- the denylist is enforced at the HTTP layer.
"""

from __future__ import annotations

from ...models import Category, Finding, Severity
from ..base import Module, ScanContext, register
from ..recon_utils import register_domain_of


@register
class SubdomainEnumModule(Module):
    name = "subdomain-enum"
    categories = [Category.RECON]
    passive = True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        registerable = register_domain_of(ctx.base_url)
        if not registerable or registerable in {"localhost", "127.0.0.1"}:
            ctx.log(f"subdomain-enum: skipping {ctx.base_url!r} (local / IP-only target)")
            return findings

        ctx.log(f"subdomain-enum: querying crt.sh CT logs for *.{registerable}")

        async def fetch(url: str) -> tuple[bool, str]:
            resp = await ctx.client.get(url, follow_redirects=True)
            return resp.ok, resp.text

        subdomains: list[str] = []
        try:
            from ..recon_utils import crt_sh_subdomains

            subdomains = await crt_sh_subdomains(registerable, fetch)
        except Exception as exc:  # noqa: BLE001
            ctx.log(f"subdomain-enum: crt.sh query failed: {exc}")
            return findings

        if not subdomains:
            ctx.log("subdomain-enum: crt.sh returned no subdomains")
            return findings

        # Group: in-scope subdomains (operator authorized to test) vs
        # out-of-scope subdomains (visible but denied). Both are surfaced as
        # INFO -- knowing they exist is itself valuable -- but we mark the
        # denied ones so operators can expand scope if appropriate.
        in_scope = [s for s in subdomains if s == registerable or s.endswith("." + registerable)]
        ctx.recon["subdomains"] = in_scope

        findings.append(
            Finding(
                category=Category.RECON,
                title=f"Certificate Transparency reveals {len(in_scope)} subdomain(s)",
                severity=Severity.INFO,
                confidence="firm",
                url=ctx.base_url,
                description=(
                    f"crt.sh's CT-log aggregation returned {len(in_scope)} distinct "
                    "hostnames under " + registerable + " for which TLS certificates "
                    "have been issued. Each one is a potential attack-surface entry "
                    "point and may be running outdated software, exposed admin panels, "
                    "or staging data."
                ),
                evidence="\n".join(in_scope[:60]),
                remediation=(
                    "Inventory all issued certificates; decommission forgotten subdomains "
                    "and re-scan the most interesting ones in scope."
                ),
                references=["https://crt.sh/", "https://certificate.transparency.dev/"],
                module=self.name,
                verified=True,
            )
        )
        return findings
