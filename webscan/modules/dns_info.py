"""DNS reconnaissance: A/AAAA/MX/NS/TXT records."""

from __future__ import annotations

from typing import List

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule

try:
    import dns.resolver

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


class DNSInfoModule(ScanModule):
    name = "dns"
    category = "recon"
    description = "Collects DNS records (A, AAAA, MX, NS, TXT, CNAME) for the host."

    def run(self, ctx: ScanContext) -> List[Finding]:
        if not _HAS_DNS:
            return [
                Finding(
                    module=self.name,
                    title="DNS library unavailable",
                    severity=Severity.INFO,
                    description="dnspython is not installed; skipping DNS recon.",
                    target=ctx.target,
                )
            ]
        if not ctx.host:
            return []

        findings: List[Finding] = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = ctx.timeout
        resolver.timeout = ctx.timeout

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(ctx.host, rtype)
            except Exception:
                continue
            values = [r.to_text() for r in answers]
            if not values:
                continue
            findings.append(
                Finding(
                    module=self.name,
                    title=f"DNS {rtype} record(s)",
                    severity=Severity.INFO,
                    description=f"{rtype} records resolved for {ctx.host}.",
                    target=ctx.host,
                    evidence=", ".join(values[:10]),
                )
            )

            # Flag a couple of commonly useful TXT findings.
            if rtype == "TXT":
                joined = " ".join(values).lower()
                if "v=spf1" not in joined:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="No SPF record found",
                            severity=Severity.LOW,
                            description="No SPF TXT record was found; email spoofing is easier.",
                            target=ctx.host,
                            remediation="Publish an SPF record restricting authorised senders.",
                        )
                    )
        return findings
