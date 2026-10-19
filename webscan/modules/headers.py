"""Security header analysis."""

from __future__ import annotations

from typing import List

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule

# header -> (severity if missing, human description, remediation)
EXPECTED_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HSTS is not set; the browser may fall back to insecure HTTP.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy; the page has weaker protection against XSS and injection.",
        "Define a restrictive Content-Security-Policy tailored to the app.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "X-Frame-Options missing; the page may be vulnerable to clickjacking.",
        "Set 'X-Frame-Options: DENY' or use CSP frame-ancestors.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options missing; browsers may MIME-sniff responses.",
        "Set 'X-Content-Type-Options: nosniff'.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Referrer-Policy not set; full URLs may leak in the Referer header.",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Permissions-Policy not set; powerful browser features are not restricted.",
        "Set a Permissions-Policy limiting features the app does not use.",
    ),
}

# Headers that disclose information and should ideally be removed.
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


class SecurityHeadersModule(ScanModule):
    name = "headers"
    category = "web"
    description = "Checks for missing security headers and information disclosure."

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        resp = ctx.http.get(ctx.target)
        if resp is None:
            return findings

        present = {k.lower(): v for k, v in resp.headers.items()}

        for header, (severity, desc, fix) in EXPECTED_HEADERS.items():
            if header not in present:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Missing security header: {header}",
                        severity=severity,
                        description=desc,
                        target=ctx.target,
                        remediation=fix,
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )
                )

        for header in LEAKY_HEADERS:
            if header in present and present[header].strip():
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Information disclosure via '{header}' header",
                        severity=Severity.INFO,
                        description=(
                            f"The response advertises '{header}: {present[header]}', "
                            "which reveals server/stack details to attackers."
                        ),
                        target=ctx.target,
                        evidence=f"{header}: {present[header]}",
                        remediation=f"Remove or obfuscate the '{header}' response header.",
                    )
                )
        return findings
