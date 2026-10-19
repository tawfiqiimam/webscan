"""Open redirect detection.

Injects an external URL into parameters whose names suggest redirection and
checks whether the server issues a redirect to the attacker-controlled host.
"""

from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule
from webscan.modules._params import has_query, iter_param_mutations

CANARY_HOST = "webscan-canary.example"
CANARY_URL = f"https://{CANARY_HOST}/"

# Parameter names commonly used for redirects.
REDIRECT_PARAMS = {
    "url", "next", "redirect", "redirect_uri", "return", "returnurl",
    "return_url", "dest", "destination", "continue", "to", "goto", "r", "u",
}


class OpenRedirectModule(ScanModule):
    name = "redirect"
    category = "web"
    description = "Detects open redirects in redirection-style parameters."

    def run(self, ctx: ScanContext) -> List[Finding]:
        if not has_query(ctx.target):
            return [
                Finding(
                    module=self.name,
                    title="Open redirect check skipped (no query parameters)",
                    severity=Severity.INFO,
                    description="No query parameters to test for open redirects.",
                    target=ctx.target,
                )
            ]

        findings: List[Finding] = []
        for name, mutated_url in iter_param_mutations(ctx.target, CANARY_URL):
            # Only test parameters that look like redirects to avoid noise.
            if name.lower() not in REDIRECT_PARAMS:
                continue
            resp = ctx.http.get(mutated_url, allow_redirects=False)
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                if urlparse(location).hostname == CANARY_HOST:
                    findings.append(
                        Finding(
                            module=self.name,
                            title=f"Open redirect via parameter '{name}'",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The parameter '{name}' controls the redirect target, allowing "
                                "redirection to an arbitrary external host (phishing risk)."
                            ),
                            target=mutated_url,
                            evidence=f"HTTP {resp.status_code} -> Location: {location}",
                            remediation=(
                                "Validate redirect targets against an allow-list of known-safe "
                                "paths or hosts; avoid redirecting to raw user input."
                            ),
                            references=["https://cwe.mitre.org/data/definitions/601.html"],
                        )
                    )

        return findings or [
            Finding(
                module=self.name,
                title="No open redirect detected",
                severity=Severity.INFO,
                description="No redirection-style parameter redirected to the external canary host.",
                target=ctx.target,
            )
        ]
