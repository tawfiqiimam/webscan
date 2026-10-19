"""Reflected XSS detection via unique-marker reflection analysis.

This is a non-destructive heuristic check: it injects a unique, harmless marker
into each query parameter and reports when the marker is reflected unencoded in
an HTML context. It does not execute JavaScript or attempt exploitation.
"""

from __future__ import annotations

import html
import uuid
from typing import List

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule
from webscan.modules._params import has_query, iter_param_mutations


class XSSModule(ScanModule):
    name = "xss"
    category = "web"
    description = "Detects reflected XSS by checking for unencoded marker reflection."

    def run(self, ctx: ScanContext) -> List[Finding]:
        if not has_query(ctx.target):
            return [
                Finding(
                    module=self.name,
                    title="XSS check skipped (no query parameters)",
                    severity=Severity.INFO,
                    description=(
                        "The target URL has no query parameters to test. "
                        "Provide a URL with parameters (e.g. ?q=test) to test for reflected XSS."
                    ),
                    target=ctx.target,
                )
            ]

        findings: List[Finding] = []
        for name, mutated_url in iter_param_mutations(ctx.target, self._marker_payload()):
            marker = self._last_marker
            resp = ctx.http.get(mutated_url)
            if resp is None or not resp.text:
                continue
            body = resp.text
            raw_present = marker in body
            encoded_present = html.escape(marker) in body

            if raw_present and f"<{marker}" in body or (raw_present and not encoded_present):
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Possible reflected XSS in parameter '{name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"The value of parameter '{name}' is reflected into the response "
                            "without HTML encoding, which can allow reflected XSS."
                        ),
                        target=mutated_url,
                        evidence=f"Unencoded marker '{marker}' found in response body.",
                        remediation=(
                            "Context-aware output encoding for all user input; apply a strict "
                            "Content-Security-Policy as defence in depth."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cwe.mitre.org/data/definitions/79.html",
                        ],
                    )
                )
            elif raw_present:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Parameter '{name}' is reflected (encoded)",
                        severity=Severity.INFO,
                        description=(
                            f"The value of '{name}' is reflected but appears to be HTML-encoded. "
                            "This is informational and generally not exploitable as XSS."
                        ),
                        target=mutated_url,
                        evidence=f"Marker '{marker}' reflected in encoded form.",
                    )
                )
        return findings or [
            Finding(
                module=self.name,
                title="No reflected XSS detected",
                severity=Severity.INFO,
                description="Injected markers were not reflected unencoded in any tested parameter.",
                target=ctx.target,
            )
        ]

    def _marker_payload(self) -> str:
        # A marker that would be dangerous only if reflected unencoded in HTML.
        token = uuid.uuid4().hex[:10]
        self._last_marker = f"xss{token}"
        return f"<{self._last_marker}>"
