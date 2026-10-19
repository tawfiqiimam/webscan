"""Lightweight technology fingerprinting from headers, cookies, and HTML."""

from __future__ import annotations

import re
from typing import List

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule

# signal name -> (where to look, regex, technology label)
SIGNATURES = [
    ("header:server", re.compile(r"nginx", re.I), "nginx"),
    ("header:server", re.compile(r"apache", re.I), "Apache"),
    ("header:server", re.compile(r"microsoft-iis", re.I), "Microsoft IIS"),
    ("header:x-powered-by", re.compile(r"php", re.I), "PHP"),
    ("header:x-powered-by", re.compile(r"express", re.I), "Express.js"),
    ("header:x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("header:x-generator", re.compile(r"drupal", re.I), "Drupal"),
    ("cookie", re.compile(r"wordpress|wp-settings", re.I), "WordPress"),
    ("cookie", re.compile(r"laravel_session", re.I), "Laravel"),
    ("cookie", re.compile(r"csrftoken|django", re.I), "Django"),
    ("cookie", re.compile(r"PHPSESSID", re.I), "PHP"),
    ("cookie", re.compile(r"JSESSIONID", re.I), "Java servlet"),
    ("html", re.compile(r'content="WordPress', re.I), "WordPress"),
    ("html", re.compile(r"/wp-content/", re.I), "WordPress"),
    ("html", re.compile(r"Drupal.settings", re.I), "Drupal"),
    ("html", re.compile(r'name="generator"\s+content="Joomla', re.I), "Joomla"),
    ("html", re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    ("html", re.compile(r"ng-version=", re.I), "Angular"),
]


class TechFingerprintModule(ScanModule):
    name = "tech"
    category = "recon"
    description = "Identifies web servers, frameworks, and CMS platforms."

    def run(self, ctx: ScanContext) -> List[Finding]:
        resp = ctx.http.get(ctx.target)
        if resp is None:
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
        html = resp.text[:200_000] if resp.text else ""

        detected: dict[str, str] = {}
        for source, pattern, tech in SIGNATURES:
            haystack = ""
            evidence = ""
            if source.startswith("header:"):
                hdr = source.split(":", 1)[1]
                haystack = headers.get(hdr, "")
                evidence = f"{hdr}: {haystack}"
            elif source == "cookie":
                haystack = cookies
                evidence = f"cookie: {cookies[:120]}"
            elif source == "html":
                haystack = html
                evidence = "matched HTML body signature"
            if haystack and pattern.search(haystack):
                detected.setdefault(tech, evidence)

        if not detected:
            return [
                Finding(
                    module=self.name,
                    title="No technologies fingerprinted",
                    severity=Severity.INFO,
                    description="No known technology signatures matched the response.",
                    target=ctx.target,
                )
            ]

        return [
            Finding(
                module=self.name,
                title=f"Technology detected: {tech}",
                severity=Severity.INFO,
                description=f"The response contains signatures consistent with {tech}.",
                target=ctx.target,
                evidence=evidence,
                remediation="Keep the detected software patched and hide version banners.",
            )
            for tech, evidence in detected.items()
        ]
