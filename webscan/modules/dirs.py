"""Directory and file discovery against a small built-in wordlist."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from urllib.parse import urljoin

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule

# A compact, high-signal wordlist. Users can extend via --wordlist on the CLI.
DEFAULT_PATHS = [
    ".git/config",
    ".env",
    ".htaccess",
    "admin/",
    "administrator/",
    "backup/",
    "backup.zip",
    "config.php",
    "db.sql",
    "dump.sql",
    "login/",
    "phpinfo.php",
    "phpmyadmin/",
    "robots.txt",
    "server-status",
    "sitemap.xml",
    "test/",
    "wp-admin/",
    "wp-login.php",
    ".DS_Store",
]

# Paths whose exposure is clearly sensitive.
SENSITIVE = {".git/config", ".env", "db.sql", "dump.sql", "backup.zip", "config.php", ".DS_Store"}


class DirBruteModule(ScanModule):
    name = "dirs"
    category = "recon"
    description = "Probes for common sensitive files and directories."

    def __init__(self, paths: List[str] | None = None) -> None:
        self.paths = paths or DEFAULT_PATHS

    def run(self, ctx: ScanContext) -> List[Finding]:
        base = ctx.target if ctx.target.endswith("/") else ctx.target + "/"
        findings: List[Finding] = []

        with ThreadPoolExecutor(max_workers=ctx.threads) as pool:
            futures = {
                pool.submit(self._probe, ctx, urljoin(base, path)): path for path in self.paths
            }
            for fut in as_completed(futures):
                path = futures[fut]
                status = fut.result()
                if status is None:
                    continue
                if status in (200, 301, 302, 401, 403):
                    sensitive = path in SENSITIVE
                    if status in (401, 403):
                        sev = Severity.INFO
                        note = "exists but is access-controlled"
                    elif sensitive and status == 200:
                        sev = Severity.HIGH
                        note = "is publicly accessible and sensitive"
                    else:
                        sev = Severity.LOW
                        note = "is reachable"
                    findings.append(
                        Finding(
                            module=self.name,
                            title=f"Discovered path: /{path} (HTTP {status})",
                            severity=sev,
                            description=f"The path /{path} {note}.",
                            target=urljoin(base, path),
                            evidence=f"HTTP {status}",
                            remediation=(
                                "Remove or restrict access to this resource if it should not be public."
                                if sensitive
                                else None
                            ),
                        )
                    )

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    title="No common paths discovered",
                    severity=Severity.INFO,
                    description="None of the probed paths returned a notable status code.",
                    target=ctx.target,
                )
            )
        return findings

    @staticmethod
    def _probe(ctx: ScanContext, url: str):
        resp = ctx.http.get(url, allow_redirects=False)
        return resp.status_code if resp is not None else None
