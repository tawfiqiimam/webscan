"""Error-based SQL injection heuristic.

Non-destructive: injects a syntactically-breaking character into each query
parameter and looks for database error signatures in the response. It does not
attempt to extract data or run destructive payloads.
"""

from __future__ import annotations

import re
from typing import List

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule
from webscan.modules._params import has_query, iter_param_mutations

# Signatures of common database error messages.
SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s+mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),
    re.compile(r"org\.postgresql\.util\.psqlexception", re.I),
    re.compile(r"sqlite3?::|sqlite_error", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"odbc sql server driver", re.I),
]

# Probes that tend to break unsanitised SQL queries.
PROBES = ["'", '"', "')", "';"]


class SQLiModule(ScanModule):
    name = "sqli"
    category = "web"
    description = "Detects error-based SQL injection via database error signatures."

    def run(self, ctx: ScanContext) -> List[Finding]:
        if not has_query(ctx.target):
            return [
                Finding(
                    module=self.name,
                    title="SQLi check skipped (no query parameters)",
                    severity=Severity.INFO,
                    description=(
                        "The target URL has no query parameters to test. Provide a URL with "
                        "parameters (e.g. ?id=1) to test for SQL injection."
                    ),
                    target=ctx.target,
                )
            ]

        findings: List[Finding] = []
        flagged: set[str] = set()

        for probe in PROBES:
            for name, mutated_url in iter_param_mutations(ctx.target, probe):
                if name in flagged:
                    continue
                resp = ctx.http.get(mutated_url)
                if resp is None or not resp.text:
                    continue
                for pattern in SQL_ERROR_PATTERNS:
                    match = pattern.search(resp.text)
                    if match:
                        flagged.add(name)
                        findings.append(
                            Finding(
                                module=self.name,
                                title=f"Possible SQL injection in parameter '{name}'",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Injecting '{probe}' into parameter '{name}' triggered a "
                                    "database error, which indicates the input reaches a SQL query "
                                    "unsanitised."
                                ),
                                target=mutated_url,
                                evidence=f"DB error signature matched: '{match.group(0)[:80]}'",
                                remediation=(
                                    "Use parameterised queries / prepared statements and validate "
                                    "input; never concatenate user data into SQL."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cwe.mitre.org/data/definitions/89.html",
                                ],
                            )
                        )
                        break

        return findings or [
            Finding(
                module=self.name,
                title="No error-based SQL injection detected",
                severity=Severity.INFO,
                description="No database error signatures were triggered by the probes.",
                target=ctx.target,
            )
        ]
