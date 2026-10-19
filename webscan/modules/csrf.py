"""Basic CSRF hygiene check for HTML forms.

Parses forms in the page and flags state-changing (POST) forms that lack an
anti-CSRF token field and are not protected by a SameSite cookie. This is a
heuristic: a missing token is a strong signal but not proof of exploitability.
"""

from __future__ import annotations

import re
from typing import List

from bs4 import BeautifulSoup

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule

# Common names/attributes that indicate an anti-CSRF token.
TOKEN_HINTS = re.compile(r"csrf|xsrf|_token|authenticity_token|nonce", re.I)


class CSRFModule(ScanModule):
    name = "csrf"
    category = "web"
    description = "Flags POST forms lacking an anti-CSRF token."

    def run(self, ctx: ScanContext) -> List[Finding]:
        resp = ctx.http.get(ctx.target)
        if resp is None or not resp.text:
            return []

        samesite_protected = self._has_samesite_cookie(resp)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return [
                Finding(
                    module=self.name,
                    title="No HTML forms found",
                    severity=Severity.INFO,
                    description="The page contains no forms to evaluate for CSRF protection.",
                    target=ctx.target,
                )
            ]

        findings: List[Finding] = []
        for idx, form in enumerate(forms):
            method = (form.get("method") or "get").strip().lower()
            if method != "post":
                continue  # GET forms are not state-changing by convention
            if self._has_token(form):
                continue
            action = form.get("action") or "(same page)"
            severity = Severity.LOW if samesite_protected else Severity.MEDIUM
            note = (
                " A SameSite cookie was observed, which mitigates but does not fully "
                "eliminate CSRF risk."
                if samesite_protected
                else ""
            )
            findings.append(
                Finding(
                    module=self.name,
                    title=f"POST form without anti-CSRF token (form #{idx + 1})",
                    severity=severity,
                    description=(
                        f"A state-changing form (action='{action}') has no detectable anti-CSRF "
                        f"token field.{note}"
                    ),
                    target=ctx.target,
                    evidence=f"method=post, action={action}",
                    remediation=(
                        "Include a per-session/per-request anti-CSRF token in state-changing forms "
                        "and set cookies with SameSite=Lax or Strict."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/352.html"],
                )
            )

        return findings or [
            Finding(
                module=self.name,
                title="All POST forms carry an anti-CSRF token",
                severity=Severity.INFO,
                description="Every POST form on the page included a token-like hidden field.",
                target=ctx.target,
            )
        ]

    @staticmethod
    def _has_token(form) -> bool:
        for inp in form.find_all("input"):
            name = (inp.get("name") or "") + " " + (inp.get("id") or "")
            if TOKEN_HINTS.search(name):
                return True
        return False

    @staticmethod
    def _has_samesite_cookie(resp) -> bool:
        set_cookie = resp.headers.get("Set-Cookie", "")
        return "samesite" in set_cookie.lower()
