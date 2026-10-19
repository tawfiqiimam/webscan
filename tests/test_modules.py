"""Tests for individual scan modules using mocked HTTP responses."""

from __future__ import annotations

import urllib.parse as urlparse

from webscan.core.finding import Severity
from webscan.modules.csrf import CSRFModule
from webscan.modules.headers import SecurityHeadersModule
from webscan.modules.redirect import OpenRedirectModule
from webscan.modules.sqli import SQLiModule
from webscan.modules.tech import TechFingerprintModule
from webscan.modules.xss import XSSModule
from tests.conftest import FakeResponse


def _param(url, name):
    return urlparse.parse_qs(urlparse.urlparse(url).query).get(name, [""])[0]


def test_sqli_detects_db_error(make_ctx):
    def handler(url, **kw):
        return FakeResponse("You have an error in your SQL syntax; check the manual")

    ctx = make_ctx("https://t.test/item?id=1", handler)
    findings = SQLiModule().run(ctx)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_sqli_clean_when_no_error(make_ctx):
    ctx = make_ctx("https://t.test/item?id=1", lambda url, **kw: FakeResponse("all good"))
    findings = SQLiModule().run(ctx)
    assert all(f.severity == Severity.INFO for f in findings)


def test_sqli_skips_without_params(make_ctx):
    ctx = make_ctx("https://t.test/", lambda url, **kw: FakeResponse(""))
    findings = SQLiModule().run(ctx)
    assert len(findings) == 1 and "skipped" in findings[0].title.lower()


def test_xss_reflected_unencoded(make_ctx):
    def handler(url, **kw):
        return FakeResponse(f"<div>{_param(url, 'q')}</div>")

    ctx = make_ctx("https://t.test/s?q=hello", handler)
    findings = XSSModule().run(ctx)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_xss_encoded_is_info(make_ctx):
    import html

    def handler(url, **kw):
        return FakeResponse(f"<div>{html.escape(_param(url, 'q'))}</div>")

    ctx = make_ctx("https://t.test/s?q=hello", handler)
    findings = XSSModule().run(ctx)
    assert all(f.severity in (Severity.INFO,) for f in findings)


def test_headers_flags_missing(make_ctx):
    ctx = make_ctx(
        "https://t.test/",
        lambda url, **kw: FakeResponse("<html></html>", headers={"Server": "nginx"}),
    )
    findings = SecurityHeadersModule().run(ctx)
    titles = [f.title for f in findings]
    assert any("strict-transport-security" in t for t in titles)
    assert any("Information disclosure" in t for t in titles)


def test_headers_quiet_when_present(make_ctx):
    good = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    ctx = make_ctx("https://t.test/", lambda url, **kw: FakeResponse("", headers=good))
    findings = SecurityHeadersModule().run(ctx)
    assert findings == []


def test_redirect_detects_open_redirect(make_ctx):
    def handler(url, **kw):
        if "webscan-canary.example" in url:
            return FakeResponse(
                "", headers={"Location": "https://webscan-canary.example/"}, status=302
            )
        return FakeResponse("")

    ctx = make_ctx("https://t.test/go?url=/home", handler)
    findings = OpenRedirectModule().run(ctx)
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_csrf_flags_post_without_token(make_ctx):
    html_body = '<form method="post" action="/transfer"><input name="amount"></form>'
    ctx = make_ctx("https://t.test/", lambda url, **kw: FakeResponse(html_body))
    findings = CSRFModule().run(ctx)
    assert any("without anti-CSRF token" in f.title for f in findings)


def test_csrf_ok_with_token(make_ctx):
    html_body = (
        '<form method="post"><input name="csrf_token" value="x"><input name="a"></form>'
    )
    ctx = make_ctx("https://t.test/", lambda url, **kw: FakeResponse(html_body))
    findings = CSRFModule().run(ctx)
    assert all("without anti-CSRF" not in f.title for f in findings)


def test_tech_fingerprint_wordpress(make_ctx):
    body = '<meta name="generator" content="WordPress 6.4"> /wp-content/themes/x'
    ctx = make_ctx("https://t.test/", lambda url, **kw: FakeResponse(body))
    findings = TechFingerprintModule().run(ctx)
    assert any("WordPress" in f.title for f in findings)
