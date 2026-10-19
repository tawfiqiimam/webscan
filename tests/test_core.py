"""Tests for core primitives: Finding, Severity, context, engine, reporters."""

from __future__ import annotations

import json

from webscan.core.context import ScanContext
from webscan.core.engine import Engine, ScanResult
from webscan.core.finding import Finding, Severity
from webscan.modules.headers import SecurityHeadersModule
from webscan.reporters import HTMLReporter, JSONReporter
from tests.conftest import FakeHttp, FakeResponse


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL.rank == 4


def test_finding_to_dict_serialises_severity():
    f = Finding(
        module="x", title="t", severity=Severity.HIGH, description="d", target="u"
    )
    d = f.to_dict()
    assert d["severity"] == "high"
    assert json.dumps(d)  # must be JSON-serialisable


def test_context_parses_target():
    ctx = ScanContext(target="https://example.com:8443/path", http=FakeHttp())
    assert ctx.scheme == "https"
    assert ctx.host == "example.com"
    assert ctx.port == 8443
    assert ctx.base_url == "https://example.com:8443"


def test_scan_result_counts_and_sorting():
    r = ScanResult(target="u")
    r.findings = [
        Finding("m", "low", Severity.LOW, "d", "u"),
        Finding("m", "crit", Severity.CRITICAL, "d", "u"),
        Finding("m", "info", Severity.INFO, "d", "u"),
    ]
    assert r.counts()["critical"] == 1
    assert r.sorted_findings()[0].severity == Severity.CRITICAL


def test_engine_runs_module_and_handles_errors():
    http_handler = lambda url, **kw: FakeResponse("", headers={"Server": "nginx"})

    class BoomModule(SecurityHeadersModule):
        name = "boom"

        def run(self, ctx):
            raise RuntimeError("intentional")

    engine = Engine(target="https://t.test/", modules=[SecurityHeadersModule(), BoomModule()])
    engine.http = FakeHttp(http_handler)
    engine.ctx.http = engine.http
    result = engine.run()
    assert "headers" in result.modules_run
    assert len(result.errors) == 1  # boom was caught, scan continued


def test_json_reporter_valid():
    r = ScanResult(target="https://t.test/")
    r.findings = [Finding("m", "t", Severity.HIGH, "d", "https://t.test/")]
    out = JSONReporter().render(r)
    parsed = json.loads(out)
    assert parsed["author"] == "T4WF1Q"
    assert parsed["summary"]["high"] == 1


def test_html_reporter_contains_brand():
    r = ScanResult(target="https://t.test/")
    r.findings = [Finding("m", "Title Here", Severity.MEDIUM, "d", "https://t.test/")]
    html = HTMLReporter().render(r)
    assert "T4WF1Q" in html
    assert "Title Here" in html
