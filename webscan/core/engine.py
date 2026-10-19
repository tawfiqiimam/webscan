"""The scan engine: orchestrates modules against a target."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.http_client import HttpClient
from webscan.core.module import ScanModule

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Aggregated output of a full scan."""

    target: str
    findings: List[Finding] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    modules_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return round(self.finished_at - self.started_at, 2)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)

    def counts(self) -> dict:
        tally = {s.value: 0 for s in Severity}
        for f in self.findings:
            tally[f.severity.value] += 1
        return tally


class Engine:
    """Runs a sequence of modules against a single target."""

    def __init__(
        self,
        target: str,
        modules: Sequence[ScanModule],
        timeout: float = 10.0,
        verify_tls: bool = True,
        threads: int = 10,
        extra_headers: Optional[dict] = None,
    ) -> None:
        self.target = target
        self.modules = list(modules)
        self.http = HttpClient(
            timeout=timeout, verify_tls=verify_tls, extra_headers=extra_headers
        )
        self.ctx = ScanContext(
            target=target,
            http=self.http,
            timeout=timeout,
            verify_tls=verify_tls,
            threads=threads,
        )

    def run(self) -> ScanResult:
        result = ScanResult(target=self.target, started_at=time.time())
        for module in self.modules:
            logger.info("Running module: %s", module.name)
            try:
                findings = module.run(self.ctx) or []
                result.findings.extend(findings)
                result.modules_run.append(module.name)
            except Exception as exc:  # modules must never kill the scan
                msg = f"Module '{module.name}' failed: {exc}"
                logger.warning(msg)
                result.errors.append(msg)
        result.finished_at = time.time()
        self.http.close()
        return result
