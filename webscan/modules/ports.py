"""A simple, concurrent TCP connect port scanner for common service ports."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule

# Common ports and their usual service, kept small and polite by default.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}

# Ports that are noteworthy if exposed to the internet.
RISKY_PORTS = {23, 445, 3306, 3389, 5432, 6379, 27017}


class PortScanModule(ScanModule):
    name = "ports"
    category = "recon"
    description = "TCP connect scan of common service ports."

    def run(self, ctx: ScanContext) -> List[Finding]:
        if not ctx.host:
            return []

        open_ports: List[Tuple[int, str]] = []
        with ThreadPoolExecutor(max_workers=ctx.threads) as pool:
            futures = {
                pool.submit(self._is_open, ctx.host, port, min(ctx.timeout, 3.0)): port
                for port in COMMON_PORTS
            }
            for fut in as_completed(futures):
                port = futures[fut]
                if fut.result():
                    open_ports.append((port, COMMON_PORTS[port]))

        open_ports.sort()
        findings: List[Finding] = []
        for port, service in open_ports:
            severity = Severity.MEDIUM if port in RISKY_PORTS else Severity.INFO
            desc = f"Port {port} ({service}) is open."
            if port in RISKY_PORTS:
                desc += " Exposing this service to the internet is risky."
            findings.append(
                Finding(
                    module=self.name,
                    title=f"Open port {port}/tcp ({service})",
                    severity=severity,
                    description=desc,
                    target=ctx.host,
                    evidence=f"{ctx.host}:{port}",
                    remediation=(
                        "Restrict access with a firewall or bind the service to localhost "
                        "if it should not be public."
                    )
                    if port in RISKY_PORTS
                    else None,
                )
            )

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    title="No common ports found open",
                    severity=Severity.INFO,
                    description="None of the scanned common ports responded.",
                    target=ctx.host,
                )
            )
        return findings

    @staticmethod
    def _is_open(host: str, port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False
