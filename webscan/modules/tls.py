"""TLS/SSL certificate and protocol analysis using the standard library."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import List, Optional

from webscan.core.context import ScanContext
from webscan.core.finding import Finding, Severity
from webscan.core.module import ScanModule

# Protocols considered insecure if the server accepts them.
WEAK_PROTOCOLS = {
    "SSLv2": ssl.TLSVersion.SSLv3,  # placeholder, handled via explicit contexts below
}


class TLSModule(ScanModule):
    name = "tls"
    category = "tls"
    description = "Inspects the TLS certificate, expiry, and protocol support."

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        if ctx.scheme != "https":
            findings.append(
                Finding(
                    module=self.name,
                    title="Target is not served over HTTPS",
                    severity=Severity.MEDIUM,
                    description=(
                        "The target uses plain HTTP, so traffic is unencrypted and "
                        "open to interception and tampering."
                    ),
                    target=ctx.target,
                    remediation="Serve the site over HTTPS and redirect HTTP to HTTPS.",
                )
            )
            return findings

        host = ctx.host
        port = ctx.port or 443

        cert = self._fetch_cert(host, port, ctx.timeout)
        if cert is None:
            findings.append(
                Finding(
                    module=self.name,
                    title="Could not establish a TLS connection",
                    severity=Severity.INFO,
                    description="The scanner was unable to complete a TLS handshake with the host.",
                    target=ctx.target,
                )
            )
            return findings

        findings.extend(self._check_expiry(cert, ctx))
        findings.extend(self._check_hostname(cert, host, ctx))
        findings.extend(self._check_protocols(host, port, ctx))
        return findings

    def _fetch_cert(self, host: str, port: int, timeout: float) -> Optional[dict]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert()
        except (ssl.SSLError, socket.error, OSError):
            # Retry without verification to still read the cert details.
            context = ssl._create_unverified_context()
            try:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.getpeercert()
            except (ssl.SSLError, socket.error, OSError):
                return None

    def _check_expiry(self, cert: dict, ctx: ScanContext) -> List[Finding]:
        not_after = cert.get("notAfter")
        if not not_after:
            return []
        try:
            expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return []
        now = datetime.datetime.utcnow()
        days_left = (expires - now).days

        if days_left < 0:
            return [
                Finding(
                    module=self.name,
                    title="TLS certificate has expired",
                    severity=Severity.HIGH,
                    description=f"The certificate expired {abs(days_left)} day(s) ago.",
                    target=ctx.target,
                    evidence=f"notAfter={not_after}",
                    remediation="Renew and deploy a valid certificate immediately.",
                )
            ]
        if days_left < 15:
            return [
                Finding(
                    module=self.name,
                    title="TLS certificate expires very soon",
                    severity=Severity.MEDIUM,
                    description=f"The certificate expires in {days_left} day(s).",
                    target=ctx.target,
                    evidence=f"notAfter={not_after}",
                    remediation="Renew the certificate before it expires.",
                )
            ]
        return [
            Finding(
                module=self.name,
                title="TLS certificate is valid",
                severity=Severity.INFO,
                description=f"The certificate is valid for another {days_left} day(s).",
                target=ctx.target,
                evidence=f"notAfter={not_after}",
            )
        ]

    def _check_hostname(self, cert: dict, host: str, ctx: ScanContext) -> List[Finding]:
        try:
            ssl.match_hostname(cert, host)
            return []
        except ssl.CertificateError as exc:
            return [
                Finding(
                    module=self.name,
                    title="TLS certificate hostname mismatch",
                    severity=Severity.HIGH,
                    description=(
                        "The certificate does not match the requested hostname, "
                        "which breaks trust and may indicate misconfiguration."
                    ),
                    target=ctx.target,
                    evidence=str(exc),
                    remediation="Install a certificate whose SAN covers this hostname.",
                )
            ]
        except Exception:
            return []

    def _check_protocols(self, host: str, port: int, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        # Test whether the server still accepts TLS 1.0 / 1.1 (deprecated).
        for label, maximum in (
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ):
            if self._accepts_protocol(host, port, maximum, ctx.timeout):
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Deprecated protocol supported: {label}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The server negotiated {label}, which is deprecated and "
                            "has known weaknesses."
                        ),
                        target=ctx.target,
                        remediation="Disable TLS 1.0/1.1; require TLS 1.2 or higher.",
                        references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                    )
                )
        return findings

    def _accepts_protocol(
        self, host: str, port: int, version: ssl.TLSVersion, timeout: float
    ) -> bool:
        context = ssl._create_unverified_context()
        try:
            context.minimum_version = version
            context.maximum_version = version
        except ValueError:
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False
