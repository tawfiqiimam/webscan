"""Shared scan context passed to every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from webscan.core.http_client import HttpClient


@dataclass
class ScanContext:
    """Everything a module needs to do its job.

    One context is created per target and reused by all modules so they share
    a single HTTP session and parsed target metadata.
    """

    target: str
    http: HttpClient
    timeout: float = 10.0
    verify_tls: bool = True
    threads: int = 10
    # Populated from the parsed target for convenience.
    scheme: str = field(init=False)
    host: str = field(init=False)
    port: Optional[int] = field(init=False)

    def __post_init__(self) -> None:
        parsed = urlparse(self.target)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.hostname or ""
        self.port = parsed.port

    @property
    def base_url(self) -> str:
        port = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port}"
