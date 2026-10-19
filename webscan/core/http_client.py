"""A thin, well-behaved HTTP client wrapper around requests.

Centralises timeouts, retries, a rotating-free custom User-Agent, redirect
control and TLS verification so every module behaves consistently.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "webscan/1.0 (+https://github.com/Tawfiqimam0/webscan)"


class HttpClient:
    """Shared HTTP client used by all scan modules."""

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool = True,
        max_retries: int = 2,
        extra_headers: Optional[dict] = None,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        if extra_headers:
            self.session.headers.update(extra_headers)

        retry = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url: str, allow_redirects: bool = True, **kwargs) -> Optional[requests.Response]:
        return self._request("GET", url, allow_redirects=allow_redirects, **kwargs)

    def head(self, url: str, allow_redirects: bool = False, **kwargs) -> Optional[requests.Response]:
        return self._request("HEAD", url, allow_redirects=allow_redirects, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self._request("POST", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        try:
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError as exc:
            logger.debug("TLS error for %s: %s", url, exc)
        except requests.exceptions.RequestException as exc:
            logger.debug("Request failed for %s: %s", url, exc)
        return None

    def close(self) -> None:
        self.session.close()
