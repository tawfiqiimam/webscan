"""Shared test fixtures: a fake HTTP response and client."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Callable, Optional

import pytest

from webscan.core.context import ScanContext


class FakeResponse:
    def __init__(self, text="", headers=None, status=200, cookies=None):
        self.text = text
        self.headers = headers or {}
        self.status_code = status
        self.cookies = cookies or []


class FakeHttp:
    """Mimics HttpClient. Routes GET through a user-supplied handler."""

    def __init__(self, handler: Optional[Callable[[str], FakeResponse]] = None):
        self._handler = handler or (lambda url, **kw: FakeResponse())

    def get(self, url, **kwargs):
        return self._handler(url, **kwargs)

    def head(self, url, **kwargs):
        return self._handler(url, **kwargs)

    def post(self, url, **kwargs):
        return self._handler(url, **kwargs)

    def close(self):
        pass


@pytest.fixture
def make_ctx():
    def _make(target: str, handler=None) -> ScanContext:
        return ScanContext(target=target, http=FakeHttp(handler))

    return _make


@pytest.fixture
def fake_response():
    return FakeResponse
