"""Scan modules and a registry for discovering them."""

from __future__ import annotations

from typing import Dict, List, Type

from webscan.core.module import ScanModule
from webscan.modules.headers import SecurityHeadersModule
from webscan.modules.tls import TLSModule
from webscan.modules.tech import TechFingerprintModule
from webscan.modules.dns_info import DNSInfoModule
from webscan.modules.ports import PortScanModule
from webscan.modules.dirs import DirBruteModule
from webscan.modules.xss import XSSModule
from webscan.modules.sqli import SQLiModule
from webscan.modules.redirect import OpenRedirectModule
from webscan.modules.csrf import CSRFModule

# All available module classes, keyed by their short name.
ALL_MODULES: Dict[str, Type[ScanModule]] = {
    m.name: m
    for m in (
        DNSInfoModule,
        PortScanModule,
        TechFingerprintModule,
        DirBruteModule,
        SecurityHeadersModule,
        TLSModule,
        XSSModule,
        SQLiModule,
        OpenRedirectModule,
        CSRFModule,
    )
}


def build_modules(
    only: List[str] | None = None,
    skip: List[str] | None = None,
    categories: List[str] | None = None,
) -> List[ScanModule]:
    """Instantiate the selected modules.

    Filtering precedence: ``only`` (exact names) wins; otherwise start from all
    modules, keep those whose category is in ``categories`` (if given), then
    drop any whose name is in ``skip``.
    """
    names = list(ALL_MODULES)
    if only:
        selected = [n for n in names if n in set(only)]
    else:
        selected = names
        if categories:
            cats = set(categories)
            selected = [n for n in selected if ALL_MODULES[n].category in cats]
        if skip:
            selected = [n for n in selected if n not in set(skip)]
    return [ALL_MODULES[n]() for n in selected]


__all__ = ["ALL_MODULES", "build_modules"]
