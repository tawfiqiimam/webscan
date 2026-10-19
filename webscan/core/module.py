"""Base class every scan module inherits from."""

from __future__ import annotations

import abc
import logging
from typing import List

from webscan.core.context import ScanContext
from webscan.core.finding import Finding

logger = logging.getLogger(__name__)


class ScanModule(abc.ABC):
    """Abstract base class for a scan module.

    Subclasses set a unique ``name`` and ``category`` and implement ``run``.
    A module is self-contained: it reads from the shared ``ScanContext`` and
    returns a list of ``Finding`` objects. It must never raise — any error is
    caught by the engine and logged.
    """

    #: Unique short identifier, e.g. "headers".
    name: str = "base"
    #: Grouping used for --only/--skip filters: "recon", "web", or "tls".
    category: str = "misc"
    #: One-line human description shown in --list-modules.
    description: str = ""

    @abc.abstractmethod
    def run(self, ctx: ScanContext) -> List[Finding]:
        """Execute the check and return findings."""
        raise NotImplementedError
