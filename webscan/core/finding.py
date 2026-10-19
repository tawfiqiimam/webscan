"""Finding model and severity levels shared across all modules."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Ordered severity levels. String-valued for easy JSON serialisation."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


@dataclass
class Finding:
    """A single result produced by a scan module.

    Attributes:
        module: Name of the module that produced the finding.
        title: Short human-readable summary.
        severity: Severity level.
        description: What the issue is and why it matters.
        target: The URL/host/endpoint the finding applies to.
        evidence: Optional supporting data (matched string, header value, etc.).
        remediation: Optional guidance on how to fix it.
        references: Optional list of external references (CWE, OWASP, docs).
    """

    module: str
    title: str
    severity: Severity
    description: str
    target: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
