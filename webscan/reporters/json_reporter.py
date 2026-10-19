"""Machine-readable JSON report."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from webscan.branding import BRAND, TOOL_NAME
from webscan.core.engine import ScanResult


class JSONReporter:
    """Serialises a ScanResult to a JSON document."""

    def render(self, result: ScanResult) -> str:
        doc = {
            "tool": TOOL_NAME,
            "author": BRAND,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": result.target,
            "duration_seconds": result.duration,
            "modules_run": result.modules_run,
            "summary": result.counts(),
            "errors": result.errors,
            "findings": [f.to_dict() for f in result.sorted_findings()],
        }
        return json.dumps(doc, indent=2)

    def write(self, result: ScanResult, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.render(result))
