from __future__ import annotations

import json
from pathlib import Path

from devsecops_agent.models import ScanSummary
from devsecops_agent.utils import ensure_directory


def write_report(summary: ScanSummary, output_path: Path = Path("reports/scan-report.json")) -> Path:
    resolved_output = output_path.resolve()
    ensure_directory(resolved_output.parent)
    with resolved_output.open("w", encoding="utf-8") as file_handle:
        json.dump(summary.to_dict(), file_handle, indent=2)
    return resolved_output
