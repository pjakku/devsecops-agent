from __future__ import annotations

from pathlib import Path

import yaml

from devsecops_agent.utils import ensure_directory

DEFAULT_CONFIG: dict[str, object] = {
    "project_name": "devsecops-agent",
    "report_format": "json",
    "reports_directory": "reports",
    "scanners": {
        "semgrep": False,
        "gitleaks": False,
        "trivy": False,
        "dependency": False,
    },
}


def initialize_config(output_path: Path) -> Path:
    output_path = output_path.resolve()
    ensure_directory(output_path.parent)
    with output_path.open("w", encoding="utf-8") as file_handle:
        yaml.safe_dump(DEFAULT_CONFIG, file_handle, sort_keys=False)
    return output_path
