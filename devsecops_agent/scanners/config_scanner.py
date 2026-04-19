from __future__ import annotations

from pathlib import Path

from devsecops_agent.models import Finding
from devsecops_agent.utils import read_text_file

RISKY_CONFIG_SUFFIXES = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env"}
RISKY_KEYWORDS = ("password", "token", "secret", "apikey")


def run(files: list[Path], base_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in files:
        if file_path.suffix.lower() not in RISKY_CONFIG_SUFFIXES and file_path.name.lower() not in {"dockerfile"}:
            continue

        content = read_text_file(file_path)
        if not content:
            continue

        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered_line = line.lower()
            keyword = next((item for item in RISKY_KEYWORDS if item in lowered_line), None)
            if keyword is None:
                continue

            findings.append(
                Finding(
                    scanner_name="config_scanner",
                    category="config",
                    severity="medium",
                    title="Risky keyword found in configuration",
                    description=f"The configuration contains the keyword '{keyword}', which may indicate embedded secrets.",
                    file_path=_relative_path(file_path, base_path),
                    line_number=line_number,
                    recommendation="Move sensitive values to a secure secret store or injected runtime configuration.",
                )
            )
            break
    return findings


def _relative_path(file_path: Path, base_path: Path) -> str:
    if base_path.is_dir():
        return str(file_path.relative_to(base_path))
    return file_path.name
