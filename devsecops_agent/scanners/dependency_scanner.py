from __future__ import annotations

from pathlib import Path

from devsecops_agent.models import Finding

DEPENDENCY_FILES = {
    "requirements.txt",
    "package.json",
    "pom.xml",
    "go.mod",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
}


def run(files: list[Path], base_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in files:
        if file_path.name.lower() not in DEPENDENCY_FILES:
            continue

        findings.append(
            Finding(
                scanner_name="dependency_scanner",
                category="dependency",
                severity="info",
                title="Dependency manifest detected",
                description="Dependency analysis should be run for this manifest in a later integration step.",
                file_path=_relative_path(file_path, base_path),
                line_number=None,
                recommendation="Add dependency vulnerability and license scanning when external tool integrations are enabled.",
            )
        )
    return findings


def _relative_path(file_path: Path, base_path: Path) -> str:
    if base_path.is_dir():
        return str(file_path.relative_to(base_path))
    return file_path.name
