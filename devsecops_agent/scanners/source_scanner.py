from __future__ import annotations

from pathlib import Path

from devsecops_agent.models import Finding

SUSPICIOUS_SOURCE_FILE_PATTERNS = (".env", "secret", "secrets", "credential", "credentials", "id_rsa")


def run(files: list[Path], base_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in files:
        file_name = file_path.name.lower()
        if not any(pattern in file_name for pattern in SUSPICIOUS_SOURCE_FILE_PATTERNS):
            continue

        findings.append(
            Finding(
                scanner_name="source_scanner",
                category="secrets",
                severity="high",
                title="Suspicious secrets-related filename detected",
                description="The filename suggests the file may contain credentials or private key material.",
                file_path=_relative_path(file_path, base_path),
                line_number=None,
                recommendation="Review the file contents and remove secrets from source-controlled locations.",
            )
        )
    return findings


def _relative_path(file_path: Path, base_path: Path) -> str:
    if base_path.is_dir():
        return str(file_path.relative_to(base_path))
    return file_path.name
