from __future__ import annotations

from pathlib import Path

from devsecops_agent.models import Finding
from devsecops_agent.utils import read_text_file

KUBERNETES_SUFFIXES = {".yaml", ".yml"}
SUSPICIOUS_PATTERNS = {
    "latest": (
        "medium",
        "Container image uses latest tag",
        "Pin container images to immutable versions instead of using the latest tag.",
    ),
    "privileged: true": (
        "high",
        "Privileged container setting detected",
        "Avoid privileged containers unless strictly required and documented.",
    ),
    "runasuser: 0": (
        "high",
        "Container configured to run as root",
        "Set a non-root user in the workload security context.",
    ),
}


def run(files: list[Path], base_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in files:
        if file_path.suffix.lower() not in KUBERNETES_SUFFIXES:
            continue

        content = read_text_file(file_path)
        if "kind:" not in content.lower():
            continue

        lowered_lines = content.splitlines()
        for line_number, line in enumerate(lowered_lines, start=1):
            normalized_line = line.lower().strip()
            for pattern, (severity, title, recommendation) in SUSPICIOUS_PATTERNS.items():
                if pattern not in normalized_line:
                    continue
                findings.append(
                    Finding(
                        scanner_name="manifest_scanner",
                        category="manifest",
                        severity=severity,
                        title=title,
                        description="A Kubernetes-style manifest contains a potentially risky configuration.",
                        file_path=_relative_path(file_path, base_path),
                        line_number=line_number,
                        recommendation=recommendation,
                    )
                )
    return findings


def _relative_path(file_path: Path, base_path: Path) -> str:
    if base_path.is_dir():
        return str(file_path.relative_to(base_path))
    return file_path.name
