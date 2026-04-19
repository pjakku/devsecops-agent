from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from devsecops_agent.config import DEFAULT_SEMGREP_CONFIGS
from devsecops_agent.models import Finding, ScannerExecution


@dataclass(slots=True)
class SemgrepRunResult:
    execution: ScannerExecution
    findings: list[Finding]


SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def resolve_semgrep_executable() -> str | None:
    return shutil.which("semgrep")


def is_semgrep_installed() -> bool:
    return resolve_semgrep_executable() is not None


def build_semgrep_command(
    executable: str,
    target_path: Path,
    configs: list[str] | None = None,
) -> list[str]:
    semgrep_configs = list(configs or DEFAULT_SEMGREP_CONFIGS)
    command = [
        executable,
        "scan",
        "--json",
        "--quiet",
    ]
    for config_value in semgrep_configs:
        command.extend(["--config", config_value])
    command.append(str(target_path))
    return command


def build_semgrep_environment() -> dict[str, str]:
    environment = dict(os.environ)
    if os.name == "nt":
        environment["PYTHONUTF8"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def run(
    target_path: Path,
    base_path: Path,
    configs: list[str] | None = None,
) -> SemgrepRunResult:
    semgrep_configs = list(configs or DEFAULT_SEMGREP_CONFIGS)
    executable = resolve_semgrep_executable()
    planned_command = build_semgrep_command("semgrep", target_path, semgrep_configs)
    if executable is None:
        return SemgrepRunResult(
            execution=ScannerExecution(
                scanner_name="semgrep",
                status="skipped",
                command=_format_command(planned_command),
                configs_used=semgrep_configs,
                findings_count=0,
                message="Semgrep not found on PATH; skipping external SAST scan.",
                stderr="",
            ),
            findings=[],
        )

    command = build_semgrep_command(executable, target_path, semgrep_configs)
    environment = build_semgrep_environment()

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
    except OSError as exc:
        stderr = str(exc)
        return SemgrepRunResult(
            execution=ScannerExecution(
                scanner_name="semgrep",
                status="failed",
                command=_format_command(command),
                configs_used=semgrep_configs,
                findings_count=0,
                message=f"Semgrep execution failed: {stderr}",
                stderr=stderr,
            ),
            findings=[],
        )

    stderr = completed.stderr.strip()
    stdout = completed.stdout or ""

    if completed.returncode not in (0, 1):
        message = stderr or "Semgrep exited with a non-zero status."
        return SemgrepRunResult(
            execution=ScannerExecution(
                scanner_name="semgrep",
                status="failed",
                command=_format_command(command),
                configs_used=semgrep_configs,
                findings_count=0,
                message=message,
                stderr=stderr,
            ),
            findings=[],
        )

    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        message = stderr or f"Semgrep returned invalid JSON output: {exc}"
        return SemgrepRunResult(
            execution=ScannerExecution(
                scanner_name="semgrep",
                status="failed",
                command=_format_command(command),
                configs_used=semgrep_configs,
                findings_count=0,
                message=message,
                stderr=stderr,
            ),
            findings=[],
        )

    findings = parse_semgrep_findings(payload, base_path)
    message = "Semgrep scan completed successfully."
    if stderr:
        message = stderr

    return SemgrepRunResult(
        execution=ScannerExecution(
            scanner_name="semgrep",
            status="ran",
            command=_format_command(command),
            configs_used=semgrep_configs,
            findings_count=len(findings),
            message=message,
            stderr=stderr,
        ),
        findings=findings,
    )


def parse_semgrep_findings(payload: dict[str, object], base_path: Path) -> list[Finding]:
    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue

        extra = item.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}

        path_value = item.get("path")
        if not isinstance(path_value, str):
            continue

        findings.append(
            Finding(
                scanner_name="semgrep",
                category="sast",
                severity=normalize_semgrep_severity(extra.get("severity")),
                title=_extract_title(item, extra),
                description=_extract_description(extra),
                file_path=_relative_file_path(Path(path_value), base_path),
                line_number=_extract_line_number(item),
                recommendation=_extract_recommendation(extra),
            )
        )

    return findings


def normalize_semgrep_severity(value: object) -> str:
    if isinstance(value, str):
        return SEMGREP_SEVERITY_MAP.get(value.upper(), "medium")
    return "medium"


def _extract_line_number(item: dict[str, object]) -> int | None:
    start = item.get("start")
    if isinstance(start, dict):
        line = start.get("line")
        if isinstance(line, int):
            return line
    return None


def _extract_title(item: dict[str, object], extra: dict[str, object]) -> str:
    message = extra.get("message")
    if isinstance(message, str) and message.strip():
        return message.strip()

    check_id = item.get("check_id")
    if isinstance(check_id, str) and check_id.strip():
        return check_id.strip()

    fallback_check_id = extra.get("check_id")
    if isinstance(fallback_check_id, str) and fallback_check_id.strip():
        return fallback_check_id.strip()
    return "Semgrep finding"


def _extract_description(extra: dict[str, object]) -> str:
    metadata = extra.get("metadata")
    if isinstance(metadata, dict):
        for key in ("description", "impact"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    message = extra.get("message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    return "Semgrep reported a potential code security issue."


def _extract_recommendation(extra: dict[str, object]) -> str:
    metadata = extra.get("metadata")
    if isinstance(metadata, dict):
        for key in ("fix", "remediation", "recommendation"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "Review the Semgrep rule match and remediate the underlying issue."


def _relative_file_path(file_path: Path, base_path: Path) -> str:
    root_path = base_path if base_path.is_dir() else base_path.parent
    try:
        if file_path.is_absolute():
            return str(file_path.relative_to(root_path))
        return str(file_path)
    except ValueError:
        return str(file_path)


def _format_command(command: list[str]) -> str:
    return " ".join(command)
