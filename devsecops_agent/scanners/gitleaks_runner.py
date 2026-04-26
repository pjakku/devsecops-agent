from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from devsecops_agent.models import Finding, ScannerExecution


@dataclass(slots=True)
class GitleaksRunResult:
    execution: ScannerExecution
    findings: list[Finding]


if os.name == "nt":
    BUNDLED_GITLEAKS_RELATIVE_PATH = Path("gitleaks") / "win" / "gitleaks.exe"
elif sys.platform == "darwin":
    BUNDLED_GITLEAKS_RELATIVE_PATH = Path("gitleaks") / "macos" / "gitleaks"
else:
    BUNDLED_GITLEAKS_RELATIVE_PATH = Path("gitleaks") / "linux" / "gitleaks"

GITLEAKS_RECOMMENDATION = (
    "Rotate the exposed secret, remove it from source control, and move it to a secure secret manager such as "
    "AWS Secrets Manager, HashiCorp Vault, or an equivalent approved secret store."
)


def resolve_gitleaks_executable() -> str | None:
    bundled_executable = resolve_bundled_gitleaks_executable()
    if bundled_executable is not None:
        return str(bundled_executable)
    return shutil.which("gitleaks")


def resolve_bundled_gitleaks_executable() -> Path | None:
    candidate = get_bundled_gitleaks_path()
    if candidate.is_file():
        return candidate
    return None


def get_bundled_gitleaks_path() -> Path:
    executable_dir = Path(sys.executable).resolve().parent
    return executable_dir / BUNDLED_GITLEAKS_RELATIVE_PATH


def build_gitleaks_command(
    executable: str,
    target_path: Path,
    report_path: Path,
) -> list[str]:
    return [
        executable,
        "detect",
        "--source",
        str(target_path),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-banner",
        "--no-git",
    ]


def build_gitleaks_environment() -> dict[str, str]:
    environment = dict(os.environ)
    if os.name == "nt":
        environment["PYTHONUTF8"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def run(target_path: Path, base_path: Path) -> GitleaksRunResult:
    executable = resolve_gitleaks_executable()
    placeholder_report_path = Path("<report-path>")
    planned_command = build_gitleaks_command("gitleaks", target_path, placeholder_report_path)
    if executable is None:
        bundled_path = get_bundled_gitleaks_path()
        return GitleaksRunResult(
            execution=ScannerExecution(
                scanner_name="gitleaks",
                status="skipped",
                command=_format_command(planned_command),
                configs_used=[],
                findings_count=0,
                message=(
                    "Gitleaks not found. Checked bundled path "
                    f"{bundled_path} and PATH; skipping external secrets scan."
                ),
                stderr="",
            ),
            findings=[],
        )

    report_file = tempfile.NamedTemporaryFile(prefix="gitleaks-", suffix=".json", delete=False)
    report_path = Path(report_file.name)
    report_file.close()
    command = build_gitleaks_command(executable, target_path, report_path)
    environment = build_gitleaks_environment()

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
    except OSError as exc:
        _cleanup_report_file(report_path)
        stderr = str(exc)
        return GitleaksRunResult(
            execution=ScannerExecution(
                scanner_name="gitleaks",
                status="failed",
                command=_format_command(command),
                configs_used=[],
                findings_count=0,
                message=f"Gitleaks execution failed: {stderr}",
                stderr=stderr,
            ),
            findings=[],
        )

    stderr = completed.stderr.strip()
    stdout = completed.stdout or ""
    try:
        payload = load_gitleaks_payload(report_path, stdout)
    finally:
        _cleanup_report_file(report_path)

    if completed.returncode not in (0, 1):
        message = stderr or "Gitleaks exited with a non-zero status."
        return GitleaksRunResult(
            execution=ScannerExecution(
                scanner_name="gitleaks",
                status="failed",
                command=_format_command(command),
                configs_used=[],
                findings_count=0,
                message=message,
                stderr=stderr,
            ),
            findings=[],
        )

    if payload is None:
        message = stderr or "Gitleaks returned invalid JSON output."
        return GitleaksRunResult(
            execution=ScannerExecution(
                scanner_name="gitleaks",
                status="failed",
                command=_format_command(command),
                configs_used=[],
                findings_count=0,
                message=message,
                stderr=stderr,
            ),
            findings=[],
        )

    findings = parse_gitleaks_findings(payload, base_path)
    message = "Gitleaks scan completed successfully."
    if completed.returncode == 0 and stderr:
        message = stderr

    return GitleaksRunResult(
        execution=ScannerExecution(
            scanner_name="gitleaks",
            status="ran",
            command=_format_command(command),
            configs_used=[],
            findings_count=len(findings),
            message=message,
            stderr="",
        ),
        findings=findings,
    )


def load_gitleaks_payload(report_path: Path, stdout: str) -> object | None:
    raw_payload = ""
    if report_path.is_file():
        raw_payload = report_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw_payload and stdout.strip():
        raw_payload = stdout.strip()
    if not raw_payload:
        return []
    try:
        return json.loads(raw_payload)
    except json.JSONDecodeError:
        return None


def parse_gitleaks_findings(payload: object, base_path: Path) -> list[Finding]:
    results = _extract_results(payload)
    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue

        path_value = _extract_value(item, "File", "file")
        if not isinstance(path_value, str) or not path_value.strip():
            continue

        findings.append(
            Finding(
                finding_id="",
                scanner_name="gitleaks",
                category="secrets",
                severity="high",
                title=_extract_title(item),
                description=_extract_description(item),
                file_path=_relative_file_path(Path(path_value), base_path),
                line_number=_extract_line_number(item),
                recommendation=GITLEAKS_RECOMMENDATION,
            )
        )

    return findings


def _extract_results(payload: object) -> list[object]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("findings", "results", "leaks"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


def _extract_line_number(item: dict[str, object]) -> int | None:
    for key in ("StartLine", "start_line", "line"):
        value = item.get(key)
        if isinstance(value, int):
            return value
    return None


def _extract_title(item: dict[str, object]) -> str:
    for key in ("RuleID", "Description", "SecretType"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "Potential secret detected"


def _extract_description(item: dict[str, object]) -> str:
    parts = ["Potential secret detected by Gitleaks."]

    description = _extract_value(item, "Description")
    title = _extract_title(item)
    if isinstance(description, str) and description.strip() and description.strip() != title:
        parts.append(description.strip())

    metadata_parts: list[str] = []
    rule_id = _extract_value(item, "RuleID")
    if isinstance(rule_id, str) and rule_id.strip():
        metadata_parts.append(f"rule={rule_id.strip()}")

    fingerprint = _extract_value(item, "Fingerprint", "fingerprint")
    if isinstance(fingerprint, str) and fingerprint.strip():
        metadata_parts.append(f"fingerprint={fingerprint.strip()}")

    commit = _extract_value(item, "Commit", "commit")
    if isinstance(commit, str) and commit.strip():
        metadata_parts.append(f"commit={commit.strip()[:12]}")

    author = _extract_value(item, "Author", "author")
    if isinstance(author, str) and author.strip():
        metadata_parts.append(f"author={author.strip()}")

    email = _extract_value(item, "Email", "email")
    if isinstance(email, str) and email.strip():
        metadata_parts.append(f"email={email.strip()}")

    redacted_match = _extract_value(
        item,
        "Redacted",
        "redacted",
        "RedactedSecret",
        "redacted_secret",
        "MaskedSecret",
    )
    if isinstance(redacted_match, str) and redacted_match.strip():
        metadata_parts.append(f"match={redacted_match.strip()}")

    if metadata_parts:
        parts.append("Metadata: " + "; ".join(metadata_parts) + ".")

    return " ".join(parts)


def _extract_value(item: dict[str, object], *keys: str) -> object:
    for key in keys:
        if key in item:
            return item[key]
    return None


def _relative_file_path(file_path: Path, base_path: Path) -> str:
    root_path = base_path if base_path.is_dir() else base_path.parent
    try:
        if file_path.is_absolute():
            return str(file_path.relative_to(root_path))
        return str(file_path)
    except ValueError:
        return str(file_path)


def _cleanup_report_file(report_path: Path) -> None:
    try:
        report_path.unlink(missing_ok=True)
    except OSError:
        return


def _format_command(command: list[str]) -> str:
    return " ".join(command)
