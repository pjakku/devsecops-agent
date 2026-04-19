from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devsecops_agent.cli import app
from devsecops_agent.models import Finding, ScannerExecution
from devsecops_agent.scanner_runner import run_scan
from devsecops_agent.scanners import semgrep_runner
from devsecops_agent.scanners.semgrep_runner import SemgrepRunResult
from devsecops_agent.utils import determine_overall_status

runner = CliRunner()


def test_run_scan_raises_for_invalid_path(tmp_path):
    missing_path = tmp_path / "does-not-exist"

    with pytest.raises(FileNotFoundError):
        run_scan(missing_path)


def test_run_scan_safe_folder_returns_pass(tmp_path, monkeypatch):
    sample_dir = tmp_path / "safe-project"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (sample_dir / "README.md").write_text("# sample\n", encoding="utf-8")

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: None)
    monkeypatch.chdir(tmp_path)
    result = run_scan(sample_dir)

    assert result.report.total_files == 2
    assert result.report.findings == []
    assert result.report.total_findings == 0
    assert result.report.overall_status == "PASS"
    assert any(execution.scanner_name == "semgrep" and execution.status == "skipped" for execution in result.report.scanner_executions)

    report_path = Path.cwd() / "reports" / "scan-report.json"
    assert report_path.exists()

    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_data["overall_status"] == "PASS"
    assert report_data["total_findings"] == 0
    assert report_data["severity_summary"]["high"] == 0
    assert any(execution["scanner_name"] == "semgrep" and execution["status"] == "skipped" for execution in report_data["scanner_executions"])


def test_run_scan_generates_findings_for_risky_files(tmp_path, monkeypatch):
    sample_dir = tmp_path / "risky-project"
    sample_dir.mkdir()
    (sample_dir / ".env").write_text("API_TOKEN=example\n", encoding="utf-8")
    (sample_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: demo:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "            runAsUser: 0\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: None)
    monkeypatch.chdir(tmp_path)
    result = run_scan(sample_dir)

    assert result.report.total_files == 2
    assert result.report.overall_status == "FAIL"
    assert result.report.severity_summary["high"] >= 1
    assert result.report.category_summary["manifest"] >= 1
    assert any(finding.file_path == ".env" for finding in result.report.findings)
    assert any(finding.scanner_name == "manifest_scanner" for finding in result.report.findings)
    assert all(finding.finding_id for finding in result.report.findings)


def test_run_scan_respects_fail_on_threshold(tmp_path, monkeypatch):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / "settings.yaml").write_text("password: demo\n", encoding="utf-8")

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: None)
    result_warn = run_scan(sample_dir, fail_on="high")
    result_fail = run_scan(sample_dir, fail_on="medium")

    assert result_warn.report.overall_status == "WARN"
    assert result_fail.report.overall_status == "FAIL"


def test_run_scan_supports_json_output_override(tmp_path, monkeypatch):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")
    output_path = tmp_path / "artifacts" / "custom-report.json"

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: None)
    result = run_scan(sample_dir, json_output_path=output_path)

    assert Path(result.report_path) == output_path.resolve()
    assert output_path.exists()


def test_run_scan_supports_no_semgrep_option(tmp_path):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")

    result = run_scan(sample_dir, include_semgrep=False)

    semgrep_execution = next(execution for execution in result.report.scanner_executions if execution.scanner_name == "semgrep")
    assert semgrep_execution.status == "skipped"
    assert "cli option" in semgrep_execution.message.lower()


def test_deduplicates_overlapping_findings(tmp_path, monkeypatch):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / ".env").write_text("API_TOKEN=example\n", encoding="utf-8")

    def fake_semgrep_run(target_path, base_path):
        return SemgrepRunResult(
            execution=ScannerExecution(
                scanner_name="semgrep",
                status="ran",
                command="semgrep scan",
                configs_used=["p/python", "p/kubernetes"],
                findings_count=1,
                message="Semgrep scan completed successfully.",
                stderr="",
            ),
            findings=[
                Finding(
                    finding_id="",
                    scanner_name="semgrep",
                    category="sast",
                    severity="high",
                    title="Suspicious secrets related filename detected",
                    description="Overlapping finding for the same file.",
                    file_path=".env",
                    line_number=None,
                    recommendation="Remove secrets from source control.",
                )
            ],
        )

    monkeypatch.setattr(semgrep_runner, "run", fake_semgrep_run)
    result = run_scan(sample_dir)

    matching_findings = [finding for finding in result.report.findings if finding.file_path == ".env" and finding.severity == "high"]
    assert len(matching_findings) == 1


def test_semgrep_not_installed_is_skipped(tmp_path, monkeypatch):
    sample_dir = tmp_path / "safe-project"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: None)
    result = run_scan(sample_dir)

    semgrep_execution = next(
        execution for execution in result.report.scanner_executions if execution.scanner_name == "semgrep"
    )
    assert semgrep_execution.status == "skipped"
    assert semgrep_execution.findings_count == 0
    assert "not found on path" in semgrep_execution.message.lower()
    assert semgrep_execution.configs_used == ["p/python", "p/kubernetes"]
    assert semgrep_execution.stderr == ""


def test_semgrep_installed_with_no_findings(tmp_path, monkeypatch):
    sample_dir = tmp_path / "safe-project"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout='{"results": []}',
            stderr="",
        )

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: "semgrep")
    monkeypatch.setattr(semgrep_runner.subprocess, "run", fake_run)

    result = run_scan(sample_dir)

    semgrep_execution = next(
        execution for execution in result.report.scanner_executions if execution.scanner_name == "semgrep"
    )
    assert semgrep_execution.status == "ran"
    assert semgrep_execution.findings_count == 0
    assert semgrep_execution.command == (
        "semgrep scan --json --quiet --config p/python --config p/kubernetes {}".format(sample_dir.resolve())
    )
    assert semgrep_execution.configs_used == ["p/python", "p/kubernetes"]
    assert result.report.overall_status == "PASS"


def test_semgrep_path_detection_uses_shutil_which(monkeypatch):
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda name: "C:\\Tools\\semgrep.exe" if name == "semgrep" else None)

    assert semgrep_runner.resolve_semgrep_executable() == "C:\\Tools\\semgrep.exe"


def test_build_semgrep_command_with_multiple_configs(tmp_path):
    command = semgrep_runner.build_semgrep_command(
        "semgrep",
        tmp_path,
        ["p/python", "p/kubernetes"],
    )

    assert command == [
        "semgrep",
        "scan",
        "--json",
        "--quiet",
        "--config",
        "p/python",
        "--config",
        "p/kubernetes",
        str(tmp_path),
    ]


def test_semgrep_run_returns_valid_json_findings(tmp_path, monkeypatch):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout=json.dumps(
                {
                    "results": [
                        {
                            "path": str(sample_dir / "app.py"),
                            "start": {"line": 3},
                            "extra": {
                                "severity": "WARNING",
                                "message": "Possible weak validation",
                                "metadata": {
                                    "description": "Unsanitized data reaches a sink.",
                                    "fix": "Validate input before use.",
                                },
                            },
                        }
                    ]
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: "semgrep")
    monkeypatch.setattr(semgrep_runner.subprocess, "run", fake_run)

    result = semgrep_runner.run(sample_dir, sample_dir)

    assert result.execution.status == "ran"
    assert result.execution.findings_count == 1
    assert result.execution.stderr == ""
    assert result.execution.configs_used == ["p/python", "p/kubernetes"]
    assert len(result.findings) == 1
    assert result.findings[0].severity == "medium"


def test_parse_semgrep_findings_normalizes_fields(tmp_path):
    payload = {
        "results": [
            {
                "path": str(tmp_path / "app.py"),
                "start": {"line": 14},
                "extra": {
                    "severity": "ERROR",
                    "message": "Unsafe subprocess usage",
                    "metadata": {
                        "description": "User input reaches shell execution.",
                        "fix": "Use a safer API or sanitize command input.",
                    },
                },
            }
        ]
    }

    findings = semgrep_runner.parse_semgrep_findings(payload, tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner_name == "semgrep"
    assert finding.category == "sast"
    assert finding.severity == "high"
    assert finding.title == "Unsafe subprocess usage"
    assert finding.description == "User input reaches shell execution."
    assert finding.file_path == "app.py"
    assert finding.line_number == 14
    assert finding.recommendation == "Use a safer API or sanitize command input."


def test_semgrep_failure_does_not_crash_scan(tmp_path, monkeypatch):
    sample_dir = tmp_path / "risky-project"
    sample_dir.mkdir()
    (sample_dir / ".env").write_text("API_TOKEN=example\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout="",
            stderr="Semgrep crashed",
        )

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: "semgrep")
    monkeypatch.setattr(semgrep_runner.subprocess, "run", fake_run)

    result = run_scan(sample_dir)

    semgrep_execution = next(
        execution for execution in result.report.scanner_executions if execution.scanner_name == "semgrep"
    )
    assert semgrep_execution.status == "failed"
    assert semgrep_execution.findings_count == 0
    assert semgrep_execution.stderr == "Semgrep crashed"
    assert semgrep_execution.message == "Semgrep crashed"
    assert semgrep_execution.configs_used == ["p/python", "p/kubernetes"]
    assert result.report.overall_status == "FAIL"
    assert any(finding.scanner_name == "source_scanner" for finding in result.report.findings)


def test_semgrep_failure_with_invalid_config_is_reported(tmp_path, monkeypatch):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout="",
            stderr="Failed to load config p/invalid",
        )

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: "semgrep")
    monkeypatch.setattr(semgrep_runner.subprocess, "run", fake_run)

    result = semgrep_runner.run(sample_dir, sample_dir, configs=["p/python", "p/invalid"])

    assert result.execution.status == "failed"
    assert result.execution.configs_used == ["p/python", "p/invalid"]
    assert result.execution.stderr == "Failed to load config p/invalid"
    assert result.execution.message == "Failed to load config p/invalid"


def test_semgrep_runner_sets_windows_utf8_env(monkeypatch):
    monkeypatch.setattr(semgrep_runner.os, "name", "nt")
    monkeypatch.setattr(semgrep_runner.os, "environ", {"PATH": "C:\\Tools"})

    environment = semgrep_runner.build_semgrep_environment()

    assert environment["PATH"] == "C:\\Tools"
    assert environment["PYTHONUTF8"] == "1"
    assert environment["PYTHONIOENCODING"] == "utf-8"


def test_cli_supports_fail_on_and_json_out_and_no_semgrep(tmp_path, monkeypatch):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / "settings.yaml").write_text("password: demo\n", encoding="utf-8")
    output_path = tmp_path / "reports" / "override.json"

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            str(sample_dir),
            "--fail-on",
            "medium",
            "--json-out",
            str(output_path),
            "--no-semgrep",
        ],
    )

    assert result.exit_code == 0
    assert "Fail threshold: medium" in result.stdout
    assert "Semgrep skipped by CLI option." in result.stdout
    assert output_path.exists()


def test_cli_displays_top_findings_in_severity_order(tmp_path, monkeypatch):
    sample_dir = tmp_path / "project"
    sample_dir.mkdir()
    (sample_dir / ".env").write_text("API_TOKEN=example\n", encoding="utf-8")
    (sample_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: demo:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "            runAsUser: 0\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(semgrep_runner, "resolve_semgrep_executable", lambda: None)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(sample_dir), "--no-semgrep"])

    assert result.exit_code == 0
    assert "Top findings:" in result.stdout
    high_index = result.stdout.index("[high]")
    medium_index = result.stdout.index("[medium]")
    assert high_index < medium_index


@pytest.mark.parametrize(
    ("severity_summary", "fail_on", "expected_status"),
    [
        ({"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}, "high", "FAIL"),
        ({"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}, "high", "FAIL"),
        ({"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}, "high", "WARN"),
        ({"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}, "medium", "FAIL"),
        ({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "high", "PASS"),
    ],
)
def test_determine_overall_status(severity_summary, fail_on, expected_status):
    assert determine_overall_status(severity_summary, fail_on=fail_on) == expected_status
