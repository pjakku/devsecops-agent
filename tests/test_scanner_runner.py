from __future__ import annotations

import json
from pathlib import Path

import pytest

from devsecops_agent.scanner_runner import run_scan
from devsecops_agent.utils import determine_overall_status


def test_run_scan_raises_for_invalid_path(tmp_path):
    missing_path = tmp_path / "does-not-exist"

    with pytest.raises(FileNotFoundError):
        run_scan(missing_path)


def test_run_scan_safe_folder_returns_pass(tmp_path, monkeypatch):
    sample_dir = tmp_path / "safe-project"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (sample_dir / "README.md").write_text("# sample\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    result = run_scan(sample_dir)

    assert result.report.total_files == 2
    assert result.report.findings == []
    assert result.report.overall_status == "PASS"

    report_path = Path.cwd() / "reports" / "scan-report.json"
    assert report_path.exists()

    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_data["overall_status"] == "PASS"
    assert report_data["severity_summary"]["high"] == 0


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

    monkeypatch.chdir(tmp_path)
    result = run_scan(sample_dir)

    assert result.report.total_files == 2
    assert result.report.overall_status == "FAIL"
    assert result.report.severity_summary["high"] >= 1
    assert any(finding.file_path == ".env" for finding in result.report.findings)
    assert any(finding.scanner_name == "manifest_scanner" for finding in result.report.findings)


@pytest.mark.parametrize(
    ("severity_summary", "expected_status"),
    [
        ({"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}, "FAIL"),
        ({"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}, "FAIL"),
        ({"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}, "WARN"),
        ({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "PASS"),
    ],
)
def test_determine_overall_status(severity_summary, expected_status):
    assert determine_overall_status(severity_summary) == expected_status
