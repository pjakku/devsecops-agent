from __future__ import annotations

import json
from pathlib import Path

from devsecops_agent import __version__
from devsecops_agent.models import Finding, ScanReport
from devsecops_agent.report_writer import write_sarif_report


def _sample_report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        target_path="sample-project",
        started_at="2026-04-26T00:00:00+00:00",
        completed_at="2026-04-26T00:01:00+00:00",
        total_files=3,
        counts_by_extension={".py": 1, ".sql": 1, ".sh": 1},
        project_categories={},
        scanners_run=["source_scanner", "script_scanner", "semgrep"],
        fail_on="high",
        total_findings=len(findings),
        findings=findings,
        severity_summary={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 1},
        category_summary={"script": 1, "sast": 1, "secrets": 1},
        scanner_summary={"script_scanner": 1, "semgrep": 1, "source_scanner": 1},
        overall_status="FAIL",
    )


def test_write_sarif_report_creates_file_and_structure(tmp_path):
    report = _sample_report(
        [
            Finding(
                finding_id="abc123def456",
                scanner_name="script_scanner",
                category="script",
                severity="high",
                title="Risky shell eval usage detected",
                description="The shell script uses eval, which can execute user-controlled input.",
                file_path="scripts/install.sh",
                line_number=4,
                recommendation="Avoid eval and pass validated arguments to explicit commands instead.",
            )
        ]
    )
    sarif_path = tmp_path / "reports" / "devsecops-agent.sarif"

    result_path = write_sarif_report(report, sarif_path)

    assert result_path == sarif_path.resolve()
    assert sarif_path.exists()
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif_data["runs"]
    driver = sarif_data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "devsecops-agent"
    assert driver["version"] == __version__
    assert driver["rules"]
    assert sarif_data["runs"][0]["results"]


def test_write_sarif_report_maps_severity_levels_and_properties(tmp_path):
    findings = [
        Finding(
            finding_id="high12345678",
            scanner_name="source_scanner",
            category="secrets",
            severity="high",
            title="Suspicious secrets-related filename detected",
            description="The filename suggests the file may contain credentials or private key material.",
            file_path=".env",
            line_number=None,
            recommendation="Review the file contents and remove secrets from source-controlled locations.",
        ),
        Finding(
            finding_id="med123456789",
            scanner_name="semgrep",
            category="sast",
            severity="medium",
            title="Unsafe subprocess usage",
            description="User input reaches shell execution.",
            file_path="app.py",
            line_number=12,
            recommendation="Use a safer API or sanitize command input.",
        ),
        Finding(
            finding_id="info12345678",
            scanner_name="dependency_scanner",
            category="dependency",
            severity="info",
            title="Dependency manifest detected",
            description="Dependency analysis should be run for this manifest in a later integration step.",
            file_path="package.json",
            line_number=None,
            recommendation="Add dependency vulnerability and license scanning when external tool integrations are enabled.",
        ),
    ]
    report = _sample_report(findings)
    sarif_path = tmp_path / "report.sarif"

    write_sarif_report(report, sarif_path)
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = sarif_data["runs"][0]["results"]

    assert [result["level"] for result in results] == ["error", "warning", "note"]
    semgrep_result = next(result for result in results if result["properties"]["scanner_name"] == "semgrep")
    assert semgrep_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert semgrep_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert semgrep_result["properties"]["category"] == "sast"
    assert semgrep_result["properties"]["severity"] == "medium"
    assert semgrep_result["properties"]["recommendation"] == "Use a safer API or sanitize command input."
    assert semgrep_result["properties"]["finding_id"] == "med123456789"
    assert semgrep_result["ruleId"] == "semgrep/unsafe-subprocess-usage"


def test_write_sarif_report_deduplicates_rules_by_rule_id(tmp_path):
    findings = [
        Finding(
            finding_id="findinga1111",
            scanner_name="script_scanner",
            category="script",
            severity="high",
            title="Risky Node.js command execution detected",
            description="The script invokes OS commands dynamically, which can lead to command injection.",
            file_path="server.js",
            line_number=3,
            recommendation="Avoid dynamic command execution and validate or allowlist all command inputs.",
        ),
        Finding(
            finding_id="findingb2222",
            scanner_name="script_scanner",
            category="script",
            severity="high",
            title="Risky Node.js command execution detected",
            description="The script invokes OS commands dynamically, which can lead to command injection.",
            file_path="worker.js",
            line_number=6,
            recommendation="Avoid dynamic command execution and validate or allowlist all command inputs.",
        ),
    ]
    report = _sample_report(findings)
    sarif_path = tmp_path / "rules.sarif"

    write_sarif_report(report, sarif_path)
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    rules = sarif_data["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 1
    assert rules[0]["id"] == "script_scanner/risky-node-js-command-execution-detected"
