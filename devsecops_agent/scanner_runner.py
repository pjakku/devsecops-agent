from __future__ import annotations

from pathlib import Path

from devsecops_agent.models import Finding, ScanReport, ScanResult, ScannerExecution
from devsecops_agent.report_writer import write_report
from devsecops_agent.scanners import config_scanner, dependency_scanner, manifest_scanner, semgrep_runner, source_scanner
from devsecops_agent.utils import (
    calculate_severity_summary,
    determine_overall_status,
    inspect_project_files,
    iter_project_files,
    utc_now_iso,
    validate_target_path,
)

SCANNER_PIPELINE = (
    ("source_scanner", source_scanner.run),
    ("config_scanner", config_scanner.run),
    ("manifest_scanner", manifest_scanner.run),
    ("dependency_scanner", dependency_scanner.run),
)


def run_scan(target_path: Path) -> ScanResult:
    resolved_target = validate_target_path(target_path)
    started_at = utc_now_iso()
    files = iter_project_files(resolved_target)
    inspection = inspect_project_files(files, resolved_target)

    findings: list[Finding] = []
    scanners_run: list[str] = []
    scanner_executions: list[ScannerExecution] = []
    for scanner_name, scanner in SCANNER_PIPELINE:
        scanners_run.append(scanner_name)
        scanner_findings = scanner(files, resolved_target)
        findings.extend(scanner_findings)
        scanner_executions.append(
            ScannerExecution(
                scanner_name=scanner_name,
                status="ran",
                command="internal",
                configs_used=[],
                findings_count=len(scanner_findings),
                message="Internal placeholder scanner completed successfully.",
                stderr="",
            )
        )

    scanners_run.append("semgrep")
    semgrep_result = semgrep_runner.run(resolved_target, resolved_target)
    findings.extend(semgrep_result.findings)
    scanner_executions.append(semgrep_result.execution)

    severity_summary = calculate_severity_summary(findings)
    overall_status = determine_overall_status(severity_summary)
    report = ScanReport(
        target_path=str(resolved_target),
        started_at=started_at,
        completed_at=utc_now_iso(),
        total_files=inspection.total_files,
        counts_by_extension=inspection.counts_by_extension,
        project_categories=inspection.categories,
        scanners_run=scanners_run,
        scanner_executions=scanner_executions,
        findings=findings,
        severity_summary=severity_summary,
        overall_status=overall_status,
    )
    report_path = write_report(report)
    return ScanResult(report=report, report_path=str(report_path))
