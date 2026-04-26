from __future__ import annotations

from pathlib import Path

from devsecops_agent.models import Finding, ScanReport, ScanResult, ScannerExecution
from devsecops_agent.report_writer import write_report
from devsecops_agent.scanners import (
    config_scanner,
    dependency_scanner,
    gitleaks_runner,
    manifest_scanner,
    semgrep_runner,
    script_scanner,
    source_scanner,
)
from devsecops_agent.utils import (
    assign_finding_ids,
    calculate_category_summary,
    calculate_scanner_summary,
    calculate_severity_summary,
    deduplicate_findings,
    determine_overall_status,
    inspect_project_files,
    iter_project_files,
    sort_findings,
    utc_now_iso,
    validate_target_path,
)

SCANNER_PIPELINE = (
    ("source_scanner", source_scanner.run, "Internal placeholder scanner completed successfully."),
    ("config_scanner", config_scanner.run, "Internal placeholder scanner completed successfully."),
    ("manifest_scanner", manifest_scanner.run, "Internal placeholder scanner completed successfully."),
    ("dependency_scanner", dependency_scanner.run, "Internal placeholder scanner completed successfully."),
    ("script_scanner", script_scanner.run, "Internal script scanner completed successfully."),
)


def run_scan(
    target_path: Path,
    *,
    fail_on: str = "high",
    json_output_path: Path = Path("reports/scan-report.json"),
    include_semgrep: bool = True,
    semgrep_configs: list[str] | None = None,
    include_gitleaks: bool = True,
) -> ScanResult:
    resolved_target = validate_target_path(target_path)
    started_at = utc_now_iso()
    files = iter_project_files(resolved_target)
    inspection = inspect_project_files(files, resolved_target)

    findings: list[Finding] = []
    scanners_run: list[str] = []
    scanner_executions: list[ScannerExecution] = []
    for scanner_name, scanner, success_message in SCANNER_PIPELINE:
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
                message=success_message,
                stderr="",
            )
        )

    scanners_run.append("semgrep")
    if include_semgrep:
        semgrep_result = semgrep_runner.run(resolved_target, resolved_target, configs=semgrep_configs)
        findings.extend(semgrep_result.findings)
        scanner_executions.append(semgrep_result.execution)
    else:
        effective_semgrep_configs = semgrep_runner.resolve_semgrep_configs(semgrep_configs)
        scanner_executions.append(
            ScannerExecution(
                scanner_name="semgrep",
                status="skipped",
                command=" ".join(
                    semgrep_runner.build_semgrep_command(
                        "semgrep",
                        resolved_target,
                        effective_semgrep_configs,
                    )
                ),
                configs_used=effective_semgrep_configs,
                findings_count=0,
                message="Semgrep skipped by CLI option.",
                stderr="",
            )
        )

    scanners_run.append("gitleaks")
    if include_gitleaks:
        gitleaks_result = gitleaks_runner.run(resolved_target, resolved_target)
        findings.extend(gitleaks_result.findings)
        scanner_executions.append(gitleaks_result.execution)
    else:
        scanner_executions.append(
            ScannerExecution(
                scanner_name="gitleaks",
                status="skipped",
                command=" ".join(
                    gitleaks_runner.build_gitleaks_command(
                        "gitleaks",
                        resolved_target,
                        Path("<report-path>"),
                    )
                ),
                configs_used=[],
                findings_count=0,
                message="Gitleaks skipped by CLI option.",
                stderr="",
            )
        )

    findings = assign_finding_ids(deduplicate_findings(findings))
    findings = sort_findings(findings)
    severity_summary = calculate_severity_summary(findings)
    category_summary = calculate_category_summary(findings)
    scanner_summary = calculate_scanner_summary(findings)
    overall_status = determine_overall_status(severity_summary, fail_on=fail_on)
    report = ScanReport(
        target_path=str(resolved_target),
        started_at=started_at,
        completed_at=utc_now_iso(),
        total_files=inspection.total_files,
        counts_by_extension=inspection.counts_by_extension,
        project_categories=inspection.categories,
        scanners_run=scanners_run,
        fail_on=fail_on,
        total_findings=len(findings),
        scanner_executions=scanner_executions,
        findings=findings,
        severity_summary=severity_summary,
        category_summary=category_summary,
        scanner_summary=scanner_summary,
        overall_status=overall_status,
    )
    report_path = write_report(report, json_output_path)
    return ScanResult(report=report, report_path=str(report_path))
