from __future__ import annotations

from pathlib import Path

from devsecops_agent.models import ScanResult, ScanSummary
from devsecops_agent.report_writer import write_report
from devsecops_agent.utils import count_files_by_extension, validate_target_path


def run_scan(target_path: Path) -> ScanResult:
    resolved_target = validate_target_path(target_path)
    file_counts = count_files_by_extension(resolved_target)
    total_files = sum(file_counts.values())

    summary = ScanSummary(
        target_path=str(resolved_target),
        total_files=total_files,
        file_counts=file_counts,
    )
    report_path = write_report(summary)

    return ScanResult(
        target_path=summary.target_path,
        total_files=summary.total_files,
        file_counts=summary.file_counts,
        report_path=str(report_path),
    )
