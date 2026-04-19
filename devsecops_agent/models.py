from __future__ import annotations

from dataclasses import asdict, dataclass, field

Severity = str
OverallStatus = str


@dataclass(slots=True)
class ProjectInspection:
    total_files: int
    counts_by_extension: dict[str, int]
    categories: dict[str, list[str]]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    scanner_name: str
    category: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int | None
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    target_path: str
    started_at: str
    completed_at: str
    total_files: int
    counts_by_extension: dict[str, int]
    project_categories: dict[str, list[str]]
    scanners_run: list[str]
    findings: list[Finding] = field(default_factory=list)
    severity_summary: dict[str, int] = field(default_factory=dict)
    overall_status: OverallStatus = "PASS"

    def to_dict(self) -> dict[str, object]:
        return {
            "target_path": self.target_path,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_files": self.total_files,
            "counts_by_extension": self.counts_by_extension,
            "project_categories": self.project_categories,
            "scanners_run": self.scanners_run,
            "findings": [finding.to_dict() for finding in self.findings],
            "severity_summary": self.severity_summary,
            "overall_status": self.overall_status,
        }


@dataclass(slots=True)
class ScanResult:
    report: ScanReport
    report_path: str
