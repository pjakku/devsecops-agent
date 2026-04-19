from __future__ import annotations

import json
from pathlib import Path

from devsecops_agent.models import Finding, ScanReport
from devsecops_agent.utils import ensure_directory


def write_report(report: ScanReport, output_path: Path = Path("reports/scan-report.json")) -> Path:
    resolved_output = output_path.resolve()
    ensure_directory(resolved_output.parent)
    with resolved_output.open("w", encoding="utf-8") as file_handle:
        json.dump(report.to_dict(), file_handle, indent=2)
    return resolved_output


def write_sarif_report(report: ScanReport, output_path: Path) -> Path:
    resolved_output = output_path.resolve()
    ensure_directory(resolved_output.parent)
    sarif_payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "devsecops-agent",
                        "informationUri": "https://example.invalid/devsecops-agent",
                        "rules": [_finding_to_rule(finding) for finding in report.findings],
                    }
                },
                "results": [_finding_to_result(finding) for finding in report.findings],
            }
        ],
    }
    with resolved_output.open("w", encoding="utf-8") as file_handle:
        json.dump(sarif_payload, file_handle, indent=2)
    return resolved_output


def _finding_to_rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.finding_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.recommendation},
        "properties": {
            "category": finding.category,
            "scanner": finding.scanner_name,
            "severity": finding.severity,
        },
    }


def _finding_to_result(finding: Finding) -> dict[str, object]:
    result = {
        "ruleId": finding.finding_id,
        "level": _severity_to_sarif_level(finding.severity),
        "message": {"text": finding.title},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                }
            }
        ],
        "properties": {
            "scanner_name": finding.scanner_name,
            "category": finding.category,
            "severity": finding.severity,
            "recommendation": finding.recommendation,
        },
    }
    if finding.line_number is not None:
        result["locations"][0]["physicalLocation"]["region"] = {"startLine": finding.line_number}
    return result


def _severity_to_sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
