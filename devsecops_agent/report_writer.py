from __future__ import annotations

import json
import re
from pathlib import Path

from devsecops_agent import __version__
from devsecops_agent.models import Finding, ScanReport
from devsecops_agent.utils import ensure_directory

DEFAULT_INFORMATION_URI = "https://example.invalid/devsecops-agent"


def write_report(report: ScanReport, output_path: Path = Path("reports/scan-report.json")) -> Path:
    resolved_output = output_path.resolve()
    ensure_directory(resolved_output.parent)
    with resolved_output.open("w", encoding="utf-8") as file_handle:
        json.dump(report.to_dict(), file_handle, indent=2)
    return resolved_output


def write_sarif_report(report: ScanReport, output_path: Path) -> Path:
    resolved_output = output_path.resolve()
    ensure_directory(resolved_output.parent)
    rules = build_sarif_rules(report.findings)
    sarif_payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "devsecops-agent",
                        "version": __version__,
                        "informationUri": DEFAULT_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": [_finding_to_result(finding) for finding in report.findings],
            }
        ],
    }
    with resolved_output.open("w", encoding="utf-8") as file_handle:
        json.dump(sarif_payload, file_handle, indent=2)
    return resolved_output


def build_sarif_rules(findings: list[Finding]) -> list[dict[str, object]]:
    rules_by_id: dict[str, dict[str, object]] = {}
    for finding in findings:
        rule_id = build_sarif_rule_id(finding)
        rules_by_id.setdefault(rule_id, _finding_to_rule(finding, rule_id))
    return list(rules_by_id.values())


def _finding_to_rule(finding: Finding, rule_id: str) -> dict[str, object]:
    return {
        "id": rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.recommendation},
        "properties": {
            "scanner_name": finding.scanner_name,
            "category": finding.category,
            "severity": finding.severity,
        },
    }


def _finding_to_result(finding: Finding) -> dict[str, object]:
    message_text = finding.title
    if finding.description and finding.description != finding.title:
        message_text = f"{finding.title}: {finding.description}"
    result = {
        "ruleId": build_sarif_rule_id(finding),
        "level": _severity_to_sarif_level(finding.severity),
        "message": {"text": message_text},
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
            "finding_id": finding.finding_id,
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


def build_sarif_rule_id(finding: Finding) -> str:
    slug = slugify_rule_name(finding.title)
    if slug:
        return f"{finding.scanner_name}/{slug}"
    return f"{finding.scanner_name}/{finding.finding_id or 'finding'}"


def slugify_rule_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return re.sub(r"-{2,}", "-", normalized)
