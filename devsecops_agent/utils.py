from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from devsecops_agent.models import Finding, OverallStatus, ProjectInspection, Severity

DEFAULT_EXCLUDED_DIRECTORIES = {
    ".venv",
    "venv",
    ".git",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
}

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".sh",
}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties"}
MANIFEST_FILES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pom.xml",
    "go.mod",
    "go.sum",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "cargo.toml",
}
DEPENDENCY_FILES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pom.xml",
    "go.mod",
    "go.sum",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
}
SECRETS_FILE_PATTERNS = (".env", "secret", "secrets", "credential", "credentials", "id_rsa")


def validate_target_path(target_path: Path) -> Path:
    resolved_target = target_path.resolve()
    if not resolved_target.exists():
        raise FileNotFoundError(f"Target path does not exist: {resolved_target}")
    return resolved_target


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def should_exclude_path(path: Path) -> bool:
    return path.name in DEFAULT_EXCLUDED_DIRECTORIES


def iter_project_files(target_path: Path) -> list[Path]:
    if target_path.is_file():
        return [target_path]

    files: list[Path] = []

    def walk(path: Path) -> None:
        for child_path in path.iterdir():
            if child_path.is_dir():
                if should_exclude_path(child_path):
                    continue
                walk(child_path)
                continue
            files.append(child_path)

    walk(target_path)
    return sorted(files)


def count_files_by_extension(files: list[Path]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for file_path in files:
        extension = file_path.suffix.lower() or "<no_extension>"
        counter[extension] += 1
    return dict(sorted(counter.items()))


def inspect_project_files(files: list[Path], base_path: Path) -> ProjectInspection:
    categories = {
        "source_code": [],
        "config": [],
        "manifests": [],
        "dependencies": [],
        "secrets_related": [],
    }

    for file_path in files:
        relative_path = str(file_path.relative_to(base_path if base_path.is_dir() else file_path.parent))
        file_name = file_path.name.lower()
        suffix = file_path.suffix.lower()

        if suffix in SOURCE_EXTENSIONS:
            categories["source_code"].append(relative_path)
        if suffix in CONFIG_EXTENSIONS:
            categories["config"].append(relative_path)
        if file_name in MANIFEST_FILES:
            categories["manifests"].append(relative_path)
        if file_name in DEPENDENCY_FILES:
            categories["dependencies"].append(relative_path)
        if any(pattern in file_name for pattern in SECRETS_FILE_PATTERNS):
            categories["secrets_related"].append(relative_path)

    normalized_categories = {key: sorted(set(value)) for key, value in categories.items()}
    return ProjectInspection(
        total_files=len(files),
        counts_by_extension=count_files_by_extension(files),
        categories=normalized_categories,
    )


def assign_finding_ids(findings: list[Finding]) -> list[Finding]:
    identified_findings: list[Finding] = []
    for finding in findings:
        if finding.finding_id:
            identified_findings.append(finding)
            continue
        finding.finding_id = generate_finding_id(finding)
        identified_findings.append(finding)
    return identified_findings


def generate_finding_id(finding: Finding) -> str:
    fingerprint = "|".join(
        [
            finding.scanner_name,
            finding.category,
            finding.severity,
            finding.file_path,
            normalize_similarity_text(finding.title),
            str(finding.line_number or 0),
        ]
    )
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:12]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    deduplicated: list[Finding] = []
    for finding in findings:
        if any(findings_overlap(existing, finding) for existing in deduplicated):
            continue
        deduplicated.append(finding)
    return deduplicated


def findings_overlap(left: Finding, right: Finding) -> bool:
    if left.file_path != right.file_path:
        return False
    if left.severity != right.severity:
        return False
    return titles_are_similar(left.title, right.title)


def titles_are_similar(left_title: str, right_title: str) -> bool:
    normalized_left = normalize_similarity_text(left_title)
    normalized_right = normalize_similarity_text(right_title)
    if not normalized_left or not normalized_right:
        return False
    if normalized_left == normalized_right:
        return True
    if normalized_left in normalized_right or normalized_right in normalized_left:
        return True
    left_tokens = set(normalized_left.split())
    right_tokens = set(normalized_right.split())
    if not left_tokens or not right_tokens:
        return False
    overlap_ratio = len(left_tokens & right_tokens) / min(len(left_tokens), len(right_tokens))
    return overlap_ratio >= 0.6


def normalize_similarity_text(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return re.sub(r"\s+", " ", normalized)


def calculate_severity_summary(findings: list[Finding]) -> dict[str, int]:
    summary = {severity: 0 for severity in SEVERITY_LEVELS}
    for finding in findings:
        if finding.severity not in summary:
            summary[finding.severity] = 0
        summary[finding.severity] += 1
    return summary


def calculate_category_summary(findings: list[Finding]) -> dict[str, int]:
    counter = Counter(finding.category for finding in findings)
    return dict(sorted(counter.items()))


def calculate_scanner_summary(findings: list[Finding]) -> dict[str, int]:
    counter = Counter(finding.scanner_name for finding in findings)
    return dict(sorted(counter.items()))


def determine_overall_status(
    severity_summary: dict[str, int],
    fail_on: Severity = "high",
) -> OverallStatus:
    threshold_rank = SEVERITY_RANK.get(fail_on, SEVERITY_RANK["high"])
    if any(
        severity_summary.get(level, 0) > 0 and SEVERITY_RANK.get(level, len(SEVERITY_RANK)) <= threshold_rank
        for level in SEVERITY_LEVELS
    ):
        return "FAIL"
    if sum(severity_summary.values()) > 0:
        return "WARN"
    return "PASS"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_RANK.get(finding.severity, len(SEVERITY_RANK)),
            finding.file_path,
            normalize_similarity_text(finding.title),
            finding.scanner_name,
        ),
    )


def read_text_file(file_path: Path, max_bytes: int = 1_000_000) -> str:
    if file_path.stat().st_size > max_bytes:
        return ""
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
