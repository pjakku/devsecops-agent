from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from devsecops_agent.models import Finding, OverallStatus, ProjectInspection

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


def calculate_severity_summary(findings: list[Finding]) -> dict[str, int]:
    summary = {severity: 0 for severity in SEVERITY_LEVELS}
    for finding in findings:
        if finding.severity not in summary:
            summary[finding.severity] = 0
        summary[finding.severity] += 1
    return summary


def determine_overall_status(severity_summary: dict[str, int]) -> OverallStatus:
    if severity_summary.get("critical", 0) > 0 or severity_summary.get("high", 0) > 0:
        return "FAIL"
    if any(severity_summary.get(level, 0) > 0 for level in ("medium", "low", "info")):
        return "WARN"
    return "PASS"


def read_text_file(file_path: Path, max_bytes: int = 1_000_000) -> str:
    if file_path.stat().st_size > max_bytes:
        return ""
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
