from __future__ import annotations

from collections import Counter
from pathlib import Path

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


def validate_target_path(target_path: Path) -> Path:
    resolved_target = target_path.resolve()
    if not resolved_target.exists():
        raise FileNotFoundError(f"Target path does not exist: {resolved_target}")
    return resolved_target


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def count_files_by_extension(target_path: Path) -> dict[str, int]:
    counter: Counter[str] = Counter()

    if target_path.is_file():
        extension = target_path.suffix.lower() or "<no_extension>"
        counter[extension] += 1
        return dict(counter)

    def walk(path: Path) -> None:
        for child_path in path.iterdir():
            if child_path.is_dir():
                if child_path.name in DEFAULT_EXCLUDED_DIRECTORIES:
                    continue
                walk(child_path)
                continue

            extension = child_path.suffix.lower() or "<no_extension>"
            counter[extension] += 1

    walk(target_path)

    return dict(sorted(counter.items()))
