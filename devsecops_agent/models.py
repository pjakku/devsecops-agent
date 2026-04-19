from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class ScanSummary:
    target_path: str
    total_files: int
    file_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    target_path: str
    total_files: int
    file_counts: dict[str, int]
    report_path: str
