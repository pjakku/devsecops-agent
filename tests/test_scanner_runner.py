from __future__ import annotations

import json
from pathlib import Path

from devsecops_agent.scanner_runner import run_scan


def test_run_scan_writes_report(tmp_path, monkeypatch):
    sample_dir = tmp_path / "sample"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (sample_dir / "README.md").write_text("# sample\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    result = run_scan(sample_dir)

    assert result.total_files == 2
    assert result.file_counts[".py"] == 1
    assert result.file_counts[".md"] == 1

    report_path = Path.cwd() / "reports" / "scan-report.json"
    assert report_path.exists()

    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_data["total_files"] == 2


def test_run_scan_excludes_default_directories(tmp_path, monkeypatch):
    sample_dir = tmp_path / "sample"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('ok')\n", encoding="utf-8")

    excluded_dir = sample_dir / ".venv"
    excluded_dir.mkdir()
    (excluded_dir / "ignored.py").write_text("print('skip')\n", encoding="utf-8")

    node_modules_dir = sample_dir / "node_modules"
    node_modules_dir.mkdir()
    (node_modules_dir / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    result = run_scan(sample_dir)

    assert result.total_files == 1
    assert result.file_counts == {".py": 1}
