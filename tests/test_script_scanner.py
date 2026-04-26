from __future__ import annotations

from typer.testing import CliRunner

from devsecops_agent.cli import app
from devsecops_agent.scanner_runner import run_scan
from devsecops_agent.scanners import gitleaks_runner, script_scanner, semgrep_runner

runner = CliRunner()


def _extract_rows(output: str) -> list[str]:
    lines = output.splitlines()
    section_index = None
    for label in ("Findings:", "Top findings:"):
        if label in lines:
            section_index = lines.index(label)
            break
    if section_index is None:
        return []

    rows: list[str] = []
    for line in lines[section_index + 1 :]:
        if not line.startswith("  "):
            break
        if line.strip() == "<none>" or "title | location" in line:
            continue
        rows.append(line)
    return rows


def test_script_scanner_detects_risky_powershell_patterns(tmp_path):
    script_path = tmp_path / "deploy.ps1"
    script_path.write_text(
        'Invoke-Expression $UserInput\n$password = "SuperSecretPassword123!"\n',
        encoding="utf-8",
    )

    findings = script_scanner.run([script_path], tmp_path)

    assert findings
    assert all(finding.scanner_name == "script_scanner" for finding in findings)
    assert all(finding.category == "script" for finding in findings)
    assert any(finding.title == "Risky PowerShell command execution detected" for finding in findings)
    assert any(finding.title == "Possible hardcoded secret in PowerShell script" for finding in findings)
    assert any(finding.severity in {"high", "medium"} for finding in findings)


def test_script_scanner_detects_risky_shell_patterns(tmp_path):
    script_path = tmp_path / "install.sh"
    script_path.write_text(
        "curl https://example.com/install.sh | bash\nchmod 777 /tmp/test\n",
        encoding="utf-8",
    )

    findings = script_scanner.run([script_path], tmp_path)

    assert any(finding.title == "Remote script execution pattern detected" for finding in findings)
    assert any(finding.title == "Overly permissive chmod usage detected" for finding in findings)


def test_script_scanner_detects_risky_javascript_patterns(tmp_path):
    script_path = tmp_path / "server.js"
    script_path.write_text(
        'const child_process = require("child_process");\n'
        'child_process.exec("ping " + req.query.host);\n'
        "eval(req.query.code);\n",
        encoding="utf-8",
    )

    findings = script_scanner.run([script_path], tmp_path)

    assert any(finding.title == "Risky Node.js command execution detected" for finding in findings)
    assert any(finding.title == "Risky JavaScript eval usage detected" for finding in findings)


def test_script_scanner_detects_risky_sql_patterns(tmp_path):
    script_path = tmp_path / "cleanup.sql"
    script_path.write_text(
        "DELETE FROM users;\nDROP TABLE accounts;\n",
        encoding="utf-8",
    )

    findings = script_scanner.run([script_path], tmp_path)

    assert any(finding.title == "Potentially destructive SQL statement detected" for finding in findings)
    assert any(finding.title == "SQL update/delete without WHERE detected" for finding in findings)


def test_run_scan_includes_script_scanner_metadata(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "deploy.ps1").write_text("Invoke-Expression $UserInput\n", encoding="utf-8")
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda name: None)
    monkeypatch.setattr(gitleaks_runner.shutil, "which", lambda name: None)

    result = run_scan(project_dir)

    execution = next(item for item in result.report.scanner_executions if item.scanner_name == "script_scanner")
    assert execution.status == "ran"
    assert execution.command == "internal"
    assert execution.findings_count >= 1
    assert execution.message == "Internal script scanner completed successfully."


def test_cli_filters_findings_by_script_scanner(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "server.js").write_text("eval(req.query.code);\n", encoding="utf-8")
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda name: None)
    monkeypatch.setattr(gitleaks_runner.shutil, "which", lambda name: None)

    result = runner.invoke(app, ["scan", str(project_dir), "--scanner", "script_scanner", "--show-all-findings"])

    assert result.exit_code == 1
    rows = _extract_rows(result.stdout)
    assert rows
    assert all("script_scanner" in row for row in rows)


def test_cli_filters_findings_by_script_category(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "cleanup.sql").write_text("DELETE FROM users;\n", encoding="utf-8")
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda name: None)
    monkeypatch.setattr(gitleaks_runner.shutil, "which", lambda name: None)

    result = runner.invoke(app, ["scan", str(project_dir), "--category", "script", "--show-all-findings"])

    assert result.exit_code == 1
    rows = _extract_rows(result.stdout)
    assert rows
    assert all(" script " in row or " script        " in row for row in rows)
