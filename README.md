# devsecops-agent

`devsecops-agent` is a Python CLI foundation for a future DevSecOps scanning tool. It provides a normalized internal scan workflow, optional Semgrep-based SAST scanning, optional Gitleaks-based secrets scanning, structured findings, JSON report output, and default configuration bootstrapping.

## Project Status

CLI V1 is complete and ready for local scanning and CI/CD integration.

## Author

Praveen Jakku

## Features

- `scan <target_path>` validates a target path, inspects project files, runs internal scanners, optionally runs Semgrep and Gitleaks when available, deduplicates overlapping findings, prints a summary, and writes a JSON report
- `version` prints the installed package version
- `config init` creates a starter YAML configuration file

## Requirements

- Python 3.11+

## Local setup

Create and activate a virtual environment, then install the project in editable mode:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## Packaging and installation

Editable install:

```bash
pip install -e ".[dev]"
```

Normal local install:

```bash
pip install .
```

Build wheel and sdist artifacts:

```bash
python -m build
```

Test install in a fresh virtual environment:

```bash
python -m venv .venv-test
.venv-test\Scripts\activate
pip install dist\devsecops_agent-1.1.0-py3-none-any.whl
devsecops-agent version
python -m devsecops_agent version
```

## Windows executable build

The CLI can be bundled as a standalone Windows console executable with PyInstaller. This is intended for the future VS Code extension backend so users can run the scanner without installing Python manually.

Install development dependencies:

```bash
pip install -e ".[dev]"
```

Build the executable:

```bash
pyinstaller packaging\pyinstaller\devsecops-agent-windows.spec --clean --noconfirm
```

Rebuild the executable after backend code changes; the frozen EXE includes the Semgrep resolver logic.

The executable is generated at:

```text
dist\devsecops-agent.exe
```

The file can later be copied into the VS Code extension backend:

```text
devsecops-agent-vscode\backend\devsecops-agent.exe
```

For production VS Code extension packaging, bundled Semgrep should be placed next to the backend executable. The preferred layout is:

```text
devsecops-agent-vscode\backend\devsecops-agent.exe
devsecops-agent-vscode\backend\semgrep\win\semgrep.exe
```

The same layout can be used directly from the local PyInstaller output folder:

```text
dist\devsecops-agent.exe
dist\semgrep\win\semgrep.exe
```

Verify the bundled executable:

```bash
dist\devsecops-agent.exe version
dist\devsecops-agent.exe config init
dist\devsecops-agent.exe scan .
```

Bundled Semgrep is the preferred production path. During development, if no bundled Semgrep executable is found next to `devsecops-agent.exe`, the agent falls back to discovering `semgrep` from `PATH`.

## Optional Semgrep setup

Semgrep is resolved from `semgrep\win\semgrep.exe` next to the packaged backend first, then from your system `PATH` as a development fallback. If it is not available, the CLI still runs and records Semgrep as skipped in the terminal summary and JSON report.

Install it locally with:

```bash
python -m pip install semgrep
```

For development fallback, make sure the `semgrep` executable is on `PATH` after installation.

This setup does not use `--config auto`. The default Semgrep config list is explicit and currently includes:

- `p/python` for Python-focused rules
- `p/java` for Java and Spring-oriented backend rules
- `p/javascript` for JavaScript and Node.js coverage
- `p/typescript` for TypeScript and React/frontend coverage
- `p/dockerfile` for Dockerfile checks
- `p/kubernetes` for Kubernetes-oriented manifest scanning

Use `--semgrep-config` one or more times to override the default list for a specific scan.

When running on Windows, the Semgrep subprocess is started with:

```text
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
```

Example explicit Semgrep invocation used by this project:

```bash
semgrep scan --json --quiet --config p/python --config p/java --config p/javascript --config p/typescript --config p/dockerfile --config p/kubernetes .
```

## Coverage overview

| Capability | Scanner |
| --- | --- |
| Python SAST | Semgrep |
| Java / Spring SAST | Semgrep |
| JavaScript / TypeScript / React / Node.js SAST | Semgrep |
| Dockerfile checks | Semgrep |
| Kubernetes checks | Semgrep + internal manifest scanner |
| PowerShell risky script checks | Internal script_scanner |
| Shell / Bash risky script checks | Internal script_scanner |
| Node.js risky backend patterns | Internal script_scanner |
| SQL risky query patterns | Internal script_scanner |
| Secrets scanning | Gitleaks + internal source scanner |
| Dependency file detection | Internal dependency scanner |

## Optional Gitleaks setup

`devsecops-agent` can optionally use Gitleaks for secrets detection. Gitleaks is executed as an external CLI tool, not imported as a Python package. If it is installed and available from a bundled backend location or on `PATH`, the agent will run it automatically during scans. If it is unavailable, the scan continues and Gitleaks is marked as skipped in scanner metadata.

`devsecops-agent` runs Gitleaks against the current file tree with `--no-git`, so normal folders and sample projects that are not Git repositories are still scanned correctly.

Bundled backends use the same sidecar pattern as Semgrep. On Windows, the preferred packaged layout is:

```text
devsecops-agent.exe
gitleaks\win\gitleaks.exe
```

Development fallback uses `gitleaks` from `PATH`.

Installation examples:

macOS:

```bash
brew install gitleaks
```

Windows:

```powershell
winget install gitleaks
```

Linux:

```bash
gitleaks version
```

Use the official Gitleaks release binary or your package manager where available.

Example invocation used by this project:

```bash
gitleaks detect --source . --report-format json --no-banner --no-git
```

## Run with `python -m`

```bash
python -m devsecops_agent scan .
python -m devsecops_agent version
python -m devsecops_agent config init
```

Additional scan examples:

```bash
python -m devsecops_agent scan . --fail-on medium
python -m devsecops_agent scan . --json-out artifacts\scan-report.json
python -m devsecops_agent scan . --no-semgrep
python -m devsecops_agent scan . --no-gitleaks
python -m devsecops_agent scan . --summary-only
python -m devsecops_agent scan . --max-findings 5
python -m devsecops_agent scan . --sarif-out artifacts\scan-results.sarif
python -m devsecops_agent scan . --severity high
python -m devsecops_agent scan . --scanner semgrep
python -m devsecops_agent scan . --semgrep-config p/java --scanner semgrep --show-all-findings
python -m devsecops_agent scan . --semgrep-config p/javascript --semgrep-config p/typescript --scanner semgrep --show-all-findings
python -m devsecops_agent scan . --semgrep-config p/dockerfile --semgrep-config p/kubernetes --scanner semgrep --show-all-findings
python -m devsecops_agent scan . --scanner script_scanner --show-all-findings
python -m devsecops_agent scan . --scanner gitleaks
python -m devsecops_agent scan . --category secrets
python -m devsecops_agent scan . --category script --show-all-findings
python -m devsecops_agent scan . --show-all-findings
```

## Run with the installed CLI

```bash
pip install -e ".[dev]"
devsecops-agent scan .
devsecops-agent version
devsecops-agent config init
```

CI-friendly examples:

```bash
devsecops-agent scan . --fail-on high
devsecops-agent scan . --fail-on medium --json-out reports\ci-scan.json
devsecops-agent scan . --no-semgrep
devsecops-agent scan . --no-gitleaks
devsecops-agent scan . --semgrep-config p/java --scanner semgrep --show-all-findings
devsecops-agent scan . --scanner script_scanner --show-all-findings
devsecops-agent scan . --summary-only --json-out reports\ci-scan.json --sarif-out reports\ci-scan.sarif
devsecops-agent scan . --severity high --scanner gitleaks
```

## Exit codes

- `0` = scan completed and did not violate the fail threshold
- `1` = scan completed and violated the fail threshold
- `2` = runtime or tool execution error
- `3` = invalid CLI usage or invalid target path

## Checking exit codes

PowerShell:

```powershell
devsecops-agent scan . --fail-on high
$LASTEXITCODE
```

`python -m devsecops_agent ...` returns the same process exit code.

Bash:

```bash
devsecops-agent scan . --fail-on high
echo $?
```

## Example output

```text
DevSecOps Agent Scan Summary
Target: C:\projects\sample-app
Total files: 12
Total findings: 3
Fail threshold: high
Scanner modules run: source_scanner, config_scanner, manifest_scanner, dependency_scanner
Scanner execution:
  source_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  config_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  manifest_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  dependency_scanner: ran (1 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  semgrep: skipped (0 findings, configs=[p/python, p/java, p/javascript, p/typescript, p/dockerfile, p/kubernetes]) - Semgrep not found. Checked bundled path C:\path\to\backend\semgrep\win\semgrep.exe and PATH; skipping external SAST scan.
  gitleaks: skipped (0 findings, configs=[n/a]) - Gitleaks not found. Checked bundled path C:\path\to\backend\gitleaks\win\gitleaks.exe and PATH; skipping external secrets scan.
Severity totals:
  critical: 0
  high: 0
  medium: 0
  low: 0
  info: 1
Findings by scanner:
  dependency_scanner: 1
Findings by category:
  dependency: 1
Overall status: WARN
Report written to: C:\projects\sample-app\reports\scan-report.json
Top findings:
  [info] dependency_scanner | Dependency manifest detected | package.json
```

## Example with Semgrep installed

```text
DevSecOps Agent Scan Summary
Target: C:\projects\sample-app
Total files: 12
Total findings: 4
Fail threshold: high
Scanner modules run: source_scanner, config_scanner, manifest_scanner, dependency_scanner, script_scanner, semgrep, gitleaks
Scanner execution:
  source_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  config_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  manifest_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  dependency_scanner: ran (1 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  script_scanner: ran (1 findings, configs=[n/a]) - Internal script scanner completed successfully.
    command: internal
  semgrep: ran (2 findings, configs=[p/python, p/java, p/javascript, p/typescript, p/dockerfile, p/kubernetes]) - Semgrep scan completed successfully.
    command: semgrep scan --json --quiet --config p/python --config p/java --config p/javascript --config p/typescript --config p/dockerfile --config p/kubernetes .
  gitleaks: ran (1 findings, configs=[n/a]) - Gitleaks scan completed successfully.
    command: gitleaks detect --source . --report-format json --report-path <temp> --no-banner --no-git
Severity totals:
  critical: 0
  high: 3
  medium: 1
  low: 0
  info: 1
Findings by scanner:
  dependency_scanner: 1
  gitleaks: 1
  semgrep: 2
  script_scanner: 1
  source_scanner: 1
Findings by category:
  dependency: 1
  sast: 2
  secrets: 2
  script: 1
Overall status: FAIL
Report written to: C:\projects\sample-app\reports\scan-report.json
Top findings:
  [high] source_scanner | Suspicious secrets-related filename detected | .env
  [high] script_scanner | Risky Node.js command execution detected | server.js
  [high] gitleaks | generic-api-key | .env
  [medium] semgrep | Unsafe subprocess usage | app.py
  [low] semgrep | Possible weak validation | app.py
  [info] dependency_scanner | Dependency manifest detected | package.json
```

## Example Semgrep failure output

```text
Scanner execution:
  semgrep: failed (0 findings, configs=[p/python, p/java, p/javascript, p/typescript, p/dockerfile, p/kubernetes]) - Failed to load config p/kubernetes
    command: semgrep scan --json --quiet --config p/python --config p/java --config p/javascript --config p/typescript --config p/dockerfile --config p/kubernetes .
    stderr: Failed to load config p/kubernetes
```

## Testing multi-language samples

To exercise the default Semgrep coverage, scan sample folders that contain:

- a Python file such as `app.py`
- a Java file such as `App.java`
- a JavaScript or TypeScript file such as `server.js` or `app.ts`
- a Dockerfile
- a Kubernetes manifest such as `deployment.yaml`

Run:

```bash
python -m devsecops_agent scan C:\path\to\sample-folder
```

Or after editable install:

```bash
devsecops-agent scan C:\path\to\sample-folder
```

Use `--json-out` if you want the report written somewhere specific, and `--no-semgrep` if you want to compare internal-only results against the combined scan output.

Use `--summary-only` to suppress top-finding details in terminal output while still writing the full JSON report. Use `--max-findings` to limit only the terminal display count. Use `--sarif-out` to generate a CI-friendly SARIF artifact alongside the JSON report.

Terminal filtering affects only what is printed. The full JSON report still contains every finding.

Filtering examples:

```bash
devsecops-agent scan . --severity high
devsecops-agent scan . --scanner semgrep
devsecops-agent scan . --semgrep-config p/java --scanner semgrep --show-all-findings
devsecops-agent scan . --semgrep-config p/javascript --semgrep-config p/typescript --scanner semgrep --show-all-findings
devsecops-agent scan . --semgrep-config p/dockerfile --semgrep-config p/kubernetes --scanner semgrep --show-all-findings
devsecops-agent scan . --scanner script_scanner --show-all-findings
devsecops-agent scan . --scanner gitleaks --show-all-findings
devsecops-agent scan . --category secrets --show-all-findings
devsecops-agent scan . --category script --show-all-findings
devsecops-agent scan . --severity medium --show-all-findings
```

## CI artifacts

Generate both JSON and SARIF outputs:

```bash
devsecops-agent scan . --json-out reports\scan-report.json --sarif-out reports\scan-report.sarif
```

## SARIF / GitHub Code Scanning

Generate a SARIF artifact locally:

```bash
devsecops-agent scan . --sarif-out reports\devsecops-agent.sarif
```

Generate JSON and SARIF together:

```bash
devsecops-agent scan . --json-out reports\scan-report.json --sarif-out reports\devsecops-agent.sarif
```

Example GitHub Actions workflow steps:

```yaml
- name: Run devsecops-agent
  run: devsecops-agent scan . --sarif-out reports/devsecops-agent.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/devsecops-agent.sarif
```

Example Jenkins PowerShell step:

```powershell
devsecops-agent scan . --fail-on high --json-out reports\scan-report.json --sarif-out reports\scan-report.sarif
if ($LASTEXITCODE -eq 1) { Write-Host "Security threshold violated"; exit 1 }
if ($LASTEXITCODE -ge 2) { Write-Host "Scan execution error"; exit $LASTEXITCODE }
```

Example Jenkins declarative pipeline step:

```groovy
stage('DevSecOps Scan') {
  steps {
    powershell '''
      devsecops-agent scan . --fail-on high --json-out reports\\scan-report.json --sarif-out reports\\scan-report.sarif
      if ($LASTEXITCODE -eq 1) { exit 1 }
      if ($LASTEXITCODE -ge 2) { exit $LASTEXITCODE }
    '''
  }
}
```

## Generated files

- `reports/scan-report.json`
- `configs/default-config.yaml`

## Testing

```bash
pytest
```

## Release checklist

- Update the package version in `pyproject.toml` and `devsecops_agent/__init__.py`
- Run `pytest`
- Build release artifacts with `python -m build`
- Test install the wheel in a fresh virtual environment
- Verify both `devsecops-agent version` and `python -m devsecops_agent version`

## Next planned integrations

- Jenkins integration
- VS Code wrapper
