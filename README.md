# devsecops-agent

`devsecops-agent` is a Python CLI foundation for a future DevSecOps scanning tool. It provides a normalized internal scan workflow, optional Semgrep-based SAST scanning, structured findings, JSON report output, and default configuration bootstrapping.

## Features

- `scan <target_path>` validates a target path, inspects project files, runs internal scanners, optionally runs Semgrep when available, prints a summary, and writes a JSON report
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

## Optional Semgrep setup

Semgrep is optional and is discovered from your system `PATH`. If it is not available, the CLI still runs and records Semgrep as skipped in the terminal summary and JSON report.

Install it locally with:

```bash
python -m pip install semgrep
```

Make sure the `semgrep` executable is on `PATH` after installation.

This setup does not use `--config auto`. The default Semgrep config list is explicit and currently includes:

- `p/python` for Python-focused rules
- `p/kubernetes` for Kubernetes-oriented manifest scanning

Additional Semgrep configs can be added later in code and config.

When running on Windows, the Semgrep subprocess is started with:

```text
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
```

Example explicit Semgrep invocation used by this project:

```bash
semgrep scan --json --quiet --config p/python --config p/kubernetes .
```

## Run with `python -m`

```bash
python -m devsecops_agent scan .
python -m devsecops_agent version
python -m devsecops_agent config init
```

## Run with the installed CLI

```bash
pip install -e ".[dev]"
devsecops-agent scan .
devsecops-agent version
devsecops-agent config init
```

## Example output

```text
DevSecOps Agent Scan Summary
Target: C:\projects\sample-app
Total files: 12
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
  semgrep: skipped (0 findings, configs=[p/python, p/kubernetes]) - Semgrep not found on PATH; skipping external SAST scan.
Severity totals:
  critical: 0
  high: 0
  medium: 0
  low: 0
  info: 1
Overall status: WARN
Report written to: C:\projects\sample-app\reports\scan-report.json
```

## Example with Semgrep installed

```text
DevSecOps Agent Scan Summary
Target: C:\projects\sample-app
Total files: 12
Scanner modules run: source_scanner, config_scanner, manifest_scanner, dependency_scanner, semgrep
Scanner execution:
  source_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  config_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  manifest_scanner: ran (0 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  dependency_scanner: ran (1 findings, configs=[n/a]) - Internal placeholder scanner completed successfully.
    command: internal
  semgrep: ran (2 findings, configs=[p/python, p/kubernetes]) - Semgrep scan completed successfully.
    command: semgrep scan --json --quiet --config p/python --config p/kubernetes .
Severity totals:
  critical: 0
  high: 1
  medium: 1
  low: 0
  info: 1
Overall status: FAIL
Report written to: C:\projects\sample-app\reports\scan-report.json
```

## Example Semgrep failure output

```text
Scanner execution:
  semgrep: failed (0 findings, configs=[p/python, p/kubernetes]) - Failed to load config p/kubernetes
    command: semgrep scan --json --quiet --config p/python --config p/kubernetes .
    stderr: Failed to load config p/kubernetes
```

## Testing Python and Kubernetes samples

To exercise both default Semgrep configs, scan a sample folder that contains:

- a Python file such as `app.py`
- a Kubernetes manifest such as `deployment.yaml`

Run:

```bash
python -m devsecops_agent scan C:\path\to\sample-folder
```

Or after editable install:

```bash
devsecops-agent scan C:\path\to\sample-folder
```

## Generated files

- `reports/scan-report.json`
- `configs/default-config.yaml`

## Testing

```bash
pytest
```
