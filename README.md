# devsecops-agent

`devsecops-agent` is a Python CLI foundation for a future DevSecOps scanning tool. It provides a normalized internal scan workflow with placeholder scanners, structured findings, JSON report output, and default configuration bootstrapping.

## Features

- `scan <target_path>` validates a target path, inspects project files, runs placeholder internal scanners, prints a summary, and writes a JSON report
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
Severity totals:
  critical: 0
  high: 1
  medium: 2
  low: 0
  info: 1
Overall status: FAIL
Report written to: C:\projects\sample-app\reports\scan-report.json
```

## Generated files

- `reports/scan-report.json`
- `configs/default-config.yaml`

## Testing

```bash
pytest
```
