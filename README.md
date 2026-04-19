# devsecops-agent

`devsecops-agent` is a Python CLI foundation for a future DevSecOps scanning tool. This first step focuses on clean packaging, a simple command surface, local scan summaries, JSON report output, and default configuration bootstrapping.

## Features

- `scan <target_path>` validates a target path, skips common cache and build directories, counts files by extension, prints a summary, and writes a JSON report
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
Unique extensions: 4

File counts by extension:
  .py: 5
  .md: 3
  .yaml: 2
  .json: 2

Report written to: reports\scan-report.json
```

## Generated files

- `reports/scan-report.json`
- `configs/default-config.yaml`

## Testing

```bash
pytest
```
