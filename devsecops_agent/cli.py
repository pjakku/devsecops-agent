from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from devsecops_agent import __version__
from devsecops_agent.config import initialize_config
from devsecops_agent.scanner_runner import run_scan
from devsecops_agent.utils import SEVERITY_LEVELS

app = typer.Typer(
    help="DevSecOps scanning CLI.",
    no_args_is_help=True,
    add_completion=False,
)
config_app = typer.Typer(help="Configuration commands.")
app.add_typer(config_app, name="config")


@app.command()
def scan(
    target_path: Path,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", case_sensitive=False, help="Severity threshold that marks the scan as FAIL."),
    ] = "high",
    json_out: Annotated[
        Path,
        typer.Option("--json-out", help="Write the JSON report to this path."),
    ] = Path("reports/scan-report.json"),
    no_semgrep: Annotated[
        bool,
        typer.Option("--no-semgrep", help="Skip Semgrep even if it is installed."),
    ] = False,
) -> None:
    """Scan a target path and write a local report."""
    normalized_fail_on = fail_on.lower()
    if normalized_fail_on not in SEVERITY_LEVELS:
        allowed_values = ", ".join(SEVERITY_LEVELS)
        typer.echo(f"Error: --fail-on must be one of: {allowed_values}", err=True)
        raise typer.Exit(code=2)

    result = run_scan(
        target_path,
        fail_on=normalized_fail_on,
        json_output_path=json_out,
        include_semgrep=not no_semgrep,
    )
    report = result.report

    typer.echo("DevSecOps Agent Scan Summary")
    typer.echo(f"Target: {report.target_path}")
    typer.echo(f"Total files: {report.total_files}")
    typer.echo(f"Total findings: {report.total_findings}")
    typer.echo(f"Fail threshold: {report.fail_on}")
    typer.echo(f"Scanner modules run: {', '.join(report.scanners_run)}")
    typer.echo("Scanner execution:")
    for execution in report.scanner_executions:
        configs_display = ", ".join(execution.configs_used) if execution.configs_used else "n/a"
        details = (
            f"{execution.scanner_name}: {execution.status} "
            f"({execution.findings_count} findings, configs=[{configs_display}])"
        )
        if execution.message:
            details = f"{details} - {execution.message}"
        typer.echo(f"  {details}")
        if execution.command:
            typer.echo(f"    command: {execution.command}")
        if execution.stderr:
            typer.echo(f"    stderr: {execution.stderr}")

    typer.echo("Severity totals:")
    for severity, count in report.severity_summary.items():
        typer.echo(f"  {severity}: {count}")

    typer.echo("Findings by scanner:")
    if report.scanner_summary:
        for scanner_name, count in report.scanner_summary.items():
            typer.echo(f"  {scanner_name}: {count}")
    else:
        typer.echo("  <none>")

    typer.echo("Findings by category:")
    if report.category_summary:
        for category, count in report.category_summary.items():
            typer.echo(f"  {category}: {count}")
    else:
        typer.echo("  <none>")

    typer.echo(f"Overall status: {report.overall_status}")
    typer.echo(f"Report written to: {result.report_path}")

    typer.echo("Top findings:")
    if report.findings:
        for finding in report.findings[:10]:
            typer.echo(f"  [{finding.severity}] {finding.scanner_name} | {finding.title} | {finding.file_path}")
    else:
        typer.echo("  <none>")


@app.command()
def version() -> None:
    """Print the current version."""
    typer.echo(__version__)


@config_app.command("init")
def config_init(output: Path = Path("configs/default-config.yaml")) -> None:
    """Create the default YAML configuration file."""
    created_path = initialize_config(output)
    typer.echo(f"Config written to: {created_path}")


def run() -> None:
    try:
        app()
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        typer.echo(f"Runtime error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    run()
