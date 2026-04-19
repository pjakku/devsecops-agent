from __future__ import annotations

from pathlib import Path

import typer

from devsecops_agent import __version__
from devsecops_agent.config import initialize_config
from devsecops_agent.scanner_runner import run_scan

app = typer.Typer(
    help="DevSecOps scanning CLI.",
    no_args_is_help=True,
    add_completion=False,
)
config_app = typer.Typer(help="Configuration commands.")
app.add_typer(config_app, name="config")


@app.command()
def scan(target_path: Path) -> None:
    """Scan a target path and write a local report."""
    result = run_scan(target_path)
    report = result.report

    typer.echo("DevSecOps Agent Scan Summary")
    typer.echo(f"Target: {report.target_path}")
    typer.echo(f"Total files: {report.total_files}")
    typer.echo(f"Scanner modules run: {', '.join(report.scanners_run)}")
    typer.echo("Severity totals:")
    for severity, count in report.severity_summary.items():
        typer.echo(f"  {severity}: {count}")
    typer.echo(f"Overall status: {report.overall_status}")
    typer.echo(f"Report written to: {result.report_path}")


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
