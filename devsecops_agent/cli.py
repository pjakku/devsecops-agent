from __future__ import annotations

from pathlib import Path
from typing import Annotated

import click
import typer

from devsecops_agent import __version__
from devsecops_agent.config import initialize_config
from devsecops_agent.models import Finding
from devsecops_agent.report_writer import write_sarif_report
from devsecops_agent.scanner_runner import run_scan
from devsecops_agent.utils import SEVERITY_LEVELS, sort_findings

SUCCESS_EXIT_CODE = 0
THRESHOLD_VIOLATION_EXIT_CODE = 1
RUNTIME_ERROR_EXIT_CODE = 2
INVALID_USAGE_EXIT_CODE = 3
DEFAULT_MAX_FINDINGS = 10
TERMINAL_TITLE_WIDTH = 72
FINDING_ID_WIDTH = 12
SEVERITY_WIDTH = 8
SCANNER_WIDTH = 18
CATEGORY_WIDTH = 14

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
    summary_only: Annotated[
        bool,
        typer.Option("--summary-only", help="Print only the high-level summary."),
    ] = False,
    max_findings: Annotated[
        int,
        typer.Option("--max-findings", min=0, help="Maximum number of findings to show in terminal output."),
    ] = DEFAULT_MAX_FINDINGS,
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Write a SARIF report to this path."),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", case_sensitive=False, help="Show only findings at this severity in terminal output."),
    ] = None,
    scanner: Annotated[
        str | None,
        typer.Option("--scanner", help="Show only findings from this scanner in terminal output."),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option("--category", help="Show only findings from this category in terminal output."),
    ] = None,
    show_all_findings: Annotated[
        bool,
        typer.Option("--show-all-findings", help="Show all filtered findings in terminal output."),
    ] = False,
) -> None:
    """Scan a target path and write local reports."""
    normalized_fail_on = fail_on.lower()
    if normalized_fail_on not in SEVERITY_LEVELS:
        allowed_values = ", ".join(SEVERITY_LEVELS)
        typer.echo(f"Error: --fail-on must be one of: {allowed_values}", err=True)
        raise typer.Exit(code=INVALID_USAGE_EXIT_CODE)
    normalized_severity = severity.lower() if severity is not None else None
    if normalized_severity is not None and normalized_severity not in SEVERITY_LEVELS:
        allowed_values = ", ".join(SEVERITY_LEVELS)
        typer.echo(f"Error: --severity must be one of: {allowed_values}", err=True)
        raise typer.Exit(code=INVALID_USAGE_EXIT_CODE)
    try:
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
        for severity_name, count in report.severity_summary.items():
            typer.echo(f"  {severity_name}: {count}")

        typer.echo("Findings by scanner:")
        if report.scanner_summary:
            for scanner_name, count in report.scanner_summary.items():
                typer.echo(f"  {scanner_name}: {count}")
        else:
            typer.echo("  <none>")

        typer.echo("Findings by category:")
        if report.category_summary:
            for category_name, count in report.category_summary.items():
                typer.echo(f"  {category_name}: {count}")
        else:
            typer.echo("  <none>")

        typer.echo(f"Overall status: {report.overall_status}")
        typer.echo(f"Report written to: {result.report_path}")

        if sarif_out is not None:
            sarif_path = write_sarif_report(report, sarif_out)
            typer.echo(f"SARIF written to: {sarif_path}")

        terminal_findings = _select_terminal_findings(
            report.findings,
            severity=normalized_severity,
            scanner=scanner,
            category=category,
        )

        if not summary_only:
            findings_to_display = terminal_findings if show_all_findings else terminal_findings[:max_findings]
            section_title = "Findings:" if show_all_findings else "Top findings:"
            typer.echo(section_title)
            if findings_to_display:
                typer.echo(_format_finding_header())
                for finding in findings_to_display:
                    typer.echo(_format_finding_row(finding))
            else:
                typer.echo("  <none>")

        exit_code = SUCCESS_EXIT_CODE if report.overall_status != "FAIL" else THRESHOLD_VIOLATION_EXIT_CODE
        raise typer.Exit(code=exit_code)
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=INVALID_USAGE_EXIT_CODE) from exc
    except OSError as exc:
        typer.echo(f"Runtime error: {exc}", err=True)
        raise typer.Exit(code=RUNTIME_ERROR_EXIT_CODE) from exc
    except click.exceptions.Exit:
        raise
    except Exception as exc:
        typer.echo(f"Runtime error: {exc}", err=True)
        raise typer.Exit(code=RUNTIME_ERROR_EXIT_CODE) from exc


@app.command()
def version() -> None:
    """Print the current version."""
    typer.echo(__version__)


@config_app.command("init")
def config_init(output: Path = Path("configs/default-config.yaml")) -> None:
    """Create the default YAML configuration file."""
    created_path = initialize_config(output)
    typer.echo(f"Config written to: {created_path}")


def main(argv: list[str] | None = None) -> int:
    try:
        result = app(args=argv, standalone_mode=False)
        return result if isinstance(result, int) else SUCCESS_EXIT_CODE
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        return INVALID_USAGE_EXIT_CODE
    except (click.BadParameter, click.UsageError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        return INVALID_USAGE_EXIT_CODE
    except click.ClickException as exc:
        typer.echo(f"Error: {exc.format_message()}", err=True)
        return INVALID_USAGE_EXIT_CODE
    except click.exceptions.Exit as exc:
        return exc.exit_code
    except OSError as exc:
        typer.echo(f"Runtime error: {exc}", err=True)
        return RUNTIME_ERROR_EXIT_CODE
    except Exception as exc:
        typer.echo(f"Runtime error: {exc}", err=True)
        return RUNTIME_ERROR_EXIT_CODE


def run() -> None:
    raise SystemExit(main())


def _truncate_title(title: str, width: int = TERMINAL_TITLE_WIDTH) -> str:
    if len(title) <= width:
        return title
    return f"{title[: width - 3].rstrip()}..."


def _select_terminal_findings(
    findings: list[Finding],
    *,
    severity: str | None,
    scanner: str | None,
    category: str | None,
) -> list[Finding]:
    filtered = list(findings)
    if severity is not None:
        normalized_severity = severity.strip().lower()
        filtered = [finding for finding in filtered if finding.severity.strip().lower() == normalized_severity]
    if scanner is not None:
        normalized_scanner = scanner.strip().lower()
        filtered = [finding for finding in filtered if finding.scanner_name.strip().lower() == normalized_scanner]
    if category is not None:
        normalized_category = category.strip().lower()
        filtered = [finding for finding in filtered if finding.category.strip().lower() == normalized_category]
    return sort_findings(filtered)


def _format_finding_header() -> str:
    return (
        f"  {'id':<{FINDING_ID_WIDTH}} "
        f"{'severity':<{SEVERITY_WIDTH}} "
        f"{'scanner':<{SCANNER_WIDTH}} "
        f"{'category':<{CATEGORY_WIDTH}} "
        "title | location"
    )


def _format_finding_row(finding: Finding) -> str:
    title = _truncate_title(finding.title)
    location = finding.file_path
    if finding.line_number is not None:
        location = f"{location}:{finding.line_number}"
    return (
        f"  {finding.finding_id:<{FINDING_ID_WIDTH}} "
        f"{finding.severity:<{SEVERITY_WIDTH}} "
        f"{finding.scanner_name:<{SCANNER_WIDTH}} "
        f"{finding.category:<{CATEGORY_WIDTH}} "
        f"{title} | {location}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
