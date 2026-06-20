"""Typer command-line interface for ghostmobile."""

from __future__ import annotations

import logging
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .analyzer import analyze
from .checks import all_checks
from .models import Severity
from .package import PackageError

app = typer.Typer(
    add_completion=False,
    help="Static security analyzer for Android APK and iOS IPA packages (authorized review only).",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


class SeverityChoice(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


@app.command(name="analyze")
def analyze_cmd(
    app_path: Path = typer.Argument(
        ..., metavar="APP", help="Path to a .apk or .ipa package to analyze."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.console, "--format", "-f", help="Output format."
    ),
    min_severity: SeverityChoice = typer.Option(
        SeverityChoice.info, "--min-severity", help="Hide findings below this severity."
    ),
    fail_on: SeverityChoice | None = typer.Option(
        None, "--fail-on", help="Exit non-zero if any finding is at or above this severity."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write report to a file instead of stdout."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging to stderr."),
) -> None:
    """Analyze a mobile package (APK or IPA autodetected). Static only, never executes the app."""
    _configure_logging(verbose)

    try:
        result = analyze(app_path)
    except PackageError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # unexpected, surface cleanly
        err_console.print(f"[bold red]unexpected error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    threshold = Severity.from_name(min_severity.value)
    result.findings = [f for f in result.findings if f.severity >= threshold]

    from . import report as report_mod

    rendered = report_mod.render(result, output_format.value, console=console)

    if rendered is not None:
        if output:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"[green]wrote {output_format.value} report to {output}[/green]")
        else:
            # Emit machine formats verbatim; avoid rich soft-wrapping the payload.
            sys.stdout.write(rendered + "\n")
    elif output:
        # console format requested with --output: capture plain text.
        file_console = Console(file=output.open("w", encoding="utf-8"), force_terminal=False)
        report_mod.render_console(result, file_console)
        console.print(f"[green]wrote console report to {output}[/green]")

    if fail_on is not None:
        fail_threshold = Severity.from_name(fail_on.value)
        max_sev = result.max_severity()
        if max_sev is not None and max_sev >= fail_threshold:
            raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@app.command()
def checks(
    output_format: OutputFormat = typer.Option(
        OutputFormat.console, "--format", "-f", help="console or json."
    ),
) -> None:
    """List all available checks grouped by platform."""
    items = all_checks()
    if output_format == OutputFormat.json:
        import json

        payload = [
            {
                "id": c.id,
                "platform": c.platform.value,
                "title": c.title,
                "description": c.description,
            }
            for c in items
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return

    table = Table(title=f"ghostmobile checks ({len(items)})")
    table.add_column("ID", no_wrap=True)
    table.add_column("Platform", no_wrap=True)
    table.add_column("Title")
    for c in items:
        table.add_row(c.id, c.platform.value, c.title)
    console.print(table)


@app.command()
def version() -> None:
    """Print the ghostmobile version."""
    console.print(f"ghostmobile {__version__}")


def main() -> None:  # pragma: no cover - thin wrapper
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
