"""Output formatters: console table, JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table

from . import __version__
from .models import AnalysisResult, Finding, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

# SARIF maps severity onto level and a numeric security-severity (0-10).
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SARIF_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def render_console(result: AnalysisResult, console: Console | None = None) -> None:
    console = console or Console()
    console.print(
        f"[bold]ghostmobile[/bold] {__version__}  target=[cyan]{result.target}[/cyan]  "
        f"platform=[magenta]{result.platform.value}[/magenta]"
    )
    if result.package_name:
        console.print(f"package: [green]{result.package_name}[/green]")

    findings = result.sorted_findings()
    if not findings:
        console.print("[green]No findings.[/green]")
    else:
        table = Table(title=f"Findings ({len(findings)})", show_lines=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Title")
        table.add_column("Location", overflow="fold")
        for f in findings:
            style = _SEVERITY_STYLE.get(f.severity, "")
            table.add_row(
                f"[{style}]{f.severity.label}[/{style}]" if style else f.severity.label,
                f.id,
                f.title,
                f.location or "-",
            )
        console.print(table)

    if result.errors:
        console.print("[yellow]Check errors:[/yellow]")
        for err in result.errors:
            console.print(f"  - {err}")


def render_json(result: AnalysisResult) -> str:
    payload = {
        "tool": "ghostmobile",
        "version": __version__,
        **result.to_dict(),
        "summary": _summary(result),
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _summary(result: AnalysisResult) -> dict[str, int]:
    counts = dict.fromkeys((s.label for s in Severity), 0)
    for f in result.findings:
        counts[f.severity.label] += 1
    counts["total"] = len(result.findings)
    return counts


def render_sarif(result: AnalysisResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for f in result.sorted_findings():
        if f.id not in rules:
            rules[f.id] = _sarif_rule(f)
        sarif_results.append(_sarif_result(f))

    run = {
        "tool": {
            "driver": {
                "name": "ghostmobile",
                "informationUri": "https://github.com/joemunene-by/ghostmobile",
                "version": __version__,
                "rules": list(rules.values()),
            }
        },
        "results": sarif_results,
        "properties": {"platform": result.platform.value, "target": result.target},
    }
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }
    return json.dumps(doc, indent=2)


def _sarif_rule(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "name": "".join(part.capitalize() for part in f.id.replace("-", " ").split()),
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.description},
        "help": {"text": f.remediation},
        "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
        "properties": {
            "platform": f.platform.value,
            "security-severity": _SARIF_SECURITY_SEVERITY[f.severity],
            "tags": ["security", f.platform.value],
        },
    }


def _sarif_result(f: Finding) -> dict[str, Any]:
    location_uri = (f.location or "package").split(" ")[0]
    return {
        "ruleId": f.id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title}. {f.description}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location_uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "severity": f.severity.label,
            "evidence": f.evidence,
            "remediation": f.remediation,
        },
    }


def render(result: AnalysisResult, fmt: str, console: Console | None = None) -> str | None:
    """Render in the requested format. Console writes directly and returns None."""
    if fmt == "console":
        render_console(result, console)
        return None
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    raise ValueError(f"unknown format: {fmt}")
