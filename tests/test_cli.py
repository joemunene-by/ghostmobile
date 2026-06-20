"""End-to-end CLI tests via Typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ghostmobile.cli import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ghostmobile" in result.stdout


def test_checks_command_lists_checks():
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0
    assert "GM-AND-001" in result.stdout
    assert "GM-IOS-001" in result.stdout


def test_checks_command_json():
    result = runner.invoke(app, ["checks", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    ids = {c["id"] for c in data}
    assert "GM-AND-004" in ids
    assert "GM-IOS-005" in ids


def test_analyze_console_default(vuln_apk: Path):
    result = runner.invoke(app, ["analyze", str(vuln_apk)])
    assert result.exit_code == 0
    assert "Findings" in result.stdout
    assert "GM-AND-001" in result.stdout


def test_analyze_json_format(vuln_ipa: Path):
    result = runner.invoke(app, ["analyze", str(vuln_ipa), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["platform"] == "ios"


def test_analyze_fail_on_high_returns_nonzero(vuln_apk: Path):
    result = runner.invoke(app, ["analyze", str(vuln_apk), "--fail-on", "high"])
    assert result.exit_code == 1


def test_analyze_fail_on_critical_returns_zero_when_no_critical(vuln_apk: Path):
    # The vulnerable sample has High findings but no Critical, so fail-on
    # critical must not trip.
    result = runner.invoke(app, ["analyze", str(vuln_apk), "--fail-on", "critical"])
    assert result.exit_code == 0


def test_analyze_clean_apk_no_fail(clean_apk: Path):
    result = runner.invoke(app, ["analyze", str(clean_apk), "--fail-on", "high"])
    assert result.exit_code == 0


def test_analyze_min_severity_filters(vuln_apk: Path):
    result = runner.invoke(
        app, ["analyze", str(vuln_apk), "--format", "json", "--min-severity", "high"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    for f in data["findings"]:
        assert f["severity"] in {"High", "Critical"}


def test_analyze_output_file(vuln_apk: Path, tmp_path: Path):
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app, ["analyze", str(vuln_apk), "--format", "sarif", "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"


def test_analyze_corrupt_archive_exit_2(corrupt_apk: Path):
    result = runner.invoke(app, ["analyze", str(corrupt_apk)])
    assert result.exit_code == 2


def test_analyze_missing_file_exit_2():
    result = runner.invoke(app, ["analyze", "/nope/missing.apk"])
    assert result.exit_code == 2
