"""Tests for JSON and SARIF reporters."""

from __future__ import annotations

import json
from pathlib import Path

from ghostmobile.analyzer import analyze
from ghostmobile.report import render_json, render_sarif


def test_json_round_trip(vuln_apk: Path):
    result = analyze(vuln_apk)
    text = render_json(result)
    data = json.loads(text)
    assert data["tool"] == "ghostmobile"
    assert data["platform"] == "android"
    assert data["package_name"] == "com.ghostmobile.vuln"
    assert data["summary"]["total"] == len(result.findings)
    assert isinstance(data["findings"], list)
    # Findings are severity-sorted descending.
    sevs = [f["severity"] for f in data["findings"]]
    assert sevs == sorted(sevs, key=_sev_rank)


def _sev_rank(label: str) -> int:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return order[label]


def test_sarif_is_valid_2_1_0(vuln_ipa: Path):
    result = analyze(vuln_ipa)
    doc = json.loads(render_sarif(result))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ghostmobile"
    assert driver["rules"]
    rule_ids = {r["id"] for r in driver["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"error", "warning", "note"}
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_security_severity_present(vuln_apk: Path):
    result = analyze(vuln_apk)
    doc = json.loads(render_sarif(result))
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]
