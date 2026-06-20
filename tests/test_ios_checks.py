"""Tests for iOS checks and Info.plist parsing."""

from __future__ import annotations

from pathlib import Path

from ghostmobile.analyzer import analyze
from ghostmobile.models import Platform


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def test_vulnerable_ipa_fires_expected_checks(vuln_ipa: Path):
    result = analyze(vuln_ipa)
    assert result.platform == Platform.IOS
    assert result.package_name == "com.ghostmobile.vuln"
    ids = _ids(result)
    assert "GM-IOS-001" in ids  # arbitrary loads
    assert "GM-IOS-002" in ids  # exception domain insecure
    assert "GM-IOS-003" in ids  # url schemes
    assert "GM-IOS-004" in ids  # usage descriptions
    assert "GM-IOS-005" in ids  # risky entitlements
    assert "GM-IOS-006" in ids  # hardcoded secret in binary


def test_clean_ipa_is_silent(clean_ipa: Path):
    result = analyze(clean_ipa)
    ids = _ids(result)
    assert "GM-IOS-001" not in ids
    assert "GM-IOS-002" not in ids
    assert "GM-IOS-003" not in ids
    assert "GM-IOS-005" not in ids
    assert "GM-IOS-006" not in ids


def test_info_plist_metadata_parsed(vuln_ipa: Path):
    result = analyze(vuln_ipa)
    assert result.info["bundle_id"] == "com.ghostmobile.vuln"
    assert result.info["version"] == "1.0"
    assert result.info["min_os"] == "12.0"


def test_entitlements_flag_get_task_allow(vuln_ipa: Path):
    result = analyze(vuln_ipa)
    ent = [f for f in result.findings if f.id == "GM-IOS-005"]
    titles = " ".join(f.title for f in ent)
    assert "get-task-allow" in titles
    assert "Wildcard" in titles


def test_clean_ipa_xml_plist_parses(clean_ipa: Path):
    result = analyze(clean_ipa)
    assert result.info["bundle_id"] == "com.ghostmobile.clean"
    assert result.info["min_os"] == "16.0"
