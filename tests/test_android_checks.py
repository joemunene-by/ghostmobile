"""Tests for Android checks: each fires on vulnerable, silent on clean."""

from __future__ import annotations

from pathlib import Path

from ghostmobile.analyzer import analyze
from ghostmobile.models import Platform, Severity


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def test_vulnerable_apk_fires_expected_checks(vuln_apk: Path):
    result = analyze(vuln_apk)
    assert result.platform == Platform.ANDROID
    assert result.package_name == "com.ghostmobile.vuln"
    ids = _ids(result)
    assert "GM-AND-001" in ids  # debuggable
    assert "GM-AND-002" in ids  # allowBackup
    assert "GM-AND-003" in ids  # cleartext
    assert "GM-AND-004" in ids  # exported component
    assert "GM-AND-005" in ids  # dangerous permission (READ_SMS)
    assert "GM-AND-006" in ids  # weak custom permission
    assert "GM-AND-008" in ids  # hardcoded secret


def test_clean_apk_is_mostly_silent(clean_apk: Path):
    result = analyze(clean_apk)
    ids = _ids(result)
    assert "GM-AND-001" not in ids  # not debuggable
    assert "GM-AND-002" not in ids  # backup disabled
    assert "GM-AND-003" not in ids  # cleartext disabled
    assert "GM-AND-004" not in ids  # no exported components
    assert "GM-AND-005" not in ids  # no dangerous permissions
    assert "GM-AND-006" not in ids  # signature-level custom permission
    assert "GM-AND-008" not in ids  # no secrets


def test_signature_check_passes_with_fake_signature(clean_apk: Path):
    result = analyze(clean_apk)
    assert "GM-AND-007" not in _ids(result)


def test_exported_provider_is_high_severity(vuln_apk: Path):
    result = analyze(vuln_apk)
    provider_findings = [
        f for f in result.findings if f.id == "GM-AND-004" and "provider" in f.title.lower()
    ]
    assert provider_findings
    assert provider_findings[0].severity == Severity.HIGH


def test_secret_finding_is_redacted(vuln_apk: Path):
    result = analyze(vuln_apk)
    secrets = [f for f in result.findings if f.id == "GM-AND-008"]
    assert secrets
    for f in secrets:
        assert "AKIAZ7QWERTYUIOPLKJH" not in f.evidence
        assert "***" in f.evidence


def test_no_check_errors_on_valid_apk(vuln_apk: Path):
    result = analyze(vuln_apk)
    assert result.errors == []
