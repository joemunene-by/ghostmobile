"""Tests for archive detection and error handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghostmobile.models import Platform
from ghostmobile.package import PackageError, detect_platform, load_apk, load_ipa


def test_detect_apk_by_extension(vuln_apk: Path):
    assert detect_platform(vuln_apk) == Platform.ANDROID


def test_detect_ipa_by_extension(vuln_ipa: Path):
    assert detect_platform(vuln_ipa) == Platform.IOS


def test_detect_apk_by_content(vuln_apk: Path, tmp_path: Path):
    renamed = tmp_path / "mystery.bin"
    renamed.write_bytes(vuln_apk.read_bytes())
    assert detect_platform(renamed) == Platform.ANDROID


def test_detect_ipa_by_content(vuln_ipa: Path, tmp_path: Path):
    renamed = tmp_path / "mystery.bin"
    renamed.write_bytes(vuln_ipa.read_bytes())
    assert detect_platform(renamed) == Platform.IOS


def test_missing_file_raises():
    with pytest.raises(PackageError):
        detect_platform("/nonexistent/path/app.apk")


def test_corrupt_archive_raises(corrupt_apk: Path):
    with pytest.raises(PackageError):
        load_apk(corrupt_apk)


def test_non_package_zip_raises(non_package_zip: Path):
    with pytest.raises(PackageError):
        detect_platform(non_package_zip)


def test_apk_loads_manifest_metadata(vuln_apk: Path):
    apk = load_apk(vuln_apk)
    try:
        assert apk.manifest.package == "com.ghostmobile.vuln"
        assert apk.manifest.debuggable is True
        assert apk.has_v1_signature is True
    finally:
        apk.close()


def test_ipa_loads_bundle_metadata(vuln_ipa: Path):
    ipa = load_ipa(vuln_ipa)
    try:
        assert ipa.bundle_id == "com.ghostmobile.vuln"
        assert ipa.binary_name == "VulnApp"
        assert ipa.entitlements.get("get-task-allow") is True
    finally:
        ipa.close()
