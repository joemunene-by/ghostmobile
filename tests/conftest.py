"""Shared pytest fixtures building crafted sample packages on disk."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import samples


@pytest.fixture
def vuln_apk(tmp_path: Path) -> Path:
    return samples.build_vulnerable_apk(tmp_path / "vuln.apk")


@pytest.fixture
def clean_apk(tmp_path: Path) -> Path:
    return samples.build_clean_apk(tmp_path / "clean.apk")


@pytest.fixture
def vuln_ipa(tmp_path: Path) -> Path:
    return samples.build_vulnerable_ipa(tmp_path / "vuln.ipa")


@pytest.fixture
def clean_ipa(tmp_path: Path) -> Path:
    return samples.build_clean_ipa(tmp_path / "clean.ipa")


@pytest.fixture
def corrupt_apk(tmp_path: Path) -> Path:
    return samples.build_corrupt_archive(tmp_path / "broken.apk")


@pytest.fixture
def non_package_zip(tmp_path: Path) -> Path:
    return samples.build_non_package_zip(tmp_path / "plain.zip")
