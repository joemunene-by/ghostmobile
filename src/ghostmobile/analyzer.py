"""Analysis engine: load a package, run checks with per-check isolation."""

from __future__ import annotations

import logging
from pathlib import Path

from .checks import checks_for
from .checks.base import CheckContext
from .models import AnalysisResult, Platform
from .package import (
    PackageError,
    detect_platform,
    load_apk,
    load_ipa,
)

logger = logging.getLogger("ghostmobile")


def analyze(path: str | Path) -> AnalysisResult:
    """Analyze a single APK or IPA package and return findings.

    Raises :class:`PackageError` only for unrecoverable problems (file missing,
    not a package, manifest undecodable). Individual check failures are
    isolated and recorded in ``result.errors`` rather than aborting the run.
    """
    target = str(path)
    platform = detect_platform(path)
    logger.info("detected platform: %s", platform.value)

    if platform == Platform.ANDROID:
        return _analyze_apk(target)
    return _analyze_ipa(target)


def _analyze_apk(target: str) -> AnalysisResult:
    apk = load_apk(target)
    try:
        result = AnalysisResult(
            target=target,
            platform=Platform.ANDROID,
            package_name=apk.manifest.package,
            info={
                "package": apk.manifest.package,
                "min_sdk": apk.manifest.min_sdk,
                "target_sdk": apk.manifest.target_sdk,
                "version_name": apk.manifest.version_name,
                "version_code": apk.manifest.version_code,
                "permissions": list(apk.manifest.permissions),
                "components": len(apk.manifest.components),
                "exported_components": len(apk.manifest.exported_components),
                "v1_signature": apk.has_v1_signature,
                "v2_signature": apk.has_v2_signature_block,
            },
        )
        ctx = CheckContext(platform=Platform.ANDROID, apk=apk)
        _run_checks(result, Platform.ANDROID, ctx)
        return result
    finally:
        apk.close()


def _analyze_ipa(target: str) -> AnalysisResult:
    ipa = load_ipa(target)
    try:
        result = AnalysisResult(
            target=target,
            platform=Platform.IOS,
            package_name=ipa.bundle_id,
            info={
                "bundle_id": ipa.bundle_id,
                "version": ipa.version,
                "min_os": ipa.min_os,
                "binary": ipa.binary_name,
                "has_entitlements": bool(ipa.entitlements),
            },
        )
        ctx = CheckContext(platform=Platform.IOS, ipa=ipa)
        _run_checks(result, Platform.IOS, ctx)
        return result
    finally:
        ipa.close()


def _run_checks(result: AnalysisResult, platform: Platform, ctx: CheckContext) -> None:
    for check in checks_for(platform):
        try:
            findings = check.run(ctx)
        except Exception as exc:  # isolate a broken check from the rest
            logger.exception("check %s failed", check.id)
            result.errors.append(f"{check.id}: {exc}")
            continue
        for finding in findings:
            result.add(finding)


__all__ = ["analyze", "PackageError"]
