"""Built-in Android (APK) security checks."""

from __future__ import annotations

from ..manifest import weak_protection_levels
from ..models import Finding, Platform, Severity
from ..secrets import scan_bytes
from .base import Check, CheckContext, register


@register
class DebuggableCheck(Check):
    id = "GM-AND-001"
    platform = Platform.ANDROID
    title = "Application is debuggable"
    description = "android:debuggable=true exposes the app to runtime inspection and tampering."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.apk and ctx.apk.manifest.debuggable:
            return [
                Finding(
                    id=self.id,
                    platform=self.platform,
                    title=self.title,
                    severity=Severity.HIGH,
                    description=(
                        "The application manifest sets android:debuggable=true. Debug builds "
                        "allow attaching a debugger and reading process memory on any device."
                    ),
                    remediation=(
                        "Remove android:debuggable or set it to false in release builds. "
                        "Let the build system manage the debuggable flag per variant."
                    ),
                    location="AndroidManifest.xml (application)",
                    evidence="android:debuggable=true",
                )
            ]
        return []


@register
class AllowBackupCheck(Check):
    id = "GM-AND-002"
    platform = Platform.ANDROID
    title = "Application allows backup"
    description = "android:allowBackup=true can let app data be extracted via adb backup."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.apk and ctx.apk.manifest.allow_backup:
            return [
                Finding(
                    id=self.id,
                    platform=self.platform,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    description=(
                        "android:allowBackup defaults to true. Application private data can be "
                        "extracted and restored through adb backup on debuggable or rooted devices."
                    ),
                    remediation=(
                        "Set android:allowBackup=false unless backup is required, or define a "
                        "backup rules file (android:fullBackupContent) that excludes secrets."
                    ),
                    location="AndroidManifest.xml (application)",
                    evidence="android:allowBackup=true",
                )
            ]
        return []


@register
class CleartextTrafficCheck(Check):
    id = "GM-AND-003"
    platform = Platform.ANDROID
    title = "Cleartext network traffic permitted"
    description = "usesCleartextTraffic=true allows unencrypted HTTP, exposing data in transit."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.apk and ctx.apk.manifest.uses_cleartext_traffic is True:
            return [
                Finding(
                    id=self.id,
                    platform=self.platform,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    description=(
                        "android:usesCleartextTraffic=true permits plaintext HTTP connections, "
                        "which are vulnerable to interception and tampering on hostile networks."
                    ),
                    remediation=(
                        "Set usesCleartextTraffic=false and serve all endpoints over HTTPS. Use a "
                        "network security config to restrict cleartext to specific dev domains only."
                    ),
                    location="AndroidManifest.xml (application)",
                    evidence="android:usesCleartextTraffic=true",
                )
            ]
        return []


@register
class ExportedComponentCheck(Check):
    id = "GM-AND-004"
    platform = Platform.ANDROID
    title = "Exported component without permission"
    description = "Exported components reachable by other apps may expose unprotected entry points."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.apk:
            return []
        findings: list[Finding] = []
        for comp in ctx.apk.manifest.exported_components:
            if comp.permission:
                continue
            how = (
                "explicitly exported (android:exported=true)"
                if comp.explicitly_exported
                else "implicitly exported via intent-filter with no exported flag"
            )
            findings.append(
                Finding(
                    id=self.id,
                    platform=self.platform,
                    title=f"Exported {comp.kind} without permission: {comp.name}",
                    severity=Severity.HIGH if comp.kind == "provider" else Severity.MEDIUM,
                    description=(
                        f"The {comp.kind} {comp.name!r} is {how} and declares no android:permission. "
                        "Any installed app can invoke it, which may bypass intended access controls."
                    ),
                    remediation=(
                        "Set android:exported=false if the component is internal, or guard it with a "
                        "signature-level android:permission when cross-app access is intended."
                    ),
                    location=f"AndroidManifest.xml ({comp.kind} {comp.name})",
                    evidence=f"{comp.kind} exported, permission=none",
                    metadata={"component": comp.name, "kind": comp.kind},
                )
            )
        return findings


@register
class DangerousPermissionCheck(Check):
    id = "GM-AND-005"
    platform = Platform.ANDROID
    title = "Dangerous permissions requested"
    description = "The app requests runtime permissions classified as dangerous."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.apk:
            return []
        dangerous = ctx.apk.manifest.dangerous_permissions
        if not dangerous:
            return []
        return [
            Finding(
                id=self.id,
                platform=self.platform,
                title=self.title,
                severity=Severity.LOW,
                description=(
                    "The manifest requests dangerous permissions: "
                    + ", ".join(sorted(dangerous))
                    + ". Confirm each is justified and minimized for the app's function."
                ),
                remediation=(
                    "Request only the permissions you use, prefer scoped or one-time grants, and "
                    "document the purpose of each dangerous permission for review."
                ),
                location="AndroidManifest.xml (uses-permission)",
                evidence=", ".join(sorted(dangerous)),
                metadata={"permissions": sorted(dangerous)},
            )
        ]


@register
class WeakCustomPermissionCheck(Check):
    id = "GM-AND-006"
    platform = Platform.ANDROID
    title = "Custom permission with weak protection level"
    description = "Custom permissions at normal/dangerous level can be acquired by any app."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.apk:
            return []
        weak = weak_protection_levels()
        findings: list[Finding] = []
        for perm in ctx.apk.manifest.custom_permissions:
            level = perm.protection_level
            if level in weak:
                shown = level or "normal (default)"
                findings.append(
                    Finding(
                        id=self.id,
                        platform=self.platform,
                        title=f"Weak custom permission: {perm.name}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The custom permission {perm.name!r} uses protectionLevel {shown!r}. "
                            "Normal and dangerous permissions can be requested by any app, so they "
                            "do not restrict access to other applications meaningfully."
                        ),
                        remediation=(
                            "Use protectionLevel=signature (or signatureOrSystem) for permissions "
                            "that guard inter-app access so only apps signed by the same key qualify."
                        ),
                        location=f"AndroidManifest.xml (permission {perm.name})",
                        evidence=f"protectionLevel={shown}",
                        metadata={"permission": perm.name, "level": level},
                    )
                )
        return findings


@register
class MissingSignatureCheck(Check):
    id = "GM-AND-007"
    platform = Platform.ANDROID
    title = "APK signing scheme verification"
    description = "Checks for v1 (JAR) signature files and the v2 signing block."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.apk:
            return []
        if ctx.apk.has_v1_signature or ctx.apk.has_v2_signature_block:
            return []
        return [
            Finding(
                id=self.id,
                platform=self.platform,
                title="APK is unsigned or missing recognizable signatures",
                severity=Severity.HIGH,
                description=(
                    "No v1 JAR signature (META-INF/*.SF + *.RSA/.DSA/.EC) and no v2 APK Signing "
                    "Block were detected. Unsigned APKs cannot be installed and may have been "
                    "tampered with after signing."
                ),
                remediation=(
                    "Sign the APK with apksigner using at least the v2 scheme (v3/v4 recommended). "
                    "Verify with apksigner verify before distribution."
                ),
                location="META-INF/",
                evidence="no v1 or v2 signature detected",
            )
        ]


@register
class HardcodedSecretCheck(Check):
    id = "GM-AND-008"
    platform = Platform.ANDROID
    title = "Hardcoded secret in bundled resources"
    description = "Scans resources and assets for API keys, tokens, and private keys."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.apk:
            return []
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for name, data in ctx.apk.iter_scannable():
            for match in scan_bytes(data, name):
                key = (match.kind, match.redacted)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        id=self.id,
                        platform=self.platform,
                        title=f"Possible hardcoded secret: {match.kind}",
                        severity=Severity.HIGH,
                        description=(
                            f"A value matching {match.kind} was found embedded in {name}. "
                            "Secrets bundled into the package can be extracted by anyone with the APK."
                        ),
                        remediation=(
                            "Remove secrets from the package. Fetch credentials at runtime from a "
                            "secured backend, rotate any exposed key, and use the Android Keystore."
                        ),
                        location=name,
                        evidence=f"{match.kind}: {match.redacted}",
                        metadata={"kind": match.kind},
                    )
                )
        return findings
