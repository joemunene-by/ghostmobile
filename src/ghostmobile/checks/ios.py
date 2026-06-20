"""Built-in iOS (IPA) security checks."""

from __future__ import annotations

from ..models import Finding, Platform, Severity
from ..secrets import scan_bytes
from .base import Check, CheckContext, register

# Permission usage-description keys and the capability they gate.
_USAGE_KEYS: dict[str, str] = {
    "NSCameraUsageDescription": "camera",
    "NSMicrophoneUsageDescription": "microphone",
    "NSLocationWhenInUseUsageDescription": "location (in use)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "location (always)",
    "NSContactsUsageDescription": "contacts",
    "NSPhotoLibraryUsageDescription": "photo library",
    "NSCalendarsUsageDescription": "calendars",
    "NSBluetoothAlwaysUsageDescription": "bluetooth",
    "NSFaceIDUsageDescription": "Face ID",
}


@register
class ATSArbitraryLoadsCheck(Check):
    id = "GM-IOS-001"
    platform = Platform.IOS
    title = "App Transport Security disabled"
    description = "NSAllowsArbitraryLoads=true disables ATS and permits insecure HTTP."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.ipa:
            return []
        ats = ctx.ipa.info_plist.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
            return [
                Finding(
                    id=self.id,
                    platform=self.platform,
                    title=self.title,
                    severity=Severity.HIGH,
                    description=(
                        "NSAppTransportSecurity.NSAllowsArbitraryLoads is true, which turns off App "
                        "Transport Security globally and allows plaintext HTTP to any host."
                    ),
                    remediation=(
                        "Remove NSAllowsArbitraryLoads. If specific legacy hosts need exceptions, "
                        "scope them under NSExceptionDomains with the minimum relaxations required."
                    ),
                    location="Info.plist (NSAppTransportSecurity)",
                    evidence="NSAllowsArbitraryLoads=true",
                )
            ]
        return []


@register
class ATSExceptionDomainCheck(Check):
    id = "GM-IOS-002"
    platform = Platform.IOS
    title = "ATS exception domains allow insecure HTTP"
    description = "Per-domain NSExceptionAllowsInsecureHTTPLoads weakens transport security."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.ipa:
            return []
        ats = ctx.ipa.info_plist.get("NSAppTransportSecurity", {})
        if not isinstance(ats, dict):
            return []
        domains = ats.get("NSExceptionDomains", {})
        if not isinstance(domains, dict):
            return []
        insecure = [
            host
            for host, cfg in domains.items()
            if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True
        ]
        if not insecure:
            return []
        return [
            Finding(
                id=self.id,
                platform=self.platform,
                title=self.title,
                severity=Severity.MEDIUM,
                description=(
                    "These ATS exception domains allow insecure HTTP loads: "
                    + ", ".join(sorted(insecure))
                    + ". Traffic to them can be intercepted on hostile networks."
                ),
                remediation=(
                    "Remove the insecure exceptions and serve these hosts over HTTPS with modern TLS. "
                    "Keep any remaining exceptions as narrow as possible."
                ),
                location="Info.plist (NSExceptionDomains)",
                evidence=", ".join(sorted(insecure)),
                metadata={"domains": sorted(insecure)},
            )
        ]


@register
class URLSchemeCheck(Check):
    id = "GM-IOS-003"
    platform = Platform.IOS
    title = "Custom URL schemes registered"
    description = "Custom URL schemes can be a deep-link attack surface if inputs are trusted."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.ipa:
            return []
        url_types = ctx.ipa.info_plist.get("CFBundleURLTypes", [])
        schemes: list[str] = []
        if isinstance(url_types, list):
            for entry in url_types:
                if isinstance(entry, dict):
                    for s in entry.get("CFBundleURLSchemes", []) or []:
                        schemes.append(str(s))
        if not schemes:
            return []
        return [
            Finding(
                id=self.id,
                platform=self.platform,
                title=self.title,
                severity=Severity.LOW,
                description=(
                    "The app registers custom URL schemes: "
                    + ", ".join(sorted(set(schemes)))
                    + ". Other apps can invoke these; validate and authorize all inbound parameters."
                ),
                remediation=(
                    "Prefer Universal Links over custom schemes, validate every deep-link parameter, "
                    "and never perform sensitive actions from an unauthenticated deep link."
                ),
                location="Info.plist (CFBundleURLTypes)",
                evidence=", ".join(sorted(set(schemes))),
                metadata={"schemes": sorted(set(schemes))},
            )
        ]


@register
class MissingUsageDescriptionCheck(Check):
    id = "GM-IOS-004"
    platform = Platform.IOS
    title = "Sensitive entitlement without usage description context"
    description = "Reports declared privacy-sensitive usage descriptions for reviewer attention."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.ipa:
            return []
        present = {
            key: str(ctx.ipa.info_plist[key])
            for key in _USAGE_KEYS
            if key in ctx.ipa.info_plist
        }
        if not present:
            return []
        capabilities = ", ".join(sorted(_USAGE_KEYS[k] for k in present))
        return [
            Finding(
                id=self.id,
                platform=self.platform,
                title="Privacy-sensitive capabilities requested",
                severity=Severity.LOW,
                description=(
                    "The app declares usage descriptions for: "
                    + capabilities
                    + ". Confirm each capability is necessary and the description is accurate."
                ),
                remediation=(
                    "Request only the capabilities you use, and write user-facing purpose strings "
                    "that clearly explain why access is needed."
                ),
                location="Info.plist",
                evidence=capabilities,
                metadata={"capabilities": sorted(present.keys())},
            )
        ]


@register
class EntitlementsCheck(Check):
    id = "GM-IOS-005"
    platform = Platform.IOS
    title = "Risky entitlements in provisioning profile"
    description = "Flags get-task-allow (debuggable) and wildcard application identifiers."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.ipa or not ctx.ipa.entitlements:
            return []
        ent = ctx.ipa.entitlements
        findings: list[Finding] = []
        if ent.get("get-task-allow") is True:
            findings.append(
                Finding(
                    id=self.id,
                    platform=self.platform,
                    title="get-task-allow entitlement is enabled",
                    severity=Severity.HIGH,
                    description=(
                        "The embedded provisioning profile sets get-task-allow=true, meaning the "
                        "binary is debuggable and a debugger can attach to read process memory."
                    ),
                    remediation=(
                        "Ship release builds with a distribution profile where get-task-allow is "
                        "false. Development profiles must not be used for production distribution."
                    ),
                    location="embedded.mobileprovision (Entitlements)",
                    evidence="get-task-allow=true",
                )
            )
        app_id = str(ent.get("application-identifier", ""))
        if app_id.endswith(".*") or app_id.endswith("*"):
            findings.append(
                Finding(
                    id=self.id,
                    platform=self.platform,
                    title="Wildcard application identifier",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The application-identifier entitlement {app_id!r} uses a wildcard. "
                        "Wildcard App IDs cannot use entitlements like keychain sharing safely and "
                        "indicate a non-production profile."
                    ),
                    remediation=(
                        "Use an explicit App ID matching the bundle identifier for distribution."
                    ),
                    location="embedded.mobileprovision (Entitlements)",
                    evidence=f"application-identifier={app_id}",
                )
            )
        return findings


@register
class IosHardcodedSecretCheck(Check):
    id = "GM-IOS-006"
    platform = Platform.IOS
    title = "Hardcoded secret in bundle"
    description = "Scans the app binary and bundled resources for embedded secrets."

    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.ipa:
            return []
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for name, data in ctx.ipa.iter_scannable():
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
                            "Secrets shipped in the bundle can be recovered from the IPA."
                        ),
                        remediation=(
                            "Remove secrets from the bundle, rotate any exposed credential, and load "
                            "secrets at runtime from a secured backend using the iOS Keychain."
                        ),
                        location=name,
                        evidence=f"{match.kind}: {match.redacted}",
                        metadata={"kind": match.kind},
                    )
                )
        return findings
