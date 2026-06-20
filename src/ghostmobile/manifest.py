"""Structured view of an AndroidManifest.xml parsed from AXML."""

from __future__ import annotations

from dataclasses import dataclass, field

from .axml import AXMLElement, parse

# Android permissions commonly classified as dangerous (protection level
# "dangerous"). Not exhaustive, but covers the high-signal ones.
DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    {
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.BODY_SENSORS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_MEDIA_LOCATION",
    }
)

_WEAK_PROTECTION_LEVELS: frozenset[str] = frozenset({"normal", "dangerous", ""})


@dataclass
class Component:
    kind: str  # activity, service, receiver, provider
    name: str
    exported: bool
    explicitly_exported: bool
    has_intent_filter: bool
    permission: str = ""

    @property
    def implicitly_exported(self) -> bool:
        return self.exported and not self.explicitly_exported


@dataclass
class CustomPermission:
    name: str
    protection_level: str


@dataclass
class Manifest:
    package: str = ""
    min_sdk: int | None = None
    target_sdk: int | None = None
    version_name: str = ""
    version_code: str = ""
    permissions: list[str] = field(default_factory=list)
    custom_permissions: list[CustomPermission] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool | None = None
    network_security_config: str = ""

    @property
    def dangerous_permissions(self) -> list[str]:
        return [p for p in self.permissions if p in DANGEROUS_PERMISSIONS]

    @property
    def exported_components(self) -> list[Component]:
        return [c for c in self.components if c.exported]


def _as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() == "true"


def _as_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _is_exported_default(kind: str, has_intent_filter: bool, explicit: bool | None) -> bool:
    if explicit is not None:
        return explicit
    # Implicit-export rule: a component with an intent-filter and no explicit
    # exported flag is exported. Providers historically defaulted to exported
    # below target SDK 17; we treat an explicit flag as authoritative and an
    # intent-filter as the implicit trigger otherwise.
    return has_intent_filter


def from_axml(root: AXMLElement) -> Manifest:
    manifest = Manifest()
    manifest.package = root.attr("package", "") or ""

    for uses_sdk in root.findall("uses-sdk"):
        manifest.min_sdk = _as_int(uses_sdk.attr("minSdkVersion"))
        manifest.target_sdk = _as_int(uses_sdk.attr("targetSdkVersion"))

    manifest.version_name = root.attr("versionName") or ""
    manifest.version_code = root.attr("versionCode") or ""

    for perm in root.findall("uses-permission"):
        name = perm.attr("name")
        if name:
            manifest.permissions.append(name)

    for perm in root.findall("permission"):
        name = perm.attr("name")
        if name:
            level = (perm.attr("protectionLevel") or "").lower()
            manifest.custom_permissions.append(CustomPermission(name=name, protection_level=level))

    for app in root.findall("application"):
        manifest.debuggable = _as_bool(app.attr("debuggable")) or False
        backup = _as_bool(app.attr("allowBackup"))
        manifest.allow_backup = True if backup is None else backup
        manifest.uses_cleartext_traffic = _as_bool(app.attr("usesCleartextTraffic"))
        manifest.network_security_config = app.attr("networkSecurityConfig") or ""

    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for comp in root.findall(kind):
            name = comp.attr("name") or ""
            explicit = _as_bool(comp.attr("exported"))
            has_filter = any(child.name == "intent-filter" for child in comp.children)
            exported = _is_exported_default(kind, has_filter, explicit)
            manifest.components.append(
                Component(
                    kind="activity" if kind == "activity-alias" else kind,
                    name=name,
                    exported=exported,
                    explicitly_exported=explicit is True,
                    has_intent_filter=has_filter,
                    permission=comp.attr("permission") or "",
                )
            )

    return manifest


def parse_manifest(buf: bytes) -> Manifest:
    """Parse raw AndroidManifest.xml bytes (binary AXML) into a Manifest."""
    root = parse(buf)
    return from_axml(root)


def weak_protection_levels() -> frozenset[str]:
    return _WEAK_PROTECTION_LEVELS
