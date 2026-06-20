"""Programmatic builders for SAFE, crafted sample packages.

Nothing here is a real proprietary app. We synthesize minimal APK and IPA
zip archives in memory or on disk, including a hand-encoded binary
AndroidManifest.xml and a binary Info.plist, so the analyzer and its checks
can be exercised without shipping third-party binaries.
"""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

from ghostmobile.axml_encode import EncAttr, EncElement, encode


def _vulnerable_manifest_tree() -> EncElement:
    return EncElement(
        "manifest",
        attributes=[
            EncAttr("package", "com.ghostmobile.vuln", namespace=""),
            EncAttr("versionName", "1.0", value_type=None),
            EncAttr("versionCode", 1),
        ],
        children=[
            EncElement(
                "uses-sdk",
                attributes=[
                    EncAttr("minSdkVersion", 19),
                    EncAttr("targetSdkVersion", 33),
                ],
            ),
            EncElement(
                "uses-permission",
                attributes=[EncAttr("name", "android.permission.READ_SMS")],
            ),
            EncElement(
                "uses-permission",
                attributes=[EncAttr("name", "android.permission.INTERNET")],
            ),
            EncElement(
                "permission",
                attributes=[
                    EncAttr("name", "com.ghostmobile.vuln.CUSTOM"),
                    EncAttr("protectionLevel", "normal", value_type=None),
                ],
            ),
            EncElement(
                "application",
                attributes=[
                    EncAttr("label", "VulnApp"),
                    EncAttr("debuggable", True),
                    EncAttr("allowBackup", True),
                    EncAttr("usesCleartextTraffic", True),
                ],
                children=[
                    EncElement(
                        "activity",
                        attributes=[
                            EncAttr("name", ".MainActivity"),
                            EncAttr("exported", True),
                        ],
                    ),
                    EncElement(
                        "provider",
                        attributes=[
                            EncAttr("name", ".LeakyProvider"),
                            EncAttr("exported", True),
                        ],
                    ),
                ],
            ),
        ],
    )


def _clean_manifest_tree() -> EncElement:
    return EncElement(
        "manifest",
        attributes=[
            EncAttr("package", "com.ghostmobile.clean", namespace=""),
            EncAttr("versionName", "2.0", value_type=None),
            EncAttr("versionCode", 2),
        ],
        children=[
            EncElement(
                "uses-sdk",
                attributes=[
                    EncAttr("minSdkVersion", 29),
                    EncAttr("targetSdkVersion", 34),
                ],
            ),
            EncElement(
                "permission",
                attributes=[
                    EncAttr("name", "com.ghostmobile.clean.SIGNED"),
                    EncAttr("protectionLevel", "signature", value_type=None),
                ],
            ),
            EncElement(
                "application",
                attributes=[
                    EncAttr("label", "CleanApp"),
                    EncAttr("debuggable", False),
                    EncAttr("allowBackup", False),
                    EncAttr("usesCleartextTraffic", False),
                ],
                children=[
                    EncElement(
                        "activity",
                        attributes=[
                            EncAttr("name", ".MainActivity"),
                            EncAttr("exported", False),
                        ],
                    ),
                ],
            ),
        ],
    )


def encode_vulnerable_manifest() -> bytes:
    return encode(_vulnerable_manifest_tree())


def encode_clean_manifest() -> bytes:
    return encode(_clean_manifest_tree())


def _add_fake_signature(zf: zipfile.ZipFile) -> None:
    zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    zf.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
    zf.writestr("META-INF/CERT.RSA", b"\x30\x82\x00\x00fake-pkcs7-signature-block")


def build_vulnerable_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", encode_vulnerable_manifest())
        # A bundled resource that contains a hardcoded secret.
        zf.writestr(
            "res/values/strings.xml",
            '<resources><string name="api">AKIAZ7QWERTYUIOPLKJH</string>'
            '<string name="g">AIzaSyB1z9Qw3rTyUiOpLkJhGfDsAzXcVbNmQwE</string></resources>',
        )
        zf.writestr("assets/config.json", '{"note": "no secret here"}')
        _add_fake_signature(zf)
    return path


def build_clean_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", encode_clean_manifest())
        zf.writestr(
            "res/values/strings.xml",
            '<resources><string name="app_name">CleanApp</string></resources>',
        )
        _add_fake_signature(zf)
    return path


def _vulnerable_info_plist() -> dict:
    return {
        "CFBundleIdentifier": "com.ghostmobile.vuln",
        "CFBundleName": "VulnApp",
        "CFBundleExecutable": "VulnApp",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
        "MinimumOSVersion": "12.0",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {
                "legacy.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}
            },
        },
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["vulnapp", "ghostmobile"]}],
        "NSCameraUsageDescription": "We need the camera for scanning.",
        "NSLocationWhenInUseUsageDescription": "We use location for maps.",
    }


def _clean_info_plist() -> dict:
    return {
        "CFBundleIdentifier": "com.ghostmobile.clean",
        "CFBundleName": "CleanApp",
        "CFBundleExecutable": "CleanApp",
        "CFBundleShortVersionString": "2.0",
        "CFBundleVersion": "2",
        "MinimumOSVersion": "16.0",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False},
    }


def build_vulnerable_ipa(path: Path) -> Path:
    app = "Payload/VulnApp.app"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{app}/Info.plist", plistlib.dumps(_vulnerable_info_plist(), fmt=plistlib.FMT_BINARY))
        # Fake "binary" carrying an embedded secret string.
        zf.writestr(
            f"{app}/VulnApp",
            b"\xca\xfe\xba\xbe MachO-ish header sk_live_0123456789abcdef0123 tail",
        )
        zf.writestr(f"{app}/embedded.mobileprovision", _fake_mobileprovision())
    return path


def build_clean_ipa(path: Path) -> Path:
    app = "Payload/CleanApp.app"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{app}/Info.plist", plistlib.dumps(_clean_info_plist(), fmt=plistlib.FMT_XML))
        zf.writestr(f"{app}/CleanApp", b"\xca\xfe\xba\xbe clean binary, nothing to see")
    return path


def _fake_mobileprovision() -> bytes:
    entitlements = {
        "Entitlements": {
            "application-identifier": "ABCDE12345.com.ghostmobile.*",
            "get-task-allow": True,
        }
    }
    plist = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
    # Wrap in a CMS-like preamble/trailer so the best-effort extractor must
    # locate the embedded plist span, mirroring real .mobileprovision files.
    return b"\x30\x82\x10\x00FAKE-PKCS7-PREAMBLE\x00" + plist + b"\x00TRAILER-BYTES"


def build_corrupt_archive(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04 this is not actually a valid zip central directory")
    return path


def build_non_package_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", "just a zip, not a mobile package")
    return path
