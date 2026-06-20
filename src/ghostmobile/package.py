"""Archive handling for APK and IPA packages.

Both formats are ZIP archives. We never execute anything: we only read
entries. The loaders detect the platform, expose convenient accessors for
the entries the checks need, and guard against corrupt or oversized
archives.
"""

from __future__ import annotations

import plistlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .manifest import Manifest, parse_manifest
from .models import Platform

# Defensive cap so a single decompressed entry cannot exhaust memory.
_MAX_ENTRY_BYTES = 64 * 1024 * 1024
# Entries larger than this are skipped during text scans for performance.
_SCAN_ENTRY_LIMIT = 8 * 1024 * 1024


class PackageError(Exception):
    """Raised for corrupt, missing, or unrecognized packages."""


def detect_platform(path: str | Path) -> Platform:
    """Detect APK vs IPA from extension first, then archive contents."""
    p = Path(path)
    if not p.exists():
        raise PackageError(f"file not found: {p}")
    if not p.is_file():
        raise PackageError(f"not a file: {p}")

    suffix = p.suffix.lower()
    if suffix == ".apk":
        return Platform.ANDROID
    if suffix == ".ipa":
        return Platform.IOS

    if not zipfile.is_zipfile(p):
        raise PackageError(
            f"{p.name} is not a recognized package: expected a .apk or .ipa zip archive"
        )

    try:
        with zipfile.ZipFile(p) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile as exc:
        raise PackageError(f"corrupt archive: {exc}") from exc

    if any(n == "AndroidManifest.xml" for n in names):
        return Platform.ANDROID
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return Platform.IOS

    raise PackageError(
        f"could not determine platform for {p.name}: "
        "no AndroidManifest.xml or Payload/*.app found"
    )


@dataclass
class ApkPackage:
    path: Path
    platform: Platform = Platform.ANDROID
    manifest: Manifest = field(default_factory=Manifest)
    entries: list[str] = field(default_factory=list)
    has_v1_signature: bool = False
    has_v2_signature_block: bool = False
    _zip: zipfile.ZipFile | None = field(default=None, repr=False)

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    def read(self, name: str) -> bytes:
        assert self._zip is not None
        info = self._zip.getinfo(name)
        if info.file_size > _MAX_ENTRY_BYTES:
            raise PackageError(f"entry {name} too large to read safely")
        return self._zip.read(name)

    def iter_scannable(self):
        """Yield (name, bytes) for entries worth scanning for secrets."""
        assert self._zip is not None
        scan_prefixes = ("res/", "assets/", "resources.arsc")
        scan_suffixes = (".xml", ".json", ".txt", ".properties", ".js", ".smali", ".plist")
        for info in self._zip.infolist():
            if info.is_dir() or info.file_size > _SCAN_ENTRY_LIMIT:
                continue
            name = info.filename
            if name.startswith(scan_prefixes) or name.endswith(scan_suffixes):
                try:
                    yield name, self._zip.read(name)
                except (KeyError, zipfile.BadZipFile, OSError):
                    continue


@dataclass
class IpaPackage:
    path: Path
    platform: Platform = Platform.IOS
    app_dir: str = ""
    bundle_id: str = ""
    version: str = ""
    min_os: str = ""
    info_plist: dict = field(default_factory=dict)
    entitlements: dict = field(default_factory=dict)
    entries: list[str] = field(default_factory=list)
    binary_name: str = ""
    _zip: zipfile.ZipFile | None = field(default=None, repr=False)

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    def read(self, name: str) -> bytes:
        assert self._zip is not None
        info = self._zip.getinfo(name)
        if info.file_size > _MAX_ENTRY_BYTES:
            raise PackageError(f"entry {name} too large to read safely")
        return self._zip.read(name)

    def iter_scannable(self):
        assert self._zip is not None
        scan_suffixes = (".plist", ".json", ".txt", ".strings", ".js", ".html")
        for info in self._zip.infolist():
            if info.is_dir() or info.file_size > _SCAN_ENTRY_LIMIT:
                continue
            name = info.filename
            is_binary = self.binary_name and name.endswith("/" + self.binary_name)
            if is_binary or name.endswith(scan_suffixes):
                try:
                    yield name, self._zip.read(name)
                except (KeyError, zipfile.BadZipFile, OSError):
                    continue


def _open_zip(path: Path) -> zipfile.ZipFile:
    if not zipfile.is_zipfile(path):
        raise PackageError(f"{path.name} is not a valid zip archive")
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise PackageError(f"corrupt archive: {exc}") from exc


def load_apk(path: str | Path) -> ApkPackage:
    p = Path(path)
    zf = _open_zip(p)
    pkg = ApkPackage(path=p, _zip=zf, entries=zf.namelist())

    if "AndroidManifest.xml" not in pkg.entries:
        zf.close()
        raise PackageError("APK is missing AndroidManifest.xml")

    raw = zf.read("AndroidManifest.xml")
    try:
        pkg.manifest = parse_manifest(raw)
    except Exception as exc:  # decoder failures should not abort analysis
        pkg.manifest = Manifest()
        pkg.manifest.package = ""
        raise PackageError(f"failed to decode AndroidManifest.xml: {exc}") from exc

    meta_inf = [n for n in pkg.entries if n.startswith("META-INF/")]
    pkg.has_v1_signature = any(
        n.upper().endswith((".RSA", ".DSA", ".EC")) for n in meta_inf
    ) and any(n.upper().endswith(".SF") for n in meta_inf)
    # v2/v3 signatures live in the APK Signing Block before the central
    # directory. A reliable lightweight proxy is the presence of the v1
    # files plus an absence check; we additionally scan for the magic.
    pkg.has_v2_signature_block = _has_apk_sig_block_v2(p)
    return pkg


def _has_apk_sig_block_v2(path: Path) -> bool:
    """Best-effort detection of the APK Signing Block v2 magic."""
    magic = b"APK Sig Block 42"
    try:
        data = path.read_bytes()
    except OSError:
        return False
    return magic in data


def load_ipa(path: str | Path) -> IpaPackage:
    p = Path(path)
    zf = _open_zip(p)
    pkg = IpaPackage(path=p, _zip=zf, entries=zf.namelist())

    app_dirs = sorted(
        {
            n.split("/")[1]
            for n in pkg.entries
            if n.startswith("Payload/") and "/" in n[len("Payload/") :] and ".app" in n
        }
    )
    app_name = next((d for d in app_dirs if d.endswith(".app")), "")
    if not app_name:
        zf.close()
        raise PackageError("IPA is missing Payload/*.app")
    pkg.app_dir = f"Payload/{app_name}"

    info_path = f"{pkg.app_dir}/Info.plist"
    if info_path not in pkg.entries:
        zf.close()
        raise PackageError(f"IPA is missing {info_path}")

    try:
        pkg.info_plist = plistlib.loads(zf.read(info_path))
    except Exception as exc:
        zf.close()
        raise PackageError(f"failed to parse Info.plist: {exc}") from exc

    pkg.bundle_id = str(pkg.info_plist.get("CFBundleIdentifier", ""))
    pkg.version = str(
        pkg.info_plist.get("CFBundleShortVersionString", pkg.info_plist.get("CFBundleVersion", ""))
    )
    pkg.min_os = str(pkg.info_plist.get("MinimumOSVersion", ""))
    pkg.binary_name = str(pkg.info_plist.get("CFBundleExecutable", ""))

    prov_path = f"{pkg.app_dir}/embedded.mobileprovision"
    if prov_path in pkg.entries:
        try:
            pkg.entitlements = _parse_mobileprovision(zf.read(prov_path))
        except Exception:
            pkg.entitlements = {}

    return pkg


def _parse_mobileprovision(data: bytes) -> dict:
    """Best-effort extraction of the embedded plist from a provisioning profile.

    A .mobileprovision is a CMS (PKCS7) signed blob. The plist payload sits
    between the ``<?xml`` (or ``bplist``) marker and the closing ``</plist>``.
    We extract that span and parse the Entitlements dictionary.
    """
    start = data.find(b"<?xml")
    end = data.find(b"</plist>")
    if start == -1 or end == -1:
        return {}
    plist_bytes = data[start : end + len(b"</plist>")]
    try:
        parsed = plistlib.loads(plist_bytes)
    except Exception:
        return {}
    ent = parsed.get("Entitlements", {})
    return ent if isinstance(ent, dict) else {}
