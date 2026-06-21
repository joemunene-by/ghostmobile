<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="ghostmobile logo">
</p>

<h1 align="center">ghostmobile</h1>

Static security analyzer for Android APK and iOS IPA packages. It unpacks a
package (a zip archive), inspects the manifest, configuration, and metadata,
and reports security issues with a severity and remediation guidance. Think of
it as a light, dependency-conscious, static-only companion to larger mobile
security suites.

## Static only

ghostmobile never executes the application. It reads archive entries, decodes
the manifest, and pattern-matches resource and binary strings. No emulator, no
instrumentation, no network calls. The worst it does to a package is read it.

## Authorized use only

Use ghostmobile only on packages you own or are explicitly authorized to
review. Static analysis of third-party applications may be restricted by law
or by the application's terms. You are responsible for ensuring you have
permission to analyze any package you point it at.

## Install

Requires Python 3.11 or newer.

```bash
git clone https://github.com/joemunene-by/ghostmobile.git
cd ghostmobile
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quickstart

Analyze a package (the platform is autodetected from the extension or the
archive contents):

```bash
ghostmobile analyze app.apk
ghostmobile analyze app.ipa --format json
ghostmobile analyze app.apk --format sarif --output app.sarif
ghostmobile analyze app.apk --min-severity high --fail-on high
ghostmobile checks
ghostmobile version
```

Sample output on a crafted, benign APK fixture (the kind the test suite
builds, never a real proprietary app):

```
ghostmobile 0.1.0  target=vuln.apk  platform=android
package: com.ghostmobile.vuln
                                  Findings (9)
 Severity   ID           Title                                  Location
 High       GM-AND-001   Application is debuggable              AndroidManifest.xml (application)
 High       GM-AND-004   Exported provider without permission   AndroidManifest.xml (provider)
 High       GM-AND-008   Possible hardcoded secret: AWS key     res/values/strings.xml
 Medium     GM-AND-002   Application allows backup              AndroidManifest.xml (application)
 Medium     GM-AND-003   Cleartext network traffic permitted    AndroidManifest.xml (application)
 Medium     GM-AND-006   Weak custom permission                 AndroidManifest.xml (permission)
 Low        GM-AND-005   Dangerous permissions requested        AndroidManifest.xml (uses-permission)
```

## CLI

| Flag | Purpose |
| --- | --- |
| `--format {console,json,sarif}` | Output format. JSON and SARIF print verbatim to stdout. |
| `--min-severity {info,low,medium,high,critical}` | Hide findings below this severity. |
| `--fail-on {info,low,medium,high,critical}` | Exit non-zero if any finding is at or above this severity. |
| `--output PATH` | Write the report to a file instead of stdout. |
| `--verbose` | Verbose logging to stderr. |

Exit codes: `0` success, `1` findings met the `--fail-on` threshold, `2` the
package could not be analyzed (missing file, not a package, corrupt archive).

## Supported checks

### Android (APK)

| ID | Severity | Check |
| --- | --- | --- |
| GM-AND-001 | High | Application is debuggable (android:debuggable=true). |
| GM-AND-002 | Medium | Application allows backup (android:allowBackup=true). |
| GM-AND-003 | Medium | Cleartext network traffic permitted. |
| GM-AND-004 | Medium/High | Exported component (explicit or implicit) without permission. |
| GM-AND-005 | Low | Dangerous runtime permissions requested. |
| GM-AND-006 | Medium | Custom permission with a weak protection level. |
| GM-AND-007 | High | APK is unsigned or missing recognizable v1/v2 signatures. |
| GM-AND-008 | High | Hardcoded secret in bundled resources or assets. |

### iOS (IPA)

| ID | Severity | Check |
| --- | --- | --- |
| GM-IOS-001 | High | App Transport Security disabled (NSAllowsArbitraryLoads). |
| GM-IOS-002 | Medium | ATS exception domain allows insecure HTTP loads. |
| GM-IOS-003 | Low | Custom URL schemes registered (deep-link attack surface). |
| GM-IOS-004 | Low | Privacy-sensitive capabilities requested. |
| GM-IOS-005 | Medium/High | Risky entitlements (get-task-allow, wildcard App ID). |
| GM-IOS-006 | High | Hardcoded secret in the app binary or bundle. |

## How the AXML decoder works

Android does not ship `AndroidManifest.xml` as plain text. It is stored in
Android binary XML (AXML), a chunked binary format produced by aapt. To keep
dependencies light, ghostmobile includes a compact, self-contained AXML
decoder (`ghostmobile/axml.py`) instead of requiring androguard.

The decoder walks the chunk stream:

1. Parse the header and locate the string pool chunk, decoding either UTF-8 or
   UTF-16 strings with their length-prefix varints.
2. Read the optional resource-id map chunk (attribute name to framework
   resource id).
3. Walk the namespace and start/end element chunks, reconstructing element
   names, attributes, and their typed values (strings, booleans, integers,
   references) into an element tree.

Element accessors (`element.attr(...)`, `element.findall(...)`) then expose the
recovered structure to the manifest model and checks. The package also ships a
matching encoder (`ghostmobile/axml_encode.py`) so the test suite can build
crafted, benign binary manifests without distributing any real app.

If `androguard` is importable it may be used as an alternative, but the
built-in decoder is the default so the tool and its tests stay dependency-light.

## Limitations

- Static analysis only. Runtime behavior, dynamic class loading, and network
  traffic are out of scope.
- Secret detection is regex-based and tuned for precision, so it can miss
  obfuscated or encoded secrets and is not a substitute for secret scanning of
  source.
- The provisioning-profile parser extracts the embedded plist on a best-effort
  basis and does not verify the CMS signature.
- The v2/v3 APK signing detection is a lightweight presence check, not a full
  signature verification.
- Resource string scanning does not decode the compiled `resources.arsc`
  binary table; it scans text-like entries.

## Roadmap

- Decode `resources.arsc` to resolve `@string` references and scan compiled
  resource values.
- Parse `network_security_config.xml` for cleartext and trust-anchor issues.
- Smali/dex string extraction for deeper Android secret and API analysis.
- Optional androguard-backed analysis path behind a feature flag.
- Baseline/suppression file support for triaged findings in CI.

## Development

```bash
ruff check .
pytest
```

CI runs `ruff check` and the test suite on Python 3.11 and 3.12.

## License

MIT. See [LICENSE](LICENSE).
