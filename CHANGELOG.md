# Changelog

All notable changes to ghostmobile are documented here. The format follows
Keep a Changelog, and this project adheres to semantic versioning.

## [0.1.0] - 2026-06-21

### Added

- Static analysis engine for Android APK and iOS IPA packages (no execution).
- Dependency-free binary AndroidManifest.xml (AXML) decoder, plus a matching
  encoder used to build crafted, benign test fixtures.
- Android manifest model: package, min/target SDK, permissions, exported
  components, debuggable, allowBackup, cleartext traffic, custom permissions.
- iOS Info.plist parsing (binary and XML), best-effort embedded provisioning
  profile entitlements extraction.
- Eight Android checks (GM-AND-001 through GM-AND-008) and six iOS checks
  (GM-IOS-001 through GM-IOS-006).
- Regex-based hardcoded secret scanning over bundled resources and binaries.
- Typer CLI with analyze, checks, and version subcommands.
- Output formats: rich console table, JSON, and SARIF 2.1.0.
- Severity filtering (--min-severity) and exit-code gating (--fail-on).
- Test suite (42 tests) runnable under bare pytest, plus ruff configuration
  and a GitHub Actions CI workflow for Python 3.11 and 3.12.
