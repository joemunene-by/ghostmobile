"""Core data models for ghostmobile: severity levels and findings."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher value means more severe."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> Severity:
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {name!r}, expected one of: {valid}") from exc

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Platform(str, enum.Enum):
    ANDROID = "android"
    IOS = "ios"


@dataclass
class Finding:
    """A single security finding produced by a check."""

    id: str
    platform: Platform
    title: str
    severity: Severity
    description: str
    remediation: str
    location: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "platform": self.platform.value,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "remediation": self.remediation,
            "location": self.location,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class AnalysisResult:
    """The full result of analyzing one package."""

    target: str
    platform: Platform
    package_name: str = ""
    findings: list[Finding] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.id))

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "platform": self.platform.value,
            "package_name": self.package_name,
            "info": self.info,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
