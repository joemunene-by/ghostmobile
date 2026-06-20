"""Regex-based detection of hardcoded secrets in bundled resources."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Each pattern is (name, compiled-regex). Patterns aim for high precision so
# the tool does not drown a reviewer in false positives.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("Stripe Secret Key", re.compile(r"\bsk_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    (
        "Generic API Key Assignment",
        re.compile(
            r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*"
            r"['\"][0-9A-Za-z_\-]{12,}['\"]"
        ),
    ),
]

# Decoy/placeholder values that should never be reported as real secrets.
_PLACEHOLDERS = re.compile(
    r"(?i)(your[_-]?api[_-]?key|example|changeme|placeholder|xxxx+|0000+|test[_-]?key)"
)


@dataclass
class SecretMatch:
    kind: str
    value: str
    location: str

    @property
    def redacted(self) -> str:
        v = self.value
        if len(v) <= 8:
            return v[:2] + "***"
        return v[:4] + "***" + v[-2:]


def scan_text(text: str, location: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(0)
            if _PLACEHOLDERS.search(value):
                continue
            matches.append(SecretMatch(kind=kind, value=value, location=location))
    return matches


def scan_bytes(data: bytes, location: str) -> list[SecretMatch]:
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    return scan_text(text, location)
