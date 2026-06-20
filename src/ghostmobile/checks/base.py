"""Base classes and registry for ghostmobile checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..models import Finding, Platform

if TYPE_CHECKING:
    from ..package import ApkPackage, IpaPackage


@dataclass
class CheckContext:
    """What a check receives at evaluation time."""

    platform: Platform
    apk: ApkPackage | None = None
    ipa: IpaPackage | None = None


class Check:
    """Base class for a single security check.

    Subclasses set ``id``, ``platform``, ``title``, ``severity_hint`` and
    implement :meth:`run`, returning a list of findings (possibly empty).
    """

    id: str = ""
    platform: Platform = Platform.ANDROID
    title: str = ""
    description: str = ""

    def run(self, ctx: CheckContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError


class _Registry:
    def __init__(self) -> None:
        self._checks: list[Check] = []

    def add(self, check: Check) -> None:
        if any(c.id == check.id for c in self._checks):
            raise ValueError(f"duplicate check id: {check.id}")
        self._checks.append(check)

    def all(self) -> list[Check]:
        return sorted(self._checks, key=lambda c: c.id)

    def for_platform(self, platform: Platform) -> list[Check]:
        return [c for c in self.all() if c.platform == platform]


registry = _Registry()


def register(cls: type[Check]) -> type[Check]:
    """Class decorator that instantiates and registers a check."""
    registry.add(cls())
    return cls
