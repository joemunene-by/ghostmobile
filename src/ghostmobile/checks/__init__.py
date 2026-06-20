"""Check framework: base class, registry, and built-in checks."""

from __future__ import annotations

from ..models import Platform

# Import built-in check modules so their @register decorators run.
from . import android as _android  # noqa: E402,F401
from . import ios as _ios  # noqa: E402,F401
from .base import Check, CheckContext, register, registry  # noqa: F401


def all_checks() -> list[Check]:
    return registry.all()


def checks_for(platform: Platform) -> list[Check]:
    return registry.for_platform(platform)
