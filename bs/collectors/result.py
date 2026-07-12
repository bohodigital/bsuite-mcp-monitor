from __future__ import annotations

from typing import Any


def meta(
    name: str,
    *,
    available: bool = True,
    limited: bool = False,
    reason: str | None = None,
    source: str | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "available": available,
        "limited": limited,
        "reason": reason,
        "source": source,
        "warnings": warnings or [],
    }


def unavailable(name: str, reason: str, *, source: str | None = None) -> dict[str, Any]:
    return meta(name, available=False, reason=reason, source=source)


def limited(name: str, reason: str, *, source: str | None = None, warnings: list[str] | None = None) -> dict[str, Any]:
    return meta(name, limited=True, reason=reason, source=source, warnings=warnings)
