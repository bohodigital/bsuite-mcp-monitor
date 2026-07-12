from __future__ import annotations

import copy
import socket
import time
from dataclasses import dataclass
from typing import Any

from bs.collectors.geo import is_public_ip, lookup_geo, non_public_location_reason


DEFAULT_LOOKUP_LIMIT = -1
DNS_TTL_SECONDS = 300.0
GEO_TTL_SECONDS = 300.0

_DNS_CACHE: dict[str, tuple[float, str | None]] = {}
_GEO_CACHE: dict[tuple[str, str | None], tuple[float, dict[str, Any] | None]] = {}


@dataclass
class LookupBudget:
    limit: int = DEFAULT_LOOKUP_LIMIT
    used: int = 0
    skipped: int = 0

    def allow(self) -> bool:
        if self.limit < 0:
            self.used += 1
            return True
        if self.used >= self.limit:
            self.skipped += 1
            return False
        self.used += 1
        return True

    def summary(self) -> dict[str, int]:
        return {"limit": self.limit, "used": self.used, "skipped": self.skipped}


def _fresh(started_at: float, ttl: float) -> bool:
    return time.monotonic() - started_at <= ttl


def reverse_dns(ip: str, budget: LookupBudget | None = None, ttl: float = DNS_TTL_SECONDS) -> str | None:
    if not is_public_ip(ip):
        return None
    cached = _DNS_CACHE.get(ip)
    if cached and _fresh(cached[0], ttl):
        return cached[1]
    if budget and not budget.allow():
        return None
    try:
        value = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        value = None
    _DNS_CACHE[ip] = (time.monotonic(), value)
    return value


def geo_lookup(ip: str, db_path: str | None = None, budget: LookupBudget | None = None, ttl: float = GEO_TTL_SECONDS) -> dict[str, Any] | None:
    if not is_public_ip(ip):
        return {"ip": ip, "available": False, "reason": non_public_location_reason(ip)}
    key = (ip, db_path)
    cached = _GEO_CACHE.get(key)
    if cached and _fresh(cached[0], ttl):
        return copy.deepcopy(cached[1])
    if budget and not budget.allow():
        return None
    value = lookup_geo(ip, db_path)
    _GEO_CACHE[key] = (time.monotonic(), copy.deepcopy(value))
    return copy.deepcopy(value)


def clear_caches() -> None:
    _DNS_CACHE.clear()
    _GEO_CACHE.clear()
