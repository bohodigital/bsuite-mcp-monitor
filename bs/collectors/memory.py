from __future__ import annotations

from typing import Any

from bs.collectors.common import percent, read_lines


def _meminfo() -> dict[str, int]:
    data: dict[str, int] = {}
    for line in read_lines("/proc/meminfo"):
        key, raw_value = line.split(":", 1)
        parts = raw_value.strip().split()
        if not parts:
            continue
        data[key] = int(parts[0]) * 1024
    return data


def collect_memory() -> dict[str, Any]:
    data = _meminfo()
    total = data.get("MemTotal", 0)
    available = data.get("MemAvailable", 0)
    used = max(total - available, 0)
    swap_total = data.get("SwapTotal", 0)
    swap_free = data.get("SwapFree", 0)
    swap_used = max(swap_total - swap_free, 0)
    return {
        "available": bool(data),
        "ram": {
            "total": total,
            "available": available,
            "used": used,
            "used_percent": percent(used, total),
        },
        "swap": {
            "total": swap_total,
            "free": swap_free,
            "used": swap_used,
            "used_percent": percent(swap_used, swap_total),
        },
    }
