from __future__ import annotations

import time
from typing import Any

from bs.collectors.common import base_host_info, read_lines, read_text


def _pretty_uptime(seconds: float) -> str:
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def collect_host() -> dict[str, Any]:
    info = base_host_info()
    uptime_text = read_text("/proc/uptime")
    uptime_seconds = float(uptime_text.split()[0]) if uptime_text else 0.0

    os_name = "Linux"
    for line in read_lines("/etc/os-release"):
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip('"')
            break

    loadavg = read_text("/proc/loadavg")
    loads = [float(item) for item in loadavg.split()[:3]] if loadavg else []

    info.update(
        {
            "os": os_name,
            "uptime_seconds": int(uptime_seconds),
            "uptime": _pretty_uptime(uptime_seconds),
            "loadavg": loads,
            "timestamp": int(time.time()),
        }
    )
    return info
