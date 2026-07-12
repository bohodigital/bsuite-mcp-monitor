from __future__ import annotations

from typing import Any

from bs.collectors.cpu import collect_cpu
from bs.collectors.disk import collect_disks, collect_mounts
from bs.collectors.host import collect_host
from bs.collectors.memory import collect_memory
from bs.collectors.network import collect_network
from bs.collectors.power import collect_power
from bs.collectors.processes import collect_processes
from bs.collectors.result import meta
from bs.collectors.thermal import collect_thermal


def collect_status() -> dict[str, Any]:
    data = {
        "host": collect_host(),
        "cpu": collect_cpu(),
        "memory": collect_memory(),
        "disks": collect_disks(),
        "mounts": collect_mounts(),
        "thermal": collect_thermal(),
        "power": collect_power(),
        "processes": collect_processes(),
        "network": collect_network(),
    }
    warnings = []
    if not data["network"].get("available"):
        warnings.append("network counters are unavailable or hidden")
    if data["processes"].get("count", 0) <= 2:
        warnings.append("process visibility appears limited")
    data["_meta"] = meta("status", limited=bool(warnings), reason=warnings[0] if warnings else None, source="/proc/sysfs", warnings=warnings)
    return data
