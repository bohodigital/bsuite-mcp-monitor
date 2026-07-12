from __future__ import annotations

import os
import time
from typing import Any

from bs.collectors.common import read_lines


def _read_cpu_times() -> dict[str, list[int]]:
    cpus: dict[str, list[int]] = {}
    for line in read_lines("/proc/stat"):
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        if parts[0] == "cpu" or parts[0][3:].isdigit():
            cpus[parts[0]] = [int(value) for value in parts[1:]]
    return cpus


def _usage_percent(before: list[int], after: list[int]) -> float:
    idle_before = before[3] + (before[4] if len(before) > 4 else 0)
    idle_after = after[3] + (after[4] if len(after) > 4 else 0)
    total_before = sum(before)
    total_after = sum(after)
    total_delta = total_after - total_before
    idle_delta = idle_after - idle_before
    if total_delta <= 0:
        return 0.0
    return round((1.0 - (idle_delta / total_delta)) * 100.0, 1)


def collect_cpu(sample_interval: float = 0.12) -> dict[str, Any]:
    before = _read_cpu_times()
    time.sleep(sample_interval)
    after = _read_cpu_times()

    total = _usage_percent(before.get("cpu", []), after.get("cpu", [])) if "cpu" in before else 0.0
    per_core = []
    for name in sorted((key for key in after if key != "cpu"), key=lambda item: int(item[3:])):
        if name in before:
            per_core.append({"core": name, "usage_percent": _usage_percent(before[name], after[name])})

    return {
        "available": bool(after),
        "logical_cores": os.cpu_count() or len(per_core),
        "usage_percent": total,
        "per_core": per_core,
    }
