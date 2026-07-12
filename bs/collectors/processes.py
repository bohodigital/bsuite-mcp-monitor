from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from bs.collectors.common import read_text


_CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")


def _boot_time() -> int:
    for line in (read_text("/proc/stat") or "").splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return int(time.time())


def _process_snapshot() -> list[dict[str, Any]]:
    boot_time = _boot_time()
    now = time.time()
    items: list[dict[str, Any]] = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        stat = read_text(proc / "stat")
        status = read_text(proc / "status")
        cmdline = read_text(proc / "cmdline")
        if not stat:
            continue
        try:
            end_comm = stat.rfind(")")
            name = stat[stat.find("(") + 1 : end_comm]
            fields = stat[end_comm + 2 :].split()
            utime = int(fields[11])
            stime = int(fields[12])
            starttime = int(fields[19])
            total_time = (utime + stime) / _CLK_TCK
            elapsed = max(now - (boot_time + (starttime / _CLK_TCK)), 0.01)
            cpu_percent = round((total_time / elapsed) * 100.0, 1)
        except (IndexError, ValueError):
            continue

        rss_bytes = 0
        if status:
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    rss_bytes = int(line.split()[1]) * 1024
                    break
        command = (cmdline or "").replace("\x00", " ").strip() or name
        items.append(
            {
                "pid": int(proc.name),
                "name": name,
                "command": command[:100],
                "cpu_percent": cpu_percent,
                "rss": rss_bytes,
            }
        )
    return items


def collect_processes(limit: int = 8) -> dict[str, Any]:
    processes = _process_snapshot()
    top_cpu = sorted(processes, key=lambda item: item["cpu_percent"], reverse=True)[:limit]
    top_mem = sorted(processes, key=lambda item: item["rss"], reverse=True)[:limit]
    return {
        "available": True,
        "count": len(processes),
        "top_cpu": top_cpu,
        "top_memory": top_mem,
    }
