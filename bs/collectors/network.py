from __future__ import annotations

from typing import Any

from bs.collectors.common import read_lines


def collect_network() -> dict[str, Any]:
    interfaces: list[dict[str, Any]] = []
    for line in read_lines("/proc/net/dev")[2:]:
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        fields = raw.split()
        if len(fields) < 16:
            continue
        iface = name.strip()
        if iface == "lo":
            continue
        interfaces.append(
            {
                "interface": iface,
                "rx_bytes": int(fields[0]),
                "rx_packets": int(fields[1]),
                "tx_bytes": int(fields[8]),
                "tx_packets": int(fields[9]),
            }
        )
    return {"available": bool(interfaces), "interfaces": interfaces}
