from __future__ import annotations

import re
from typing import Any

from bs.collectors.common import run_command


_THROTTLE_FLAGS = {
    0: "under_voltage_now",
    1: "frequency_capped_now",
    2: "throttled_now",
    3: "soft_temp_limit_now",
    16: "under_voltage_seen",
    17: "frequency_capped_seen",
    18: "throttled_seen",
    19: "soft_temp_limit_seen",
}


def _parse_throttled(output: str) -> dict[str, Any] | None:
    match = re.search(r"0x([0-9a-fA-F]+)", output)
    if not match:
        return None
    value = int(match.group(1), 16)
    flags = [name for bit, name in _THROTTLE_FLAGS.items() if value & (1 << bit)]
    return {"raw": f"0x{value:x}", "active": bool(value & 0xF), "flags": flags}


def collect_power() -> dict[str, Any]:
    throttled_output = run_command(["vcgencmd", "get_throttled"])
    throttled = _parse_throttled(throttled_output) if throttled_output else None

    volts: dict[str, str] = {}
    for rail in ("core", "sdram_c", "sdram_i", "sdram_p"):
        output = run_command(["vcgencmd", "measure_volts", rail])
        if output and "=" in output:
            volts[rail] = output.split("=", 1)[1]

    return {
        "available": throttled is not None or bool(volts),
        "throttled": throttled,
        "volts": volts,
        "reason": None if throttled is not None or volts else "vcgencmd power data unavailable",
    }
