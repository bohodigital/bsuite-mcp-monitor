from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from bs.collectors.common import read_text, run_command


def _vcgencmd_temp() -> dict[str, Any] | None:
    output = run_command(["vcgencmd", "measure_temp"])
    if not output:
        return None
    match = re.search(r"temp=([0-9.]+)", output)
    if not match:
        return None
    return {"label": "cpu", "temperature_c": float(match.group(1)), "source": "vcgencmd"}


def _sysfs_temps() -> list[dict[str, Any]]:
    temps: list[dict[str, Any]] = []
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        raw_temp = read_text(zone / "temp")
        if not raw_temp:
            continue
        try:
            value = int(raw_temp)
        except ValueError:
            continue
        label = read_text(zone / "type") or zone.name
        temps.append({"label": label, "temperature_c": round(value / 1000.0, 1), "source": str(zone)})
    return temps


def _hwmon_temps() -> list[dict[str, Any]]:
    temps: list[dict[str, Any]] = []
    for hwmon in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        name = read_text(hwmon / "name") or hwmon.name
        for temp_input in sorted(hwmon.glob("temp*_input")):
            raw_value = read_text(temp_input)
            if raw_value is None:
                continue
            try:
                value = int(raw_value)
            except ValueError:
                continue
            index = temp_input.name.removeprefix("temp").removesuffix("_input")
            label = read_text(hwmon / f"temp{index}_label") or name
            temps.append(
                {
                    "label": label,
                    "temperature_c": round(value / 1000.0, 1),
                    "source": str(temp_input),
                }
            )
    return temps


def _hwmon_fans() -> list[dict[str, Any]]:
    fans: list[dict[str, Any]] = []
    for hwmon in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        name = read_text(hwmon / "name") or hwmon.name
        for fan_input in sorted(hwmon.glob("fan*_input")):
            raw_value = read_text(fan_input)
            if raw_value is None:
                continue
            try:
                rpm = int(raw_value)
            except ValueError:
                continue
            index = fan_input.name.removeprefix("fan").removesuffix("_input")
            pwm = read_text(hwmon / f"pwm{index}")
            fans.append(
                {
                    "label": f"{name} fan{index}",
                    "rpm": rpm,
                    "pwm": int(pwm) if pwm and pwm.isdigit() else None,
                    "source": str(fan_input),
                }
            )
    return fans


def collect_thermal() -> dict[str, Any]:
    temps = []
    vc_temp = _vcgencmd_temp()
    if vc_temp:
        temps.append(vc_temp)
    for temp in _sysfs_temps():
        if not any(existing["source"] == temp["source"] for existing in temps):
            temps.append(temp)
    for temp in _hwmon_temps():
        if not any(existing["source"] == temp["source"] for existing in temps):
            temps.append(temp)
    return {
        "available": bool(temps),
        "temperatures": temps,
        "fans": _hwmon_fans(),
        "reason": None if temps else "no thermal source found",
    }
