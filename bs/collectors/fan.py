from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bs.collectors.common import read_text


THERMAL_ZONE = Path("/sys/class/thermal/thermal_zone0/temp")
COOLING_DEVICE = Path("/sys/class/thermal/cooling_device0")
CUR_STATE = COOLING_DEVICE / "cur_state"
MAX_STATE = COOLING_DEVICE / "max_state"
COOLING_TYPE = COOLING_DEVICE / "type"
HWMON_FAN = Path("/sys/class/hwmon/hwmon2")
PWM = HWMON_FAN / "pwm1"
PWM_ENABLE = HWMON_FAN / "pwm1_enable"
FAN_INPUT = HWMON_FAN / "fan1_input"


@dataclass(frozen=True)
class FanProfile:
    name: str
    up: tuple[float, float, float, float]
    down: tuple[float, float, float, float]
    emergency_c: float


PROFILES: dict[str, FanProfile] = {
    "quiet": FanProfile("quiet", up=(52, 60, 67, 74), down=(47, 55, 62, 69), emergency_c=80),
    "balanced": FanProfile("balanced", up=(48, 56, 64, 70), down=(44, 52, 60, 66), emergency_c=78),
    "cool": FanProfile("cool", up=(43, 50, 58, 65), down=(40, 47, 55, 62), emergency_c=74),
}


def _int_text(path: Path) -> int | None:
    text = read_text(path)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def read_cpu_temp_c() -> float | None:
    raw = _int_text(THERMAL_ZONE)
    if raw is None:
        return None
    return round(raw / 1000.0, 1)


def read_temp_sensors() -> list[dict[str, Any]]:
    sensors = []
    cpu = read_cpu_temp_c()
    if cpu is not None:
        sensors.append({"label": "cpu-thermal", "temperature_c": cpu, "source": str(THERMAL_ZONE)})
    for hwmon in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        name = read_text(hwmon / "name") or hwmon.name
        for temp_input in sorted(hwmon.glob("temp*_input")):
            raw = _int_text(temp_input)
            if raw is None:
                continue
            index = temp_input.name.removeprefix("temp").removesuffix("_input")
            label = read_text(hwmon / f"temp{index}_label") or name
            sensors.append({"label": label, "temperature_c": round(raw / 1000.0, 1), "source": str(temp_input)})
    return sensors


def read_control_temp_c() -> float | None:
    sensors = read_temp_sensors()
    values = [sensor["temperature_c"] for sensor in sensors if sensor.get("temperature_c") is not None]
    return max(values) if values else None


def collect_fan() -> dict[str, Any]:
    sensors = read_temp_sensors()
    return {
        "available": CUR_STATE.exists(),
        "temperature_c": read_cpu_temp_c(),
        "control_temperature_c": read_control_temp_c(),
        "temperature_sensors": sensors,
        "cooling_device": {
            "path": str(COOLING_DEVICE),
            "type": read_text(COOLING_TYPE),
            "state": _int_text(CUR_STATE),
            "max_state": _int_text(MAX_STATE),
        },
        "hwmon": {
            "path": str(HWMON_FAN),
            "pwm": _int_text(PWM),
            "pwm_enable": _int_text(PWM_ENABLE),
            "rpm": _int_text(FAN_INPUT),
        },
        "profiles": {name: {"up": profile.up, "down": profile.down, "emergency_c": profile.emergency_c} for name, profile in PROFILES.items()},
    }


def target_state(temp_c: float, current_state: int, profile: FanProfile) -> int:
    if temp_c >= profile.emergency_c:
        return 4

    state = max(0, min(current_state, 4))

    while state < 4 and temp_c >= profile.up[state]:
        state += 1

    while state > 0 and temp_c <= profile.down[state - 1]:
        state -= 1

    return state


def write_state(state: int, use_sudo: bool = True) -> None:
    max_state = _int_text(MAX_STATE)
    if max_state is None:
        raise RuntimeError("fan cooling max_state is unavailable")
    if state < 0 or state > max_state:
        raise ValueError(f"state must be between 0 and {max_state}")

    value = f"{state}\n"
    if os.geteuid() == 0:
        CUR_STATE.write_text(value, encoding="utf-8")
        return

    if not use_sudo:
        raise PermissionError(f"writing {CUR_STATE} requires root")

    result = subprocess.run(
        ["sudo", "-n", "tee", str(CUR_STATE)],
        input=value,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PermissionError(result.stderr.strip() or f"failed to write {CUR_STATE}")


def auto_step(profile_name: str = "cool", use_sudo: bool = True) -> dict[str, Any]:
    profile = PROFILES[profile_name]
    before = collect_fan()
    temp = before["control_temperature_c"]
    current = before["cooling_device"]["state"]
    if temp is None or current is None:
        raise RuntimeError("fan temperature/state is unavailable")
    target = target_state(temp, current, profile)
    changed = target != current
    if changed:
        write_state(target, use_sudo=use_sudo)
        time.sleep(0.2)
    after = collect_fan()
    return {
        "profile": profile.name,
        "temperature_c": temp,
        "previous_state": current,
        "target_state": target,
        "changed": changed,
        "fan": after,
    }
