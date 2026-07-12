from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


def render_fan(data: dict[str, Any]) -> None:
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Temperature", f"{data['temperature_c']:.1f} C" if data.get("temperature_c") is not None else "n/a")
    table.add_row(
        "Control Temp",
        f"{data['control_temperature_c']:.1f} C" if data.get("control_temperature_c") is not None else "n/a",
    )
    for sensor in data.get("temperature_sensors", []):
        table.add_row(f"Sensor {sensor['label']}", f"{sensor['temperature_c']:.1f} C")
    table.add_row("Cooling Device", data["cooling_device"].get("type") or "n/a")
    table.add_row("State", f"{data['cooling_device'].get('state')} / {data['cooling_device'].get('max_state')}")
    table.add_row("PWM", str(data["hwmon"].get("pwm")))
    table.add_row("PWM Enable", str(data["hwmon"].get("pwm_enable")))
    table.add_row("RPM", str(data["hwmon"].get("rpm")))
    console.print(Panel(table, title="B-Suite Fan", box=box.ROUNDED))


def render_fan_step(data: dict[str, Any]) -> None:
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Profile", data["profile"])
    table.add_row("Temperature", f"{data['temperature_c']:.1f} C")
    table.add_row("Previous State", str(data["previous_state"]))
    table.add_row("Target State", str(data["target_state"]))
    table.add_row("Changed", "yes" if data["changed"] else "no")
    fan = data["fan"]
    table.add_row("Current RPM", str(fan["hwmon"].get("rpm")))
    table.add_row("Current PWM", str(fan["hwmon"].get("pwm")))
    console.print(Panel(table, title="B-Suite Fan Control", box=box.ROUNDED))
