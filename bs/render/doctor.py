from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table


console = Console()


def _style(status: str) -> str:
    return {"ok": "green", "warn": "yellow", "fail": "red"}.get(status, "")


def build_doctor_renderable(data: dict[str, Any]) -> Group:
    summary = data["summary"]
    summary_table = Table(show_header=False, box=None, expand=True)
    summary_table.add_column("Metric")
    summary_table.add_column("Value")
    summary_table.add_row("OK", str(summary.get("ok", 0)))
    summary_table.add_row("Warnings", str(summary.get("warn", 0)))
    summary_table.add_row("Failures", str(summary.get("fail", 0)))

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Status")
    table.add_column("Category")
    table.add_column("Check")
    table.add_column("Detail")
    table.add_column("Hint")
    for check in data["checks"]:
        status = check["status"]
        table.add_row(f"[{_style(status)}]{status}[/{_style(status)}]" if _style(status) else status, check["category"], check["name"], check["detail"], check.get("hint", ""))

    panels = [Panel(summary_table, title="Summary", box=box.ROUNDED)]
    installation = data.get("installation")
    if installation:
        install_table = Table(show_header=False, box=None, expand=True)
        install_table.add_column("Metric")
        install_table.add_column("Value")
        install_table.add_row("Result", "installed" if installation.get("ok") else "not installed")
        install_table.add_row("Manager", str(installation.get("manager") or "unavailable"))
        install_table.add_row("Packages", ", ".join(installation.get("packages", [])) or "none")
        install_table.add_row("Detail", str(installation.get("message") or ""))
        panels.append(Panel(install_table, title="Dependency Installation", box=box.ROUNDED, border_style="green" if installation.get("ok") else "red"))
    panels.append(Panel(table, title="Checks", box=box.ROUNDED))
    return Group("B-Suite Doctor", *panels)


def render_doctor(data: dict[str, Any]) -> None:
    console.print(build_doctor_renderable(data))
