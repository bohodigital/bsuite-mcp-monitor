from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table


console = Console()


def _style(severity: str) -> str:
    return {"high": "red", "medium": "yellow", "low": "cyan", "info": "blue", "ok": "green"}.get(severity, "")


def build_security_renderable(data: dict[str, Any]) -> Group:
    summary = data["summary"]
    summary_table = Table(show_header=False, box=None, expand=True)
    summary_table.add_column("Severity")
    summary_table.add_column("Count")
    for severity in ("high", "medium", "low", "info", "ok"):
        summary_table.add_row(severity, str(summary.get(severity, 0)))

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Severity")
    table.add_column("Area")
    table.add_column("Finding")
    table.add_column("Detail")
    table.add_column("Recommendation")
    for item in data["findings"]:
        severity = item["severity"]
        style = _style(severity)
        table.add_row(f"[{style}]{severity}[/{style}]" if style else severity, item["area"], item["title"], item["detail"], item.get("recommendation", ""))

    return Group("B-Suite Security", Panel(summary_table, title="Summary", box=box.ROUNDED), Panel(table, title="Findings", box=box.ROUNDED))


def render_security(data: dict[str, Any]) -> None:
    console.print(build_security_renderable(data))
