from __future__ import annotations

import time
from typing import Any, Callable

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


console = Console()


def _style(status: str) -> str:
    return {"healthy": "green", "warning": "yellow", "failed": "red", "unknown": "dim"}.get(status, "")


def build_auth_renderable(data: dict[str, Any]) -> Group:
    summary = data["summary"]
    summary_table = Table(show_header=False, box=None, expand=True)
    summary_table.add_column("Metric")
    summary_table.add_column("Value")
    for name in ("healthy", "warning", "failed", "unknown"):
        summary_table.add_row(name.title(), str(summary.get(name, 0)))

    checks = Table(box=box.SIMPLE_HEAVY, expand=True)
    checks.add_column("Status")
    checks.add_column("Name")
    checks.add_column("Provider")
    checks.add_column("Reference")
    checks.add_column("Purpose")
    checks.add_column("Expiry")
    checks.add_column("Detail")
    for item in data["checks"]:
        status = item["status"]
        checks.add_row(f"[{_style(status)}]{status}[/{_style(status)}]", item["name"], item["provider"], item["reference"], item["purpose"], item.get("expires_at") or "unknown", item["detail"])
    if not data["checks"]:
        checks.add_row("unknown", "none", "", "", "Copy auth.example.toml to configure explicit checks.", "", "")
    return Group(f"B-Suite Auth Health: {data['profile']['source']}", Panel(summary_table, title="Summary", box=box.ROUNDED), Panel(checks, title="Credential References", box=box.ROUNDED))


def render_auth(data: dict[str, Any]) -> None:
    console.print(build_auth_renderable(data))


def render_auth_watch(collect: Callable[[], dict[str, Any]], interval: float) -> None:
    with Live(build_auth_renderable(collect()), console=console, refresh_per_second=2, screen=True) as live:
        while True:
            time.sleep(interval)
            live.update(build_auth_renderable(collect()))
