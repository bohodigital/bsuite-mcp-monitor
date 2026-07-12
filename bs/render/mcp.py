from __future__ import annotations

import datetime as dt
import time
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from bs.config import MonitorConfig
from bs.collectors.common import bytes_to_human
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT
from bs.collectors.mcp import collect_mcp


console = Console()


def _geo_label(item: dict[str, Any]) -> str:
    labels = []
    local_geo = item.get("local_geo") or {}
    if local_geo:
        labels.append(f"local: {local_geo.get('organization') or local_geo.get('country') or local_geo.get('reason') or 'located'}")
    if item.get("peer_hostname"):
        labels.append(item["peer_hostname"])
    geo = item.get("geo")
    if not geo:
        return " | ".join(labels)
    if not geo.get("available"):
        labels.append(geo.get("reason") or "Geo unavailable")
        return " | ".join(labels)
    parts = [geo.get("city"), geo.get("region"), geo.get("country") or geo.get("country_name")]
    label = ", ".join(str(part) for part in parts if part)
    if label:
        labels.append(label)
        return " | ".join(labels)
    if geo.get("organization"):
        labels.append(str(geo["organization"]))
        return " | ".join(labels)
    labels.append("Geo hit")
    return " | ".join(labels)


def _service_panel(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Role")
    table.add_column("Unit")
    table.add_column("State")
    table.add_column("PID", justify="right")
    table.add_column("Uptime")
    table.add_column("RSS", justify="right")
    table.add_column("Restarts", justify="right")
    table.add_column("Capabilities")
    for role, service in data["services"].items():
        process = service.get("process", {})
        flags = service.get("security_flags", {})
        capabilities = ", ".join(name for name, enabled in (("write", flags.get("write_tools_enabled")), ("secret", flags.get("secret_tools_enabled"))) if enabled) or "none"
        table.add_row(
            role,
            service["unit"],
            f"{service['active_state']}/{service['sub_state']}",
            str(service.get("main_pid") or ""),
            process.get("uptime", "n/a"),
            bytes_to_human(process.get("rss")),
            str(service.get("n_restarts", 0)),
            capabilities,
        )
    return Panel(table, title="Services", box=box.ROUNDED)


def _runtime_panel(data: dict[str, Any]) -> Panel:
    mode_probe = data.get("mode", {})
    mode = mode_probe.get("result", {}) if mode_probe.get("ok") else {}
    health = data.get("probes", {}).get("mcp_health", {}).get("json") or {}
    target = data.get("target", {})
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("HTTP health", "healthy" if health.get("ok") else "unavailable")
    table.add_row("Runtime mode", str(mode.get("mode") or "unknown"))
    table.add_row("Active tools", str(len(mode.get("active_tools") or [])))
    table.add_row("Secret tools", "enabled" if mode.get("secret_tools_enabled") else "disabled")
    table.add_row("Write tools", "enabled" if mode.get("write_tools_enabled") else "disabled")
    table.add_row("Workspace", f"{health.get('tracked_files', 'n/a')} tracked files; knowledge DB {'present' if health.get('knowledge_db_exists') else 'missing'}")
    table.add_row("Tunnel target", f"{target.get('kind') or 'unknown'} via {target.get('transport') or 'unknown'}")
    target_flags = target.get("security_flags", {})
    target_capabilities = "unavailable"
    if target_flags.get("available"):
        target_capabilities = f"write {'enabled' if target_flags.get('write_tools_enabled') else 'disabled'}; secret {'enabled' if target_flags.get('secret_tools_enabled') else 'disabled'}"
    table.add_row("Tunnel target tools", target_capabilities)
    table.add_row("Profile", str(target.get("profile") or "unknown"))
    return Panel(table, title="MCP Runtime", box=box.ROUNDED)


def _reset_time(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "unknown"
    return dt.datetime.fromtimestamp(value).astimezone().strftime("%Y-%m-%d %H:%M")


def _usage_panel(data: dict[str, Any]) -> Panel:
    usage = data.get("usage", {})
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Metric")
    table.add_column("Value")
    if not usage.get("available"):
        table.add_row("Status", "not configured" if usage.get("disabled") else "unavailable")
        table.add_row("Reason", str(usage.get("error") or usage.get("http_mcp_error") or "unknown"))
        return Panel(table, title="Codex Usage Limits", box=box.ROUNDED, border_style="red")
    windows = usage.get("windows", {})
    for name in ("5h", "weekly"):
        window = windows.get(name, {})
        remaining = window.get("remaining_percent")
        value = f"{remaining:g}% remaining" if isinstance(remaining, (int, float)) else "unavailable"
        table.add_row(name, f"{value}; resets {_reset_time(window.get('resets_at'))}")
    table.add_row("Plan", str(usage.get("plan_type") or "unknown"))
    table.add_row("Reset credits", str(usage.get("reset_credits_available") if usage.get("reset_credits_available") is not None else "unknown"))
    latest_tokens = usage.get("latest_daily_tokens")
    latest_label = f"{latest_tokens:,}" if isinstance(latest_tokens, int) else "unavailable"
    table.add_row("Daily tokens", f"{latest_label} ({usage.get('latest_daily_date') or 'unknown date'})")
    table.add_row("Source", str(usage.get("source") or "unknown"))
    if usage.get("http_mcp_error"):
        table.add_row("HTTP source", str(usage["http_mcp_error"]))
    return Panel(table, title="Codex Usage Limits", box=box.ROUNDED, border_style="green" if not usage.get("warnings") else "yellow")


def _listeners_panel(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Role")
    table.add_column("Bind")
    table.add_column("PID", justify="right")
    table.add_column("Process")
    table.add_column("Safety")
    for item in data["listeners"]:
        bind = f"{item['local']['address']}:{item['local']['port']}"
        safety = item.get("warning") or "loopback-only"
        table.add_row(item["role"], bind, str(item.get("pid") or ""), item.get("process") or "", safety)
    if not data["listeners"]:
        table.add_row("n/a", "none", "", "", "")
    return Panel(table, title="Listeners", box=box.ROUNDED)


def _probe_detail(probe: dict[str, Any]) -> str:
    metrics = probe.get("metrics")
    if metrics:
        average = metrics.get("average_latency_ms")
        latency = f", avg {average} ms" if average is not None else ""
        return f"{metrics['successful']}/{metrics['commands']} successful, {metrics['failed']} failed{latency}"
    detail = str(probe.get("error") or probe.get("body_preview", ""))
    if detail.lstrip().lower().startswith("<!doctype html"):
        return "HTML health page"
    return " ".join(detail.split())[:120]


def _probes_panel(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Probe")
    table.add_column("OK")
    table.add_column("Status")
    table.add_column("Latency")
    table.add_column("Detail")
    for name, probe in data["probes"].items():
        if probe.get("skipped"):
            table.add_row(name, "skip", "", "", probe.get("reason", "skipped"))
            continue
        table.add_row(
            name,
            "yes" if probe.get("ok") else "no",
            str(probe.get("status", "")),
            f"{probe['latency_ms']} ms" if probe.get("latency_ms") is not None else "",
            _probe_detail(probe),
        )
    return Panel(table, title="Health Probes", box=box.ROUNDED)


def _connections_panel(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Kind")
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("PID", justify="right")
    table.add_column("Process")
    table.add_column("Geo/ASN")
    rows = []
    for item in data["local_connections"]:
        rows.append(("local", item))
    for item in data["tunnel_outbound"]:
        rows.append(("outbound", item))
    for kind, item in rows:
        local = f"{item['local']['address']}:{item['local']['port'] or '*'}"
        peer = f"{item['peer']['address']}:{item['peer']['port'] or '*'}"
        table.add_row(kind, local, peer, str(item.get("pid") or ""), item.get("process") or "", _geo_label(item))
    if not rows:
        table.add_row("n/a", "none", "", "", "", "")
    return Panel(table, title="Connections", box=box.ROUNDED)


def _tunnel_panel(data: dict[str, Any]) -> Panel:
    metrics = data.get("probes", {}).get("tunnel_metrics", {}).get("metrics", {})
    outbound = data.get("tunnel_outbound", [])
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Outbound TLS", str(len(outbound)))
    table.add_row("Commands", str(metrics.get("commands", "unavailable")))
    table.add_row("Successful", str(metrics.get("successful", "unavailable")))
    table.add_row("Failed", str(metrics.get("failed", "unavailable")))
    average = metrics.get("average_latency_ms")
    table.add_row("Average latency", f"{average} ms" if average is not None else "unavailable")
    statuses = metrics.get("status_counts") or {}
    table.add_row("Status counts", ", ".join(f"{status}: {count}" for status, count in sorted(statuses.items())) or "unavailable")
    return Panel(table, title="Tunnel Command Telemetry", box=box.ROUNDED)


def _activity_panel(data: dict[str, Any]) -> Panel:
    counts = data["journal"]["counts"]
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Level")
    table.add_column("Count", justify="right")
    table.add_row("errors", str(counts["error"]))
    table.add_row("warnings", str(counts["warning"]))
    table.add_row("requests", str(counts["requests"]))
    table.add_row("info", str(counts["info"]))

    recent = data["journal"]["entries"][-5:]
    for entry in recent:
        message = str(entry.get("message", ""))[:110]
        table.add_row(entry.get("level", "info"), "", message)
    return Panel(table, title="Recent Activity", box=box.ROUNDED)


def _warnings_panel(data: dict[str, Any]) -> Panel | None:
    if not data["warnings"]:
        return None
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Warning")
    for warning in data["warnings"]:
        table.add_row(warning)
    return Panel(table, title="Warnings", box=box.ROUNDED, border_style="yellow")


def build_mcp_renderable(data: dict[str, Any]) -> Group:
    profile = data.get("profile", {})
    header = f"B-Suite MCP Monitor: {profile.get('name') or 'default'}"
    if data.get("geo_database"):
        header = f"{header}\nGeoLite DB: {data['geo_database']}"
    panels = [_service_panel(data), _runtime_panel(data), _usage_panel(data), _listeners_panel(data), _probes_panel(data), _tunnel_panel(data), _connections_panel(data), _activity_panel(data)]
    warnings = _warnings_panel(data)
    if warnings:
        panels.insert(0, warnings)
    return Group(header, *panels)


def render_mcp(data: dict[str, Any]) -> None:
    console.print(build_mcp_renderable(data))


def render_mcp_watch(
    interval: float = 2.0,
    lines: int = 40,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
    config: MonitorConfig | None = None,
    config_source: str | None = None,
) -> None:
    with Live(
        build_mcp_renderable(collect_mcp(lines=lines, resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit, config=config, config_source=config_source)),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        while True:
            live.update(build_mcp_renderable(collect_mcp(lines=lines, resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit, config=config, config_source=config_source)))
            time.sleep(interval)
