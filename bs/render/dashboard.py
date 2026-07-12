from __future__ import annotations

import datetime as dt
import time
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bs.config import MonitorConfig
from bs.collectors.common import bytes_to_human
from bs.collectors.dashboard import collect_dashboard
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT
from bs.collectors.mcp import collect_mcp
from bs.collectors.status import collect_status


console = Console()


def _bar(percent: float, width: int = 24) -> str:
    filled = int((max(0.0, min(percent, 100.0)) / 100.0) * width)
    return "█" * filled + "░" * (width - filled)


def _host_panel(data: dict[str, Any]) -> Panel:
    host = data["host"]
    timestamp = dt.datetime.fromtimestamp(host["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    loads = " ".join(f"{item:.2f}" for item in host.get("loadavg", [])) or "n/a"
    table = Table.grid(expand=True)
    table.add_column(ratio=1)
    table.add_column(ratio=1)
    table.add_row("Host", f"[bold]{host['hostname']}[/bold]")
    table.add_row("OS", host["os"])
    table.add_row("Kernel", f"{host['kernel']} ({host['machine']})")
    table.add_row("Uptime", host["uptime"])
    table.add_row("Load", loads)
    table.add_row("Updated", timestamp)
    return Panel(table, title="System", box=box.ROUNDED)


def _cpu_memory_panel(data: dict[str, Any]) -> Panel:
    cpu = data["cpu"]
    memory = data["memory"]
    ram = memory["ram"]
    swap = memory["swap"]

    table = Table.grid(expand=True)
    table.add_column(ratio=1)
    table.add_column(ratio=3)
    table.add_column(justify="right")
    table.add_row("CPU", f"[cyan]{_bar(cpu['usage_percent'])}[/cyan]", f"{cpu['usage_percent']:.1f}%")
    table.add_row(
        "RAM",
        f"[green]{_bar(ram['used_percent'])}[/green]",
        f"{bytes_to_human(ram['used'])} / {bytes_to_human(ram['total'])}  {ram['used_percent']:.1f}%",
    )
    table.add_row(
        "Swap",
        f"[yellow]{_bar(swap['used_percent'])}[/yellow]",
        f"{bytes_to_human(swap['used'])} / {bytes_to_human(swap['total'])}  {swap['used_percent']:.1f}%",
    )
    table.add_row("Cores", str(cpu["logical_cores"]), "")
    return Panel(table, title="CPU & Memory", box=box.ROUNDED)


def _thermal_power_panel(data: dict[str, Any]) -> Panel:
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Metric")
    table.add_column("Value")
    thermal = data["thermal"]
    if thermal["available"]:
        for item in thermal["temperatures"]:
            table.add_row(f"Temp {item['label']}", f"{item['temperature_c']:.1f} C")
    else:
        table.add_row("Temperature", f"[dim]{thermal['reason']}[/dim]")
    for fan in thermal.get("fans", []):
        pwm = f", pwm {fan['pwm']}" if fan.get("pwm") is not None else ""
        table.add_row(f"Fan {fan['label']}", f"{fan['rpm']} RPM{pwm}")

    power = data["power"]
    throttled = power.get("throttled")
    if throttled:
        state = "active" if throttled["active"] else "clear"
        flags = ", ".join(throttled["flags"]) if throttled["flags"] else "none"
        style = "red" if throttled["active"] else "green"
        table.add_row("Throttling", f"[{style}]{state}[/{style}] ({throttled['raw']})")
        table.add_row("Power Flags", flags)
    else:
        table.add_row("Power", f"[dim]{power['reason']}[/dim]")
    for rail, value in power.get("volts", {}).items():
        table.add_row(f"Voltage {rail}", value)
    return Panel(table, title="Thermals & Power", box=box.ROUNDED)


def _disk_table(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Device")
    table.add_column("Mount")
    table.add_column("FS")
    table.add_column("Use", justify="right")
    table.add_column("Used / Total", justify="right")
    for disk in data["disks"]:
        table.add_row(
            disk["device"],
            disk["mountpoint"],
            disk["fs_type"],
            f"{disk['used_percent']:.1f}%",
            f"{bytes_to_human(disk['used'])} / {bytes_to_human(disk['total'])}",
        )
    if not data["disks"]:
        table.add_row("n/a", "n/a", "n/a", "n/a", "n/a")
    return Panel(table, title="Disks", box=box.ROUNDED)


def _process_table(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("PID", justify="right")
    table.add_column("CPU", justify="right")
    table.add_column("RSS", justify="right")
    table.add_column("Command", overflow="fold")
    for proc in data["processes"]["top_cpu"]:
        table.add_row(
            str(proc["pid"]),
            f"{proc['cpu_percent']:.1f}%",
            bytes_to_human(proc["rss"]),
            proc["command"],
        )
    return Panel(table, title=f"Top CPU Processes ({data['processes']['count']} total)", box=box.ROUNDED)


def _network_table(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Interface")
    table.add_column("RX", justify="right")
    table.add_column("TX", justify="right")
    for iface in data["network"]["interfaces"]:
        table.add_row(iface["interface"], bytes_to_human(iface["rx_bytes"]), bytes_to_human(iface["tx_bytes"]))
    if not data["network"]["interfaces"]:
        table.add_row("n/a", "n/a", "n/a")
    return Panel(table, title="Network", box=box.ROUNDED)


def _mcp_panel() -> Panel:
    data = collect_mcp(lines=12, resolve=True, geo=True)
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Metric")
    table.add_column("Value")
    for role, service in data["services"].items():
        pid = service.get("main_pid") or "n/a"
        uptime = service.get("process", {}).get("uptime", "n/a")
        table.add_row(f"{role} service", f"{service['active_state']}/{service['sub_state']} pid {pid} uptime {uptime}")
    target = data.get("target", {})
    table.add_row("MCP Target", f"{target.get('kind') or 'unknown'} via {target.get('transport') or 'unknown'}")
    listeners = ", ".join(f"{item['role']} {item['local']['address']}:{item['local']['port']}" for item in data["listeners"]) or "none"
    table.add_row("Listeners", listeners)
    outbound_items = []
    for item in data["tunnel_outbound"]:
        peer = f"{item['peer']['address']}:{item['peer']['port']}"
        details = []
        if item.get("peer_hostname"):
            details.append(item["peer_hostname"])
        geo = item.get("geo") or {}
        if geo.get("organization"):
            details.append(str(geo["organization"]))
        elif geo.get("country") or geo.get("country_name"):
            details.append(str(geo.get("country") or geo.get("country_name")))
        outbound_items.append(f"{peer} ({', '.join(details)})" if details else peer)
    outbound = ", ".join(outbound_items) or "none"
    table.add_row("Tunnel Outbound", outbound)
    table.add_row("Recent Warnings", str(data["journal"]["counts"]["warning"]))
    table.add_row("Recent Errors", str(data["journal"]["counts"]["error"]))
    if data["warnings"]:
        table.add_row("Status", "; ".join(data["warnings"][:2]))
    else:
        table.add_row("Status", "healthy")
    return Panel(table, title="MCP & Tunnel", box=box.ROUNDED)


def _mount_table(data: dict[str, Any]) -> Panel:
    skip_fs = {
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "fusectl",
        "mqueue",
        "proc",
        "pstore",
        "securityfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    }
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Device")
    table.add_column("Mount")
    table.add_column("FS")
    table.add_column("Mode")
    for mount in data["mounts"]:
        if mount["fs_type"] in skip_fs:
            continue
        table.add_row(
            mount["device"],
            mount["mountpoint"],
            mount["fs_type"],
            "rw" if mount["writable"] else "ro",
        )
    return Panel(table, title="Mounts", box=box.ROUNDED)


def build_status_renderable(data: dict[str, Any], show_all: bool = True) -> Group:
    title = Text("B-Suite Status", style="bold white")
    panels = [
        _host_panel(data),
        _cpu_memory_panel(data),
        _thermal_power_panel(data),
        _disk_table(data),
        _process_table(data),
        _network_table(data),
    ]
    if show_all:
        panels.append(_mcp_panel())
        panels.append(_mount_table(data))
    return Group(title, *panels)


def render_status(data: dict[str, Any], show_all: bool = True) -> None:
    console.print(build_status_renderable(data, show_all=show_all))


def render_watch(interval: float = 2.0) -> None:
    with Live(build_status_renderable(collect_status()), console=console, refresh_per_second=4, screen=True) as live:
        while True:
            live.update(build_status_renderable(collect_status()))
            time.sleep(interval)


def _summary_panel(title: str, rows: list[tuple[str, str]], border_style: str) -> Panel:
    table = Table.grid(expand=True)
    table.add_column(overflow="ellipsis", no_wrap=True)
    for label, value in rows:
        table.add_row(Text.assemble((f"{label:<15} ", "dim"), (value, "")))
    return Panel(table, title=title, box=box.ROUNDED, border_style=border_style)


def _remote_identity(item: dict[str, Any]) -> str:
    labels = []
    hostname = item.get("peer_hostname") or item.get("remote_hostname")
    if hostname:
        labels.append(str(hostname))
    geo = item.get("geo") or {}
    if geo.get("organization"):
        labels.append(str(geo["organization"]))
    elif geo.get("country") or geo.get("country_name"):
        labels.append(str(geo.get("country") or geo.get("country_name")))
    return " | ".join(labels)


def _location_label(location: dict[str, Any] | None) -> str:
    if not location:
        return "location unavailable"
    return str(location.get("organization") or location.get("country") or location.get("country_name") or location.get("reason") or "located")


def _compact(value: str, limit: int = 72) -> str:
    return value if len(value) <= limit else f"{value[: limit - 3]}..."


def _endpoint(address: Any, port: Any = None) -> str:
    host = str(address or "unknown")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}" if port is not None else host


def _unique_addresses(items: list[dict[str, Any]], key: str = "address") -> list[str]:
    addresses: list[str] = []
    for item in items:
        address = item.get(key)
        if isinstance(address, str) and address not in addresses:
            addresses.append(address)
    return addresses


def _dash_status_panel(data: dict[str, Any]) -> Panel:
    host = data["host"]
    ram = data["memory"]["ram"]
    swap = data["memory"]["swap"]
    root = next((disk for disk in data["disks"] if disk.get("mountpoint") == "/"), None)
    thermal = data["thermal"]
    temperature = "n/a"
    if thermal.get("available") and thermal.get("temperatures"):
        temperature = f"{thermal['temperatures'][0]['temperature_c']:.1f} C"
    if thermal.get("fans"):
        temperature = f"{temperature} | fan {thermal['fans'][0]['rpm']} RPM"
    loads = ", ".join(f"{item:.2f}" for item in host.get("loadavg", [])) or "n/a"
    return _summary_panel(
        "Status",
        [
            ("Host", f"{host['hostname']} | {host['os']}"),
            ("Uptime", str(host["uptime"])),
            ("Load", loads),
            ("CPU", f"{data['cpu']['usage_percent']:.1f}% | {data['cpu']['logical_cores']} cores"),
            ("Memory", f"{ram['used_percent']:.1f}% | {bytes_to_human(ram['used'])} / {bytes_to_human(ram['total'])}"),
            ("Swap", f"{swap['used_percent']:.1f}% | {bytes_to_human(swap['used'])} / {bytes_to_human(swap['total'])}"),
            ("Root disk", f"{root['used_percent']:.1f}% | {bytes_to_human(root['used'])} / {bytes_to_human(root['total'])}" if root else "n/a"),
            ("Thermals", temperature),
        ],
        "cyan",
    )


def _dash_network_panel(data: dict[str, Any]) -> Panel:
    interfaces = [item for item in data["interfaces"] if item.get("state") == "UP"]
    traffic = {item["interface"]: item for item in data["traffic"]}
    addresses = []
    address_locations = []
    for interface in interfaces:
        for address in interface.get("addresses", []):
            if address.get("local") and address.get("scope") == "global":
                addresses.append(str(address["local"]))
                address_locations.append(f"{interface['name']}: {_location_label(address.get('geo'))}")
    default = next((route for route in data["routes"] if route.get("dst") == "default"), None)
    remote = next((item for item in data["established"] if item["peer"].get("address")), None)
    remote_label = "none"
    if remote:
        remote_label = f"{remote['peer']['address']}:{remote['peer']['port'] or '*'}"
        identity = _remote_identity(remote)
        if identity:
            remote_label = f"{remote_label} ({identity})"
    rate_labels = []
    for interface in interfaces:
        counters = traffic.get(interface["name"], {})
        rate_labels.append(f"{interface['name']} rx {bytes_to_human(counters.get('rx_bytes_per_sec'))}/s tx {bytes_to_human(counters.get('tx_bytes_per_sec'))}/s")
    budget = data.get("lookup_budget", {})
    geo_db = data.get("geo_database") or "not found"
    dns = [str(item) for item in data["dns"]]
    return _summary_panel(
        "Network",
        [
            ("My IP is", ", ".join(addresses) or "none"),
            ("Gateway IP", str(default.get("gateway")) if default else "n/a"),
            ("DNS 1", dns[0] if dns else "n/a"),
            ("DNS 2", dns[1] if len(dns) > 1 else "n/a"),
            ("Traffic", ", ".join(rate_labels) or "n/a"),
            ("Sockets", f"{len(data['established'])} established | {len(data['listening'])} listening"),
            ("Remote IP", _compact(remote_label)),
            ("IP location", _compact(", ".join(address_locations) or "unavailable")),
            ("Enrichment", f"GeoLite {geo_db} | {budget.get('used', 0)} lookups"),
        ],
        "green",
    )


def _dash_ssh_panel(data: dict[str, Any]) -> Panel:
    server = data["server"]
    my_ips = ", ".join(_unique_addresses(server.get("listening_ips", []))) or "none"
    listening_ips = ", ".join(_endpoint(item.get("address"), item.get("port")) for item in server.get("listening_ips", [])) or "none"
    listeners = ", ".join(_endpoint(item["local"].get("address"), item["local"].get("port")) for item in server.get("listeners", [])) or "none"
    session_label = "none"
    if data["current"]:
        session = data["current"][0]
        session_label = f"{session['remote']['address']}:{session['remote']['port'] or '*'}"
        identity = _remote_identity(session)
        if identity:
            session_label = f"{session_label} ({identity})"
    return _summary_panel(
        "SSH",
        [
            ("My IP is", my_ips),
            ("Service", f"{server['service']['active']} / {server['service']['enabled']}"),
            ("SSH endpoint", _compact(listening_ips)),
            ("Wildcard binds", _compact(listeners)),
            ("Sessions", str(len(data["current"]))),
            ("Client IP", _compact(session_label)),
            ("Authentication", f"keys {server['summary'].get('pubkeyauthentication') or 'n/a'} | password {server['summary'].get('passwordauthentication') or 'n/a'} | root {server['summary'].get('permitrootlogin') or 'n/a'}"),
            ("Restrictions", f"{len(server['source_restrictions'])} source | {len(server['firewall_rules'])} firewall"),
            ("Authorized keys", str(len(server["authorized_keys"]))),
        ],
        "magenta",
    )


def _dash_mcp_panel(data: dict[str, Any]) -> Panel:
    mcp_service = data["services"].get("mcp", {})
    tunnel_service = data["services"].get("tunnel", {})
    mode = data.get("mode", {}).get("result", {})
    usage = data.get("usage", {})
    usage_provider = str(usage.get("provider_label") or "Usage")
    target_flags = data["target"].get("security_flags", {})
    target_capabilities = "unavailable"
    if target_flags.get("available"):
        target_capabilities = f"W:{'on' if target_flags.get('write_tools_enabled') else 'off'} S:{'on' if target_flags.get('secret_tools_enabled') else 'off'}"
    listeners = {item.get("role"): item for item in data.get("listeners", [])}
    mcp_listener = listeners.get("mcp", {}).get("local", {})
    tunnel_listener = listeners.get("tunnel-health", {}).get("local", {})
    tunnel_peer = next(iter(data.get("tunnel_outbound", [])), {}).get("peer", {})
    windows = usage.get("windows", {})
    limit_label = "not configured" if usage.get("disabled") else "usage unavailable"
    if usage.get("available"):
        five_hour = windows.get("5h", {}).get("remaining_percent")
        weekly = windows.get("weekly", {}).get("remaining_percent")
        limit_label = f"5h {five_hour:g}% | week {weekly:g}%" if isinstance(five_hour, (int, float)) and isinstance(weekly, (int, float)) else "window data unavailable"
    token_count = usage.get("latest_daily_tokens")
    token_label = f"{token_count / 1_000_000:.1f}M today" if isinstance(token_count, int) else "daily tokens unavailable"
    metrics = data["probes"].get("tunnel_metrics", {}).get("metrics", {})
    metric_activity = "telemetry unavailable"
    if metrics:
        metric_activity = f"{metrics['commands']} total | {metrics['failed']} errors"
    return _summary_panel(
        "MCP & Tunnel",
        [
            ("MCP IP", f"{'up' if mcp_service.get('active_state') == 'active' else 'down'} | {_endpoint(mcp_listener.get('address'), mcp_listener.get('port'))}" if mcp_listener else "unavailable"),
            ("HTTP mode", f"{mode.get('mode') or 'unknown'} | {len(mode.get('active_tools') or [])} tools"),
            ("HTTP tools", f"S:{'on' if mode.get('secret_tools_enabled') else 'off'} W:{'on' if mode.get('write_tools_enabled') else 'off'}"),
            ("Tunnel IP", f"{'up' if tunnel_service.get('active_state') == 'active' else 'down'} | {_endpoint(tunnel_listener.get('address'), tunnel_listener.get('port'))}" if tunnel_listener else "unavailable"),
            ("Tunnel peer", _endpoint(tunnel_peer.get("address"), tunnel_peer.get("port")) if tunnel_peer else "unavailable"),
            ("Target", f"{data['target'].get('kind') or 'unknown'} | {target_capabilities}"),
            ("Usage", f"{usage_provider}: {limit_label}"),
            ("Credits/tokens", f"{usage.get('reset_credits_available', 'n/a')} | {token_label}"),
            ("Commands", metric_activity),
        ],
        "yellow",
    )


def build_dash_renderable(data: dict[str, Any]) -> Layout:
    layout = Layout()
    layout.split_column(Layout(name="header", size=3), Layout(name="top"), Layout(name="bottom"))
    layout["top"].split_row(Layout(name="status"), Layout(name="network"))
    layout["bottom"].split_row(Layout(name="ssh"), Layout(name="mcp"))
    host = data["status"]["host"]
    updated = dt.datetime.fromtimestamp(host["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    layout["header"].update(
        Panel(
            Text("B-Suite Dashboard", style="bold cyan"),
            subtitle=f"{host['hostname']} | updated {updated} | Status | Network | SSH | MCP",
            box=box.ROUNDED,
            border_style="bright_blue",
        )
    )
    layout["status"].update(_dash_status_panel(data["status"]))
    layout["network"].update(_dash_network_panel(data["network"]))
    layout["ssh"].update(_dash_ssh_panel(data["ssh"]))
    layout["mcp"].update(_dash_mcp_panel(data["mcp"]))
    return layout


def render_dash(data: dict[str, Any]) -> None:
    console.print(build_dash_renderable(data))


def render_dash_watch(
    interval: float = 2.0,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
    monitor_config: MonitorConfig | None = None,
    monitor_config_source: str | None = None,
) -> None:
    with Live(
        build_dash_renderable(collect_dashboard(resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit, monitor_config=monitor_config, monitor_config_source=monitor_config_source)),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        while True:
            time.sleep(interval)
            live.update(build_dash_renderable(collect_dashboard(resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit, monitor_config=monitor_config, monitor_config_source=monitor_config_source)))
