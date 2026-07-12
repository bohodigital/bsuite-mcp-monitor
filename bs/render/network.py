from __future__ import annotations

import time
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from bs.collectors.common import bytes_to_human
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT
from bs.collectors.network_detail import collect_network_detail


console = Console()


def _interfaces(data: dict[str, Any]) -> Panel:
    traffic = {item["interface"]: item for item in data["traffic"]}
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Iface")
    table.add_column("State")
    table.add_column("IPv4/IPv6")
    table.add_column("RX", justify="right")
    table.add_column("TX", justify="right")
    table.add_column("RX/s", justify="right")
    table.add_column("TX/s", justify="right")
    for iface in data["interfaces"]:
        addresses = ", ".join(addr["local"] for addr in iface["addresses"] if addr.get("local")) or "n/a"
        counters = traffic.get(iface["name"], {})
        table.add_row(
            iface["name"],
            iface.get("state") or "unknown",
            addresses,
            bytes_to_human(counters.get("rx_bytes")),
            bytes_to_human(counters.get("tx_bytes")),
            bytes_to_human(counters.get("rx_bytes_per_sec")),
            bytes_to_human(counters.get("tx_bytes_per_sec")),
        )
    return Panel(table, title="Interfaces", box=box.ROUNDED)


def _routes_dns(data: dict[str, Any]) -> Panel:
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Key")
    table.add_column("Value")
    defaults = [route for route in data["routes"] if route.get("dst") == "default"]
    if defaults:
        for route in defaults:
            table.add_row("Default route", f"{route.get('dev')} via {route.get('gateway')}")
    else:
        table.add_row("Default route", "n/a")
    table.add_row("DNS", ", ".join(data["dns"]) if data["dns"] else "n/a")
    if data.get("geo_database"):
        table.add_row("GeoLite DB", data["geo_database"])
    return Panel(table, title="Routing & DNS", box=box.ROUNDED)


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
        labels.append(geo.get("reason") or "GeoLite unavailable")
        return " | ".join(labels)
    parts = [geo.get("city"), geo.get("region"), geo.get("country") or geo.get("country_name")]
    label = ", ".join(str(part) for part in parts if part)
    if label:
        labels.append(label)
        return " | ".join(labels)
    if geo.get("organization"):
        labels.append(str(geo["organization"]))
        return " | ".join(labels)
    labels.append("GeoLite hit")
    return " | ".join(labels)


def _sockets(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("PID", justify="right")
    table.add_column("Process")
    table.add_column("Geo/Host")
    for sock in data["sockets"][:30]:
        local = f"{sock['local']['address']}:{sock['local']['port'] or '*'}"
        peer = f"{sock['peer']['address']}:{sock['peer']['port'] or '*'}"
        table.add_row(sock["proto"], sock["state"], local, peer, str(sock.get("pid") or ""), sock.get("process") or "", _geo_label(sock))
    if not data["sockets"]:
        table.add_row("n/a", "n/a", "n/a", "n/a", "", "", "")
    return Panel(table, title="Sockets", box=box.ROUNDED)


def build_network_renderable(data: dict[str, Any]) -> Group:
    return Group("B-Suite Network", _interfaces(data), _routes_dns(data), _sockets(data))


def render_network(data: dict[str, Any]) -> None:
    console.print(build_network_renderable(data))


def render_network_watch(
    interval: float = 2.0,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
) -> None:
    with Live(
        build_network_renderable(collect_network_detail(resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit)),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        while True:
            live.update(build_network_renderable(collect_network_detail(resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit)))
            time.sleep(interval)
