from __future__ import annotations

import time
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT
from bs.collectors.ssh import collect_ssh


console = Console()


def _geo_label(item: dict[str, Any], hostname_key: str) -> str:
    labels = []
    local_geo = item.get("local_geo") or {}
    if local_geo:
        labels.append(f"local: {local_geo.get('organization') or local_geo.get('country') or local_geo.get('reason') or 'located'}")
    if item.get(hostname_key):
        labels.append(item[hostname_key])
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


def _current(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Remote")
    table.add_column("Local")
    table.add_column("PID", justify="right")
    table.add_column("Process")
    table.add_column("Uptime")
    table.add_column("Geo/Host")
    for session in data["current"]:
        remote = f"{session['remote']['address']}:{session['remote']['port'] or '*'}"
        local = f"{session['local']['address']}:{session['local']['port'] or '*'}"
        table.add_row(remote, local, str(session.get("pid") or ""), session.get("process") or "", session.get("uptime") or "", _geo_label(session, "remote_hostname"))
    if not data["current"]:
        table.add_row("none", "", "", "", "", "")
    return Panel(table, title="Current SSH Connections", box=box.ROUNDED)


def _value(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _endpoint(address: str, port: int | str | None) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{port if port is not None else '*'}"


def _host_ips(listening_ips: list[dict[str, Any]]) -> str:
    addresses: list[str] = []
    for item in listening_ips:
        address = item.get("address")
        if isinstance(address, str) and address not in addresses:
            addresses.append(address)
    return ", ".join(addresses) or "none"


def _server(data: dict[str, Any]) -> Panel:
    server = data["server"]
    summary = server["summary"]
    table = Table(show_header=False, box=None, expand=True)
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("Service", f"{server['service']['active']} / {server['service']['enabled']}")
    table.add_row("My IP is", _host_ips(server.get("listening_ips", [])))
    listening_ips = ", ".join(
        f"{_endpoint(item['address'], item['port'])} ({item['interface']})"
        for item in server.get("listening_ips", [])
    ) or "none"
    table.add_row("Listening IPs", listening_ips)
    listeners = ", ".join(_endpoint(sock["local"]["address"], sock["local"]["port"]) for sock in server["listeners"]) or "none"
    table.add_row("Listener sockets", listeners)
    for key in (
        "ports",
        "listenaddress",
        "pubkeyauthentication",
        "passwordauthentication",
        "permitrootlogin",
        "kbdinteractiveauthentication",
        "authenticationmethods",
        "allowusers",
        "allowgroups",
        "denyusers",
        "denygroups",
        "x11forwarding",
        "allowtcpforwarding",
        "allowagentforwarding",
        "loglevel",
    ):
        table.add_row(key, _value(summary.get(key)))
    return Panel(table, title="SSH Server", box=box.ROUNDED)


def _source_restrictions(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("File")
    table.add_column("Rule")
    for rule in data["server"]["source_restrictions"]:
        table.add_row(rule["file"], rule["rule"])
    if not data["server"]["source_restrictions"]:
        table.add_row("n/a", "No AllowUsers/DenyUsers/Match Address rules found in sshd config")
    return Panel(table, title="SSH Source/User Restrictions", box=box.ROUNDED)


def _firewall_rules(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Source")
    table.add_column("Rule")
    for rule in data["server"].get("firewall_rules", []):
        table.add_row(rule["source"], rule["rule"])
    if not data["server"].get("firewall_rules"):
        table.add_row("n/a", "No nftables/iptables SSH port rules found")
    return Panel(table, title="Firewall SSH Rules", box=box.ROUNDED)


def _authorized_keys(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("User")
    table.add_column("Type")
    table.add_column("Fingerprint")
    table.add_column("Comment")
    table.add_column("File")
    for key in data["server"]["authorized_keys"]:
        if not key.get("readable"):
            table.add_row(key["user"], "unreadable", key.get("reason", ""), "", key["path"])
            continue
        if key.get("empty"):
            table.add_row(key["user"], "none", "authorized_keys is empty", "", key["path"])
            continue
        table.add_row(
            key["user"],
            key.get("type", "invalid"),
            key.get("fingerprint") or "n/a",
            key.get("comment") or "",
            f"{key['path']}:{key.get('line', '')}",
        )
    if not data["server"]["authorized_keys"]:
        table.add_row("n/a", "none found", "", "", "")
    return Panel(table, title="Authorized SSH Keys", box=box.ROUNDED)


def _history(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time")
    table.add_column("Type")
    table.add_column("User")
    table.add_column("IP")
    table.add_column("Method")
    table.add_column("Geo/Host")
    for event in data["history"][-20:]:
        table.add_row(event["time"], event["type"], event["user"], event["ip"] or "", event.get("method") or "", _geo_label(event, "hostname"))
    if not data["history"]:
        table.add_row("n/a", "no history requested/found", "", "", "", "")
    return Panel(table, title="Recent SSH Events", box=box.ROUNDED)


def build_ssh_renderable(data: dict[str, Any]) -> Group:
    header = "B-Suite SSH"
    if data.get("geo_database"):
        header = f"{header}\nGeoLite DB: {data['geo_database']}"
    return Group(header, _server(data), _source_restrictions(data), _firewall_rules(data), _authorized_keys(data), _current(data), _history(data))


def render_ssh(data: dict[str, Any]) -> None:
    console.print(build_ssh_renderable(data))


def render_ssh_watch(
    interval: float = 2.0,
    include_history: bool = False,
    lines: int = 80,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
) -> None:
    with Live(
        build_ssh_renderable(collect_ssh(include_history=include_history, lines=lines, resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit)),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        while True:
            live.update(build_ssh_renderable(collect_ssh(include_history=include_history, lines=lines, resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit)))
            time.sleep(interval)
