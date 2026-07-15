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
        "maxauthtries",
        "logingracetime",
        "maxstartups",
        "persourcemaxstartups",
        "persourcepenalties",
        "persourcenetblocksize",
        "maxsessions",
        "allowusers",
        "allowgroups",
        "denyusers",
        "denygroups",
        "x11forwarding",
        "allowtcpforwarding",
        "allowagentforwarding",
        "disableforwarding",
        "gatewayports",
        "permituserenvironment",
        "permitemptypasswords",
        "loglevel",
    ):
        table.add_row(key, _value(summary.get(key)))
    return Panel(table, title="SSH Server", box=box.ROUNDED)


def _attack_summary(data: dict[str, Any]) -> Panel:
    attacks = data["attacks"]
    if not attacks.get("available"):
        return Panel(f"[yellow]{attacks.get('reason') or 'unavailable'}[/yellow]", title="SSH Attack Summary", box=box.ROUNDED)

    counts = attacks["counts"]
    level = attacks["level"]
    style = {"clear": "green", "guarded": "yellow", "elevated": "dark_orange", "high": "red"}.get(level, "yellow")
    table = Table.grid(expand=True)
    table.add_column(ratio=1)
    table.add_column(ratio=1)
    table.add_row("Assessment", f"[{style}][bold]{level.upper()}[/bold][/{style}] over last {attacks['window_hours']}h")
    table.add_row("Failed authentication", f"[{style}]{counts['failed']}[/{style}]")
    table.add_row("Invalid users", str(counts["invalid_user"]))
    table.add_row("Pre-auth disconnects", str(counts["preauth"]))
    table.add_row("Daemon source penalties", str(counts["penalty"]))
    table.add_row("Transport-only events", str(counts["transport"]))
    table.add_row("Accepted logins", str(counts["accepted"]))
    table.add_row("Observed window", f"{attacks.get('first_seen') or 'n/a'} to {attacks.get('last_seen') or 'n/a'}")
    return Panel(table, title="SSH Attack Summary", subtitle="Journal-derived signals; not proof of compromise", box=box.ROUNDED)


def _attack_sources(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Source")
    table.add_column("Signals", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Invalid", justify="right")
    table.add_column("Penalty", justify="right")
    table.add_column("Last Seen")
    table.add_column("Location / Host")
    for source in data["attacks"].get("sources", []):
        table.add_row(
            source["ip"],
            str(source["signals"]),
            str(source["failed"]),
            str(source["invalid_user"]),
            str(source["penalty"]),
            source["last_seen"],
            _geo_label(source, "hostname"),
        )
    if not data["attacks"].get("sources"):
        table.add_row("none", "", "", "", "", "", "")
    return Panel(table, title="Top SSH Pressure Sources", subtitle="Top 12 by journal signal count; pre-auth signals are context, not attribution", box=box.ROUNDED)


def _recent_threats(data: dict[str, Any]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time")
    table.add_column("Signal")
    table.add_column("User")
    table.add_column("IP")
    table.add_column("Detail")
    for event in data["attacks"].get("recent", []):
        table.add_row(event["time"], event["type"], event.get("user") or "-", event.get("ip") or "-", event["raw"].split(": ", 1)[-1])
    if not data["attacks"].get("recent"):
        table.add_row("none", "", "", "", "No recent non-accepted SSH signals")
    return Panel(table, title="Latest SSH Threat Signals", box=box.ROUNDED)


def _baseline(data: dict[str, Any]) -> Panel | None:
    baseline = data.get("baseline")
    written = data.get("baseline_write")
    if not baseline and not written:
        return None
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("State")
    table.add_column("Detail")
    if written:
        table.add_row("written", written["path"])
    if baseline:
        table.add_row(baseline["status"], baseline["path"])
        for change in baseline.get("changes", [])[:12]:
            table.add_row(change.get("field", "baseline"), str(change.get("observed") or change.get("detail") or "changed"))
    return Panel(table, title="SSH Baseline", subtitle="Expected listener, control, and authorized-key fingerprint state", box=box.ROUNDED)


def _trend(data: dict[str, Any]) -> Panel | None:
    trend = data.get("trend")
    snapshot = data.get("snapshot")
    if not trend and not snapshot:
        return None
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time")
    table.add_column("Level")
    table.add_column("Failed", justify="right")
    table.add_column("Invalid", justify="right")
    table.add_column("Penalties", justify="right")
    if snapshot:
        table.add_row(snapshot["record"]["timestamp"], snapshot["record"].get("level", "unknown"), str(snapshot["record"]["counts"].get("failed", 0)), str(snapshot["record"]["counts"].get("invalid_user", 0)), str(snapshot["record"]["counts"].get("penalty", 0)))
    if trend:
        for record in trend.get("records", [])[-12:]:
            counts = record.get("counts", {})
            table.add_row(record.get("timestamp", "n/a"), record.get("level", "unknown"), str(counts.get("failed", 0)), str(counts.get("invalid_user", 0)), str(counts.get("penalty", 0)))
    return Panel(table, title="SSH Attack Trend", subtitle=(trend or snapshot).get("path", "count-only snapshots"), box=box.ROUNDED)


def _audit(data: dict[str, Any]) -> Panel | None:
    findings = data.get("audit")
    alert = data.get("alert")
    if findings is None and not alert:
        return None
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Recommended action")
    for item in findings or []:
        style = {"high": "red", "medium": "yellow", "low": "cyan"}.get(item["severity"], "")
        table.add_row(f"[{style}]{item['severity']}[/{style}]" if style else item["severity"], item["title"], item["recommendation"])
    if alert:
        table.add_row("alert", alert["status"], alert.get("reason") or f"threshold {alert.get('minimum_level', 'n/a')}")
    if not findings and not alert:
        table.add_row("clear", "No guided findings", "Keep the baseline and snapshots current")
    return Panel(table, title="SSH Audit & Alert", subtitle="Recommendations only; B-Suite does not alter SSH or firewall policy", box=box.ROUNDED)


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
    panels = [_attack_summary(data), _attack_sources(data), _recent_threats(data), _baseline(data), _trend(data), _audit(data), _server(data), _source_restrictions(data), _firewall_rules(data), _authorized_keys(data), _current(data), _history(data)]
    return Group(header, *(panel for panel in panels if panel is not None))


def render_ssh(data: dict[str, Any]) -> None:
    console.print(build_ssh_renderable(data))


def render_ssh_watch(
    interval: float = 2.0,
    include_history: bool = False,
    lines: int = 80,
    attack_hours: int = 24,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
) -> None:
    with Live(
        build_ssh_renderable(collect_ssh(include_history=include_history, lines=lines, attack_hours=attack_hours, resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit)),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        while True:
            live.update(build_ssh_renderable(collect_ssh(include_history=include_history, lines=lines, attack_hours=attack_hours, resolve=resolve, geo=geo, geo_db=geo_db, lookup_limit=lookup_limit)))
            time.sleep(interval)
