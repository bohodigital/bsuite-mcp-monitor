from __future__ import annotations

import base64
import binascii
import hashlib
import os
import pwd
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bs.collectors.common import read_lines, read_text, run_command
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT, LookupBudget, geo_lookup, reverse_dns
from bs.collectors.geo import find_geo_db
from bs.collectors.network_detail import collect_interfaces, collect_sockets
from bs.collectors.result import meta


_ACCEPT_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_FAIL_RE = re.compile(r"Failed (?P<method>\S+) for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_DISCONNECT_RE = re.compile(r"Disconnected from (invalid user )?(?P<user>\S+ )?(?P<ip>\S+) port (?P<port>\d+)")
_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_PREAUTH_RE = re.compile(
    r"(?P<action>Connection (?:closed|reset)|Disconnected) (?:from|by) "
    r"(?:(?P<state>invalid user|authenticating user) )?(?P<user>\S+ )?(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)(?: \[preauth\])?"
)
_PENALTY_RE = re.compile(r"(?:new |from \[)(?P<ip>[0-9A-Fa-f:.]+)(?:/\d+|\])")
_KEY_TYPES = ("ssh-", "ecdsa-", "sk-")
_JOURNAL_CACHE_TTL_SECONDS = 15.0
_JOURNAL_CACHE: dict[int, tuple[float, str | None]] = {}


def _parse_journal_event(line: str) -> dict[str, Any] | None:
    """Normalize the OpenSSH journal formats used for authentication and abuse signals."""
    event_type = None
    match = _ACCEPT_RE.search(line)
    if match:
        event_type = "accepted"
    else:
        match = _FAIL_RE.search(line)
        if match:
            event_type = "failed"
        else:
            match = _INVALID_USER_RE.search(line)
            if match:
                event_type = "invalid_user"
            else:
                match = _DISCONNECT_RE.search(line)
                if match:
                    event_type = "preauth"
                else:
                    match = _PREAUTH_RE.search(line)
                    if match:
                        event_type = "preauth"
                    else:
                        match = _PENALTY_RE.search(line) if "penalty" in line.lower() else None
                        if match:
                            event_type = "penalty"
                        elif "kex_exchange_identification" in line or "banner exchange" in line.lower():
                            event_type = "transport"
                        else:
                            return None

    data = match.groupdict() if match else {}
    ip = data.get("ip")
    return {
        "time": line.split()[0],
        "type": event_type,
        "user": (data.get("user") or "").strip(),
        "method": data.get("method"),
        "ip": ip,
        "port": int(data["port"]) if data.get("port") else None,
        "raw": line,
    }


def _hostname(ip: str) -> str | None:
    return reverse_dns(ip)


def _connection_uptime(pid: int | None) -> str | None:
    if not pid:
        return None
    output = run_command(["ps", "-o", "etimes=", "-p", str(pid)])
    if not output or not output.strip().isdigit():
        return None
    seconds = int(output.strip())
    hours, rem = divmod(seconds, 3600)
    minutes, _ = divmod(rem, 60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


def _parse_sshd_t() -> dict[str, Any]:
    output = run_command(["sudo", "-n", "sshd", "-T"], timeout=2.0) or run_command(["sshd", "-T"], timeout=2.0)
    config: dict[str, Any] = {"available": False, "values": {}, "reason": "sshd -T unavailable"}
    if not output:
        return config
    values: dict[str, list[str] | str] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        key, _, value = line.partition(" ")
        if key in values:
            existing = values[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                values[key] = [existing, value]
        else:
            values[key] = value
    config.update({"available": True, "values": values, "reason": None})
    return config


def _listening_ips(listeners: list[dict[str, Any]], interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand wildcard SSH sockets to active, globally scoped interface IPs."""
    listening_ips: list[dict[str, Any]] = []
    seen: set[tuple[str, int | str | None]] = set()

    for listener in listeners:
        local = listener["local"]
        address = local["address"]
        port = local["port"]
        if address in {"0.0.0.0", "::", "*"}:
            family = "inet" if address == "0.0.0.0" else "inet6" if address == "::" else None
            for interface in interfaces:
                if interface.get("state") != "UP":
                    continue
                for item in interface.get("addresses", []):
                    if item.get("scope") != "global" or (family and item.get("family") != family):
                        continue
                    ip = item.get("local")
                    if not isinstance(ip, str) or (ip, port) in seen:
                        continue
                    listening_ips.append({"address": ip, "port": port, "interface": interface.get("name")})
                    seen.add((ip, port))
            continue

        if isinstance(address, str) and (address, port) not in seen:
            listening_ips.append({"address": address, "port": port, "interface": None})
            seen.add((address, port))

    return listening_ips


def collect_ssh_server() -> dict[str, Any]:
    active = run_command(["systemctl", "is-active", "ssh"], timeout=1.0)
    enabled = run_command(["systemctl", "is-enabled", "ssh"], timeout=1.0)
    config = _parse_sshd_t()
    values = config.get("values", {})
    listeners = [
        sock
        for sock in collect_sockets(resolve=False, geo=False)
        if sock["state"] == "LISTEN" and sock["local"]["port"] == 22
    ]
    return {
        "service": {
            "active": active or "unknown",
            "enabled": enabled or "unknown",
        },
        "listeners": listeners,
        "listening_ips": _listening_ips(listeners, collect_interfaces()) if listeners else [],
        "config": config,
        "summary": {
            "ports": values.get("port"),
            "listenaddress": values.get("listenaddress"),
            "pubkeyauthentication": values.get("pubkeyauthentication"),
            "passwordauthentication": values.get("passwordauthentication"),
            "permitrootlogin": values.get("permitrootlogin"),
            "kbdinteractiveauthentication": values.get("kbdinteractiveauthentication"),
            "authenticationmethods": values.get("authenticationmethods"),
            "maxauthtries": values.get("maxauthtries"),
            "logingracetime": values.get("logingracetime"),
            "maxstartups": values.get("maxstartups"),
            "persourcemaxstartups": values.get("persourcemaxstartups"),
            "persourcepenalties": values.get("persourcepenalties"),
            "persourcenetblocksize": values.get("persourcenetblocksize"),
            "maxsessions": values.get("maxsessions"),
            "allowusers": values.get("allowusers", "not set"),
            "allowgroups": values.get("allowgroups", "not set"),
            "denyusers": values.get("denyusers", "not set"),
            "denygroups": values.get("denygroups", "not set"),
            "authorizedkeysfile": values.get("authorizedkeysfile"),
            "x11forwarding": values.get("x11forwarding"),
            "allowtcpforwarding": values.get("allowtcpforwarding"),
            "allowagentforwarding": values.get("allowagentforwarding"),
            "disableforwarding": values.get("disableforwarding"),
            "gatewayports": values.get("gatewayports"),
            "permituserenvironment": values.get("permituserenvironment"),
            "permitemptypasswords": values.get("permitemptypasswords"),
            "usedns": values.get("usedns"),
            "loglevel": values.get("loglevel"),
        },
        "source_restrictions": _collect_source_restrictions(),
        "firewall_rules": _collect_firewall_ssh_rules(),
        "authorized_keys": collect_authorized_keys(),
    }


def _collect_source_restrictions() -> list[dict[str, str]]:
    restrictions: list[dict[str, str]] = []
    config_paths = [Path("/etc/ssh/sshd_config")]
    config_paths.extend(sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")))
    for path in config_paths:
        for line in read_lines(path):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if lower.startswith(("match address", "allowusers", "denyusers", "allowgroups", "denygroups")):
                restrictions.append({"file": str(path), "rule": stripped})
    return restrictions


def _collect_firewall_ssh_rules() -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    output = run_command(["sudo", "-n", "nft", "list", "ruleset"], timeout=2.0)
    if output is not None:
        for line in output.splitlines():
            stripped = line.strip()
            if "dport 22" in stripped or "sport 22" in stripped or ". ssh" in stripped:
                rules.append({"source": "nft", "rule": stripped})
        return rules
    output = run_command(["sudo", "-n", "iptables", "-S"], timeout=2.0)
    if output is not None:
        for line in output.splitlines():
            if "--dport 22" in line or "--sport 22" in line:
                rules.append({"source": "iptables", "rule": line})
    return rules


def _public_key_parts(line: str) -> tuple[str, str, str] | None:
    parts = line.strip().split()
    for index, part in enumerate(parts):
        if part.startswith(_KEY_TYPES) and index + 1 < len(parts):
            key_type = part
            key_blob = parts[index + 1]
            comment = " ".join(parts[index + 2 :])
            return key_type, key_blob, comment
    return None


def _fingerprint(key_blob: str) -> str | None:
    try:
        decoded = base64.b64decode(key_blob.encode("ascii"), validate=True)
    except (ValueError, binascii.Error):
        return None
    digest = base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def collect_authorized_keys() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    users = []
    for user in pwd.getpwall():
        if user.pw_uid == 0 or user.pw_uid >= 1000:
            if user.pw_dir and user.pw_dir not in {"/nonexistent", "/var/empty"}:
                users.append(user)
    for user in users:
        path = Path(user.pw_dir) / ".ssh" / "authorized_keys"
        try:
            exists = path.exists()
        except PermissionError:
            entries.append({"user": user.pw_name, "path": str(path), "readable": False, "reason": "permission denied"})
            continue
        if not exists:
            continue
        if not os.access(path, os.R_OK):
            entries.append({"user": user.pw_name, "path": str(path), "readable": False, "reason": "not readable"})
            continue
        key_lines = read_lines(path)
        if not any(line.strip() and not line.strip().startswith("#") for line in key_lines):
            entries.append({"user": user.pw_name, "path": str(path), "readable": True, "empty": True})
            continue
        for line_no, line in enumerate(key_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key = _public_key_parts(stripped)
            if not key:
                entries.append({"user": user.pw_name, "path": str(path), "line": line_no, "readable": True, "valid": False})
                continue
            key_type, key_blob, comment = key
            entries.append(
                {
                    "user": user.pw_name,
                    "path": str(path),
                    "line": line_no,
                    "readable": True,
                    "valid": True,
                    "type": key_type,
                    "fingerprint": _fingerprint(key_blob),
                    "comment": comment,
                }
            )
    return entries


def collect_current_ssh(
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_budget: LookupBudget | None = None,
) -> list[dict[str, Any]]:
    sessions = []
    for sock in collect_sockets(resolve=False, geo=False):
        local_port = sock["local"]["port"]
        peer_port = sock["peer"]["port"]
        if sock["state"] != "ESTAB" or (local_port != 22 and peer_port != 22):
            continue
        remote = sock["peer"] if local_port == 22 else sock["local"]
        remote_ip = remote["address"]
        item: dict[str, Any] = {
            "proto": sock["proto"],
            "local": sock["local"],
            "remote": remote,
            "pid": sock["pid"],
            "process": sock["process"],
            "uptime": _connection_uptime(sock["pid"]),
        }
        if resolve and isinstance(remote_ip, str):
            item["remote_hostname"] = reverse_dns(remote_ip, lookup_budget)
        if geo and isinstance(remote_ip, str):
            item["local_geo"] = geo_lookup(item["local"]["address"], geo_db, lookup_budget)
            item["geo"] = geo_lookup(remote_ip, geo_db, lookup_budget)
        sessions.append(item)
    return sessions


def collect_ssh_history(
    lines: int = 80,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_budget: LookupBudget | None = None,
) -> list[dict[str, Any]]:
    output = run_command(
        ["journalctl", "-u", "ssh", "-u", "sshd", "-n", str(max(lines, 1)), "--no-pager", "--output", "short-iso"],
        timeout=2.0,
    )
    if not output:
        return []
    events = []
    for line in output.splitlines():
        item = _parse_journal_event(line)
        if not item:
            continue
        ip = item.get("ip")
        if resolve and ip:
            item["hostname"] = reverse_dns(ip, lookup_budget)
        if geo and ip:
            item["geo"] = geo_lookup(ip, geo_db, lookup_budget)
        events.append(item)
    return events


def _journal_output(hours: int) -> str | None:
    window_hours = max(hours, 1)
    cached = _JOURNAL_CACHE.get(window_hours)
    if cached and time.monotonic() - cached[0] < _JOURNAL_CACHE_TTL_SECONDS:
        return cached[1]

    since = f"{window_hours} hours ago"
    args = ["journalctl", "-u", "ssh", "-u", "sshd", "--since", since, "--no-pager", "--output", "short-iso"]
    output = run_command(["sudo", "-n", *args], timeout=8.0) or run_command(args, timeout=8.0)
    _JOURNAL_CACHE[window_hours] = (time.monotonic(), output)
    return output


def collect_ssh_attacks(
    hours: int = 24,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_budget: LookupBudget | None = None,
) -> dict[str, Any]:
    """Summarize recent SSH abuse signals without treating transport noise as a compromise."""
    output = _journal_output(hours)
    empty_counts = {name: 0 for name in ("accepted", "failed", "invalid_user", "preauth", "penalty", "transport")}
    if output is None:
        return {
            "available": False,
            "reason": "SSH journal unavailable",
            "window_hours": max(hours, 1),
            "counts": empty_counts,
            "sources": [],
            "recent": [],
            "level": "unknown",
        }

    events = [event for line in output.splitlines() if (event := _parse_journal_event(line))]
    counts = Counter(event["type"] for event in events)
    source_counts: dict[str, Counter[str]] = {}
    source_last_seen: dict[str, str] = {}
    for event in events:
        ip = event.get("ip")
        if not ip or event["type"] not in {"failed", "invalid_user", "preauth", "penalty", "transport"}:
            continue
        source_counts.setdefault(ip, Counter())[event["type"]] += 1
        source_last_seen[ip] = event["time"]

    sources = []
    for ip, signals in sorted(source_counts.items(), key=lambda item: (sum(item[1].values()), item[0]), reverse=True)[:12]:
        item: dict[str, Any] = {
            "ip": ip,
            "signals": sum(signals.values()),
            "failed": signals["failed"],
            "invalid_user": signals["invalid_user"],
            "preauth": signals["preauth"],
            "penalty": signals["penalty"],
            "transport": signals["transport"],
            "last_seen": source_last_seen[ip],
        }
        if resolve:
            item["hostname"] = reverse_dns(ip, lookup_budget)
        if geo:
            item["geo"] = geo_lookup(ip, geo_db, lookup_budget)
        sources.append(item)

    failed = counts["failed"]
    level = "clear" if not failed else "guarded" if failed < 25 else "elevated" if failed < 250 else "high"
    return {
        "available": True,
        "reason": None,
        "window_hours": max(hours, 1),
        "counts": {name: counts[name] for name in empty_counts},
        "sources": sources,
        "recent": [event for event in events if event["type"] != "accepted"][-12:],
        "level": level,
        "first_seen": events[0]["time"] if events else None,
        "last_seen": events[-1]["time"] if events else None,
    }


def collect_ssh(
    include_history: bool = False,
    lines: int = 80,
    attack_hours: int = 24,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
) -> dict[str, Any]:
    budget = LookupBudget(lookup_limit)
    server = collect_ssh_server()
    warnings = []
    if server["service"]["active"] == "unknown":
        warnings.append("ssh service visibility is limited")
    if budget.skipped:
        warnings.append(f"{budget.skipped} hostname/GeoLite lookups skipped by lookup budget")
    return {
        "_meta": meta("ssh", limited=server["service"]["active"] == "unknown", reason=warnings[0] if warnings else None, source="systemctl/sshd/ss/journal", warnings=warnings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "geo_database": find_geo_db(geo_db) if geo else None,
        "lookup_budget": budget.summary(),
        "server": server,
        "current": collect_current_ssh(resolve=resolve, geo=geo, geo_db=geo_db, lookup_budget=budget),
        "attacks": collect_ssh_attacks(hours=attack_hours, resolve=resolve, geo=geo, geo_db=geo_db, lookup_budget=budget),
        "history": collect_ssh_history(lines=lines, resolve=resolve, geo=geo, geo_db=geo_db, lookup_budget=budget) if include_history else [],
    }
