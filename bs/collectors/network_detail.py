from __future__ import annotations

import json
import re
import time
from typing import Any

from bs.collectors.common import read_lines, read_text, run_command
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT, LookupBudget, geo_lookup, reverse_dns
from bs.collectors.geo import find_geo_db
from bs.collectors.network import collect_network
from bs.collectors.result import meta


_PROCESS_RE = re.compile(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+),fd=(?P<fd>\d+)\)\)')


def _split_endpoint(value: str) -> dict[str, Any]:
    if value in {"*", "*:*"}:
        return {"address": "*", "port": None}
    if value.startswith("[") and "]:" in value:
        address, port = value.rsplit("]:", 1)
        return {"address": address.removeprefix("["), "port": _port(port)}
    if ":" in value:
        address, port = value.rsplit(":", 1)
        return {"address": address, "port": _port(port)}
    return {"address": value, "port": None}


def _port(value: str) -> int | str | None:
    if value == "*":
        return None
    return int(value) if value.isdigit() else value


def _hostname(ip: str) -> str | None:
    return reverse_dns(ip)


def collect_interfaces() -> list[dict[str, Any]]:
    output = run_command(["ip", "-j", "addr"])
    if output:
        try:
            items = json.loads(output)
            return [
                {
                    "name": item.get("ifname"),
                    "state": item.get("operstate"),
                    "flags": item.get("flags", []),
                    "mtu": item.get("mtu"),
                    "mac": item.get("address"),
                    "addresses": [
                        {
                            "family": addr.get("family"),
                            "local": addr.get("local"),
                            "prefixlen": addr.get("prefixlen"),
                            "scope": addr.get("scope"),
                        }
                        for addr in item.get("addr_info", [])
                    ],
                }
                for item in items
            ]
        except json.JSONDecodeError:
            pass

    interfaces = []
    for iface in collect_network()["interfaces"]:
        name = iface["interface"]
        interfaces.append(
            {
                "name": name,
                "state": read_text(f"/sys/class/net/{name}/operstate") or "unknown",
                "flags": [],
                "mtu": read_text(f"/sys/class/net/{name}/mtu"),
                "mac": read_text(f"/sys/class/net/{name}/address"),
                "addresses": [],
            }
        )
    return interfaces


def collect_routes() -> list[dict[str, Any]]:
    output = run_command(["ip", "-j", "route"])
    if not output:
        return []
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return []


def collect_dns() -> list[str]:
    servers = []
    for line in read_lines("/etc/resolv.conf"):
        line = line.strip()
        if line.startswith("nameserver "):
            servers.append(line.split()[1])
    return servers


def collect_traffic_rates(sample_interval: float = 0.25) -> list[dict[str, Any]]:
    before = {item["interface"]: item for item in collect_network()["interfaces"]}
    time.sleep(max(sample_interval, 0.0))
    after = collect_network()["interfaces"]
    rates = []
    for item in after:
        previous = before.get(item["interface"])
        enriched = dict(item)
        if previous and sample_interval > 0:
            enriched["rx_bytes_per_sec"] = int((item["rx_bytes"] - previous["rx_bytes"]) / sample_interval)
            enriched["tx_bytes_per_sec"] = int((item["tx_bytes"] - previous["tx_bytes"]) / sample_interval)
        else:
            enriched["rx_bytes_per_sec"] = None
            enriched["tx_bytes_per_sec"] = None
        rates.append(enriched)
    return rates


def collect_sockets(
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
    lookup_budget: LookupBudget | None = None,
) -> list[dict[str, Any]]:
    output = run_command(["ss", "-tunap"], timeout=2.0)
    if not output:
        return []

    budget = lookup_budget or LookupBudget(lookup_limit)
    sockets = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, state, recv_q, send_q, local_raw, peer_raw = parts[:6] if len(parts) >= 6 else (*parts[:5], "")
        process_raw = " ".join(parts[6:]) if len(parts) > 6 else ""
        process_match = _PROCESS_RE.search(process_raw)
        peer = _split_endpoint(peer_raw)
        item: dict[str, Any] = {
            "proto": proto,
            "state": state,
            "recv_q": recv_q,
            "send_q": send_q,
            "local": _split_endpoint(local_raw),
            "peer": peer,
            "process": process_match.group("name") if process_match else None,
            "pid": int(process_match.group("pid")) if process_match else None,
        }
        local_address = item["local"]["address"]
        peer_address = peer["address"]
        if geo and isinstance(local_address, str):
            item["local_geo"] = geo_lookup(local_address, geo_db, budget)
        if resolve and isinstance(peer_address, str):
            item["peer_hostname"] = reverse_dns(peer_address, budget)
        if geo and isinstance(peer_address, str):
            item["geo"] = geo_lookup(peer_address, geo_db, budget)
        sockets.append(item)
    return sockets


def collect_network_detail(
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
) -> dict[str, Any]:
    budget = LookupBudget(lookup_limit)
    sockets = collect_sockets(resolve=resolve, geo=geo, geo_db=geo_db, lookup_budget=budget)
    interfaces = collect_interfaces()
    if geo:
        for interface in interfaces:
            for address in interface.get("addresses", []):
                local = address.get("local")
                if isinstance(local, str):
                    address["geo"] = geo_lookup(local, geo_db, budget)
    warnings = []
    if not sockets:
        warnings.append("socket list is empty or ss output is unavailable")
    if budget.skipped:
        warnings.append(f"{budget.skipped} hostname/GeoLite lookups skipped by lookup budget")
    return {
        "_meta": meta("network", limited=not bool(sockets), reason=warnings[0] if warnings else None, source="ip/ss/proc", warnings=warnings),
        "geo_database": find_geo_db(geo_db) if geo else None,
        "lookup_budget": budget.summary(),
        "interfaces": interfaces,
        "traffic": collect_traffic_rates(),
        "routes": collect_routes(),
        "dns": collect_dns(),
        "sockets": sockets,
        "listening": [item for item in sockets if item["state"] == "LISTEN"],
        "established": [item for item in sockets if item["state"] == "ESTAB"],
    }
