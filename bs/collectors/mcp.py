from __future__ import annotations

import json
import re
import shlex
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from bs.config import MonitorConfig
from bs.collectors.common import bytes_to_human, read_text, run_command
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT, LookupBudget, geo_lookup
from bs.collectors.geo import find_geo_db
from bs.collectors.network_detail import collect_sockets
from bs.collectors.result import meta


LOCAL_ADDRESSES = {"127.0.0.1", "::1", "localhost"}
_COMMAND_METRIC_RE = re.compile(r"^command_end_to_end_latency_milliseconds_(?P<kind>count|sum)\{(?P<labels>[^}]*)\}\s+(?P<value>[0-9.eE+-]+)$")
_STATUS_LABEL_RE = re.compile(r'tunnel_service_status="(?P<status>[^"]+)"')


def _duration(seconds: int | None) -> str:
    if seconds is None:
        return "n/a"
    days, rem = divmod(max(seconds, 0), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _parse_show(output: str | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if not output:
        return values
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _int_value(value: str | None, default: int = 0) -> int:
    if value is None:
        return default
    value = value.strip()
    return int(value) if value.isdigit() else default


def _pid_stats(pid: int | None) -> dict[str, Any]:
    if not pid:
        return {}
    status = read_text(f"/proc/{pid}/status") or ""
    stats: dict[str, Any] = {}
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                stats["rss"] = int(parts[1]) * 1024
        elif line.startswith("Threads:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                stats["threads"] = int(parts[1])
    etimes = run_command(["ps", "-o", "etimes=", "-p", str(pid)], timeout=1.0)
    if etimes and etimes.strip().isdigit():
        stats["uptime_seconds"] = int(etimes.strip())
        stats["uptime"] = _duration(stats["uptime_seconds"])
    return stats


def _service(unit: str, config: MonitorConfig) -> dict[str, Any]:
    output = run_command(["systemctl", "show", unit, "--no-pager"], timeout=2.0)
    values = _parse_show(output)
    main_pid = _int_value(values.get("MainPID")) or None
    environment = values.get("Environment", "")
    return {
        "unit": unit,
        "description": values.get("Description"),
        "load_state": values.get("LoadState", "unknown"),
        "active_state": values.get("ActiveState", "unknown"),
        "sub_state": values.get("SubState", "unknown"),
        "enabled": values.get("UnitFileState", "unknown"),
        "main_pid": main_pid,
        "n_restarts": _int_value(values.get("NRestarts")),
        "exec_start": values.get("ExecStart"),
        "working_directory": values.get("WorkingDirectory"),
        "user": values.get("User"),
        "cpu_usage_nsec": _int_value(values.get("CPUUsageNSec")),
        "tasks_current": _int_value(values.get("TasksCurrent")),
        "security_flags": {
            "write_tools_enabled": bool(config.write_tools_environment and config.write_tools_environment in environment),
            "secret_tools_enabled": bool(config.secret_tools_environment and config.secret_tools_environment in environment),
        },
        "process": _pid_stats(main_pid),
    }


def _tcp_probe(host: str, port: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return {"ok": True, "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def _http_probe(url: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "bs-mcp-health/0.1"})
        with urllib.request.urlopen(request, timeout=1.5) as response:
            body = response.read(512)
            text = body.decode("utf-8", errors="replace")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = None
            return {
                "ok": 200 <= response.status < 500,
                "status": response.status,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "body_preview": text[:160],
                "json": payload if isinstance(payload, dict) else None,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def _mcp_tool_probe(config: MonitorConfig, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "bs-monitor",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    ).encode("utf-8")
    try:
        request = urllib.request.Request(
            config.mcp_rpc_url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "bs-mcp-health/0.1"},
        )
        with urllib.request.urlopen(request, timeout=5.0) as response:
            raw = response.read(2_000_000)
            data = json.loads(raw.decode("utf-8", errors="replace"))
        result = data.get("result") if isinstance(data, dict) else None
        structured = result.get("structuredContent") if isinstance(result, dict) else None
        is_error = bool(result.get("isError")) if isinstance(result, dict) else True
        return {
            "ok": not is_error,
            "status": response.status,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "result": structured if isinstance(structured, dict) else {},
        }
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)}


def _summarize_usage_limits(limits: dict[str, Any]) -> dict[str, Any]:
    windows = {
        name: {
            "remaining_percent": value.get("remaining_percent"),
            "used_percent": value.get("used_percent"),
            "resets_at": value.get("resets_at"),
            "window_duration_minutes": value.get("window_duration_minutes"),
        }
        for name in ("5h", "weekly")
        if isinstance((value := limits.get(name)), dict)
    }
    account = limits.get("account") if isinstance(limits.get("account"), dict) else {}
    token_usage = limits.get("token_usage") if isinstance(limits.get("token_usage"), dict) else {}
    buckets = token_usage.get("recent_daily_usage_buckets") if isinstance(token_usage.get("recent_daily_usage_buckets"), list) else []
    latest = max((item for item in buckets if isinstance(item, dict)), key=lambda item: str(item.get("startDate", "")), default={})
    warnings = []
    for name, window in windows.items():
        remaining = window.get("remaining_percent")
        if isinstance(remaining, (int, float)) and remaining <= 25:
            warnings.append(f"{name} limit has {remaining:g}% remaining")
    return {
        "windows": windows,
        "reset_credits_available": (limits.get("reset_credits") or {}).get("available_count"),
        "plan_type": account.get("plan_type"),
        "credit_balance": (account.get("credits") or {}).get("balance"),
        "latest_daily_date": latest.get("startDate"),
        "latest_daily_tokens": latest.get("tokens"),
        "lifetime_tokens": (token_usage.get("summary") or {}).get("lifetimeTokens"),
        "warnings": warnings,
    }


def _provider_label(provider: str) -> str:
    return {"codex": "Codex", "claude-code": "Claude Code"}.get(provider, provider)


def _summarize_normalized_usage(payload: dict[str, Any]) -> dict[str, Any]:
    windows = payload.get("windows") if isinstance(payload.get("windows"), dict) else {}
    normalized_windows = {
        name: {
            "remaining_percent": value.get("remaining_percent"),
            "used_percent": value.get("used_percent"),
            "resets_at": value.get("resets_at"),
            "window_duration_minutes": value.get("window_duration_minutes"),
        }
        for name, value in windows.items()
        if isinstance(value, dict)
    }
    warnings = []
    for name, window in normalized_windows.items():
        remaining = window.get("remaining_percent")
        if isinstance(remaining, (int, float)) and remaining <= 25:
            warnings.append(f"{name} limit has {remaining:g}% remaining")
    return {
        "windows": normalized_windows,
        "reset_credits_available": payload.get("reset_credits_available"),
        "plan_type": payload.get("plan_type"),
        "credit_balance": payload.get("credit_balance"),
        "latest_daily_date": payload.get("latest_daily_date"),
        "latest_daily_tokens": payload.get("latest_daily_tokens"),
        "lifetime_tokens": payload.get("lifetime_tokens"),
        "warnings": warnings,
    }


_SHELL_EXECUTABLES = {"sh", "bash", "dash", "zsh", "fish"}


def _safe_usage_args(args: list[str]) -> bool:
    return bool(args and Path(args[0]).is_absolute() and Path(args[0]).name not in _SHELL_EXECUTABLES)


def _tunnel_usage_probe(config: MonitorConfig) -> dict[str, Any]:
    args = list(config.usage_command)
    source = "configured usage command"
    if not args and config.usage_environment_variable:
        environment = run_command(["systemctl", "show", config.tunnel_service, "--property=Environment", "--value", "--no-pager"], timeout=2.0) or ""
        try:
            assignments = shlex.split(environment)
        except ValueError:
            assignments = []
        command = next((item.partition("=")[2] for item in assignments if item.startswith(f"{config.usage_environment_variable}=")), "")
        try:
            args = shlex.split(command)
        except ValueError:
            args = []
        source = "configured service usage command"
    if not _safe_usage_args(args):
        return {"available": False, "error": "a safe usage command is not configured"}
    output = run_command(args, timeout=config.usage_timeout_seconds)
    if not output:
        return {"available": False, "error": "trusted tunnel usage probe returned no data"}
    try:
        limits = json.loads(output)
    except json.JSONDecodeError:
        return {"available": False, "error": "trusted tunnel usage probe returned invalid JSON"}
    if not isinstance(limits, dict):
        return {"available": False, "error": "trusted tunnel usage probe returned an invalid payload"}
    summary = _summarize_usage_limits(limits) if config.usage_format == "codex" else _summarize_normalized_usage(limits)
    return {"available": True, "source": source, "provider": config.usage_provider, "provider_label": _provider_label(config.usage_provider), **summary}


def _collect_usage(config: MonitorConfig, use_http: bool = True) -> dict[str, Any]:
    provider = config.usage_provider
    provider_fields = {"provider": provider, "provider_label": _provider_label(provider)}
    if provider == "claude-code":
        if not (config.usage_command or config.usage_environment_variable):
            return {"available": False, "disabled": True, **provider_fields, "error": "configure a normalized Claude Code usage command"}
        result = _tunnel_usage_probe(config)
        return {**provider_fields, **result}
    if not (config.usage_tool or config.usage_command or config.usage_environment_variable):
        return {"available": False, "disabled": True, "provider": config.usage_provider, "provider_label": _provider_label(config.usage_provider), "error": "usage monitoring is not configured"}
    if not use_http:
        return {**provider_fields, **_tunnel_usage_probe(config)}
    if not config.usage_tool:
        return {**provider_fields, **_tunnel_usage_probe(config)}
    mcp_probe = _mcp_tool_probe(config, config.usage_tool)
    usage = mcp_probe.get("result", {}).get("usage") if mcp_probe.get("ok") else None
    limits = usage.get("limits") if isinstance(usage, dict) else None
    source_probe = usage.get("probe") if isinstance(usage, dict) else None
    if isinstance(limits, dict) and limits and isinstance(source_probe, dict) and source_probe.get("available"):
        return {"available": True, "source": "HTTP MCP usage tool", "provider": "codex", "provider_label": "Codex", **_summarize_usage_limits(limits)}
    fallback = {**provider_fields, **_tunnel_usage_probe(config)}
    fallback["http_mcp_error"] = source_probe.get("error") if isinstance(source_probe, dict) else mcp_probe.get("error")
    return fallback


def _parse_tunnel_metrics(body: str) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    latency_sum = 0.0
    commands = 0
    for line in body.splitlines():
        match = _COMMAND_METRIC_RE.match(line)
        if not match:
            continue
        status_match = _STATUS_LABEL_RE.search(match["labels"])
        if not status_match:
            continue
        value = float(match["value"])
        if match["kind"] == "count":
            count = int(value)
            status = status_match["status"]
            status_counts[status] = status_counts.get(status, 0) + count
            commands += count
        else:
            latency_sum += value
    successful = sum(count for status, count in status_counts.items() if status.startswith("2"))
    return {
        "commands": commands,
        "successful": successful,
        "failed": commands - successful,
        "status_counts": status_counts,
        "average_latency_ms": round(latency_sum / commands, 1) if commands else None,
    }


def _tunnel_metrics_probe(url: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "bs-mcp-health/0.1"})
        with urllib.request.urlopen(request, timeout=1.5) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")
            return {
                "ok": 200 <= response.status < 500,
                "status": response.status,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "metrics": _parse_tunnel_metrics(body),
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def _skipped_probe(reason: str) -> dict[str, Any]:
    return {"ok": None, "skipped": True, "reason": reason}


def _journal(config: MonitorConfig, lines: int) -> dict[str, Any]:
    output = run_command(
        [
            "journalctl",
            "-u",
            config.mcp_service,
            "-u",
            config.tunnel_service,
            "-n",
            str(max(lines, 1)),
            "--no-pager",
            "--output",
            "short-iso",
        ],
        timeout=2.0,
    )
    entries: list[dict[str, Any]] = []
    counts = {"error": 0, "warning": 0, "info": 0, "requests": 0}
    if not output:
        return {"entries": entries, "counts": counts}

    for line in output.splitlines():
        entry: dict[str, Any] = {"raw": line, "level": "info", "message": line}
        if f" {config.mcp_service.removesuffix('.service')}" in line:
            entry["unit"] = config.mcp_service
        elif f" {config.tunnel_service.removesuffix('.service')}" in line:
            entry["unit"] = config.tunnel_service

        json_start = line.find("{")
        if json_start >= 0:
            try:
                payload = json.loads(line[json_start:])
                entry["payload"] = payload
                entry["level"] = str(payload.get("level", "info")).lower()
                entry["message"] = payload.get("msg", line)
            except json.JSONDecodeError:
                pass
        elif "WARNING" in line or " WARN" in line:
            entry["level"] = "warning"
        elif "ERROR" in line or " ERR" in line:
            entry["level"] = "error"

        lower = line.lower()
        level = str(entry.get("level", "info")).lower()
        if level in {"error", "err", "fatal"}:
            counts["error"] += 1
        elif level in {"warn", "warning"} or ("warn" in lower and "level" not in entry):
            counts["warning"] += 1
        else:
            counts["info"] += 1
        if '"GET ' in line or '"POST ' in line or " /mcp " in line or " /health " in line:
            counts["requests"] += 1
        entries.append(entry)
    return {"entries": entries, "counts": counts}


def _tunnel_startup_summary(config: MonitorConfig) -> dict[str, Any]:
    output = run_command(
        [
            "journalctl",
            "-u",
            config.tunnel_service,
            "-n",
            "1",
            "--no-pager",
            "--output",
            "cat",
            "--grep",
            config.startup_log_match,
        ],
        timeout=2.0,
    )
    if not output:
        return {}
    for line in reversed(output.splitlines()):
        json_start = line.find("{")
        if json_start < 0:
            continue
        try:
            payload = json.loads(line[json_start:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("mcp_target_kind"):
            return payload
    return {}


def _target_summary(config: MonitorConfig, journal: dict[str, Any], services: dict[str, Any], startup: dict[str, Any] | None = None) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "kind": None,
        "value": None,
        "transport": None,
        "profile": None,
        "profile_path": None,
        "tunnel_url": None,
        "source": None,
    }
    entries = ([{"payload": startup}] if startup else []) + list(reversed(journal["entries"]))
    for entry in entries:
        payload = entry.get("payload") or {}
        if not summary["kind"] and payload.get("mcp_target_kind"):
            summary["kind"] = payload.get("mcp_target_kind")
            summary["value"] = payload.get("mcp_target_value")
            summary["profile"] = payload.get("profile_name")
            summary["profile_path"] = payload.get("profile_path")
            summary["source"] = "tunnel startup summary"
        if not summary["transport"] and payload.get("transport"):
            summary["transport"] = payload.get("transport")
        if not summary["tunnel_url"] and payload.get("tunnel_url"):
            summary["tunnel_url"] = payload.get("tunnel_url")
        if summary["kind"] and summary["transport"] and summary["tunnel_url"]:
            break

    if not summary["kind"]:
        mcp_service = services["mcp"]
        if mcp_service["active_state"] == "active":
            summary.update({"kind": "http", "value": f"{config.mcp_host}:{config.mcp_port}", "source": config.mcp_service})
        else:
            summary.update({"kind": "unknown", "source": "not detected"})
    if not summary["transport"]:
        summary["transport"] = summary["kind"]
    target_value = str(summary.get("value") or "")
    summary["security_flags"] = {
        "available": summary.get("source") == "tunnel startup summary",
        "write_tools_enabled": bool(config.write_tools_environment and config.write_tools_environment in target_value),
        "secret_tools_enabled": bool(config.secret_tools_environment and config.secret_tools_environment in target_value),
    }
    return summary


def _listener_label(config: MonitorConfig, socket_item: dict[str, Any]) -> str:
    port = socket_item["local"]["port"]
    if port == config.mcp_port:
        return "mcp"
    if port == config.tunnel_port:
        return "tunnel-health"
    return "other"


def _bind_warning(socket_item: dict[str, Any]) -> str | None:
    address = socket_item["local"]["address"]
    if address not in LOCAL_ADDRESSES:
        return f"{address}:{socket_item['local']['port']} is not loopback-only"
    return None


def collect_mcp(
    lines: int = 40,
    resolve: bool = True,
    geo: bool = True,
    geo_db: str | None = None,
    lookup_limit: int = DEFAULT_LOOKUP_LIMIT,
    config: MonitorConfig | None = None,
    config_source: str | None = None,
) -> dict[str, Any]:
    config = config or MonitorConfig()
    services = {
        "mcp": _service(config.mcp_service, config),
        "tunnel": _service(config.tunnel_service, config),
    }
    budget = LookupBudget(lookup_limit)
    sockets = collect_sockets(resolve=resolve, geo=geo, geo_db=geo_db, lookup_budget=budget)
    journal = _journal(config, lines)
    target = _target_summary(config, journal, services, _tunnel_startup_summary(config))
    listeners = [
        {**item, "role": _listener_label(config, item), "warning": _bind_warning(item)}
        for item in sockets
        if item["state"] == "LISTEN" and item["local"]["port"] in {config.mcp_port, config.tunnel_port}
    ]
    local_connections = [
        item
        for item in sockets
        if item["state"] == "ESTAB"
        and (item["local"]["port"] in {config.mcp_port, config.tunnel_port} or item["peer"]["port"] in {config.mcp_port, config.tunnel_port})
    ]
    tunnel_pid = services["tunnel"].get("main_pid")
    tunnel_outbound = []
    for item in sockets:
        if item["state"] != "ESTAB":
            continue
        if item.get("pid") == tunnel_pid or (
            tunnel_pid is None
            and services["tunnel"]["active_state"] == "active"
            and config.tunnel_process
            and item.get("process") == config.tunnel_process
        ):
            peer = item["peer"]
            if peer["port"] == 443:
                enriched = dict(item)
                if geo and isinstance(peer["address"], str):
                    enriched["local_geo"] = enriched.get("local_geo") or geo_lookup(enriched["local"]["address"], geo_db, budget)
                    enriched["geo"] = enriched.get("geo") or geo_lookup(peer["address"], geo_db, budget)
                tunnel_outbound.append(enriched)

    has_mcp_http_listener = any(listener["role"] == "mcp" for listener in listeners)
    has_tunnel_listener = any(listener["role"] == "tunnel-health" for listener in listeners)
    target_kind = str(target.get("kind") or "").lower()
    mcp_http_expected = target_kind in {"http", "sse"} or services["mcp"]["active_state"] == "active" or has_mcp_http_listener
    visibility_limited = (
        services["mcp"]["active_state"] == "unknown"
        and services["tunnel"]["active_state"] == "unknown"
        and target.get("source") not in {None, "not detected"}
        and not listeners
    )
    probes = {
        "mcp_tcp": _tcp_probe(config.mcp_host, config.mcp_port) if mcp_http_expected else _skipped_probe(f"MCP target is {target_kind or 'not HTTP'}"),
        "mcp_health": _http_probe(config.mcp_health_url) if mcp_http_expected else _skipped_probe(f"MCP target is {target_kind or 'not HTTP'}"),
        "tunnel_tcp": _tcp_probe(config.tunnel_host, config.tunnel_port) if has_tunnel_listener else _skipped_probe("tunnel health listener not visible"),
        "tunnel_health": _http_probe(config.tunnel_health_url) if has_tunnel_listener else _skipped_probe("tunnel health listener not visible"),
        "tunnel_metrics": _tunnel_metrics_probe(config.tunnel_metrics_url) if has_tunnel_listener else _skipped_probe("tunnel health listener not visible"),
    }
    mode = _mcp_tool_probe(config, config.mode_tool) if mcp_http_expected and config.mode_tool else _skipped_probe(f"MCP target is {target_kind or 'not HTTP'}")
    usage = _collect_usage(config, use_http=mcp_http_expected)

    warnings = []
    if visibility_limited:
        warnings.append("limited view: service/socket/probe access is restricted; using journal-derived target info")
    if budget.skipped:
        warnings.append(f"{budget.skipped} hostname/GeoLite lookups skipped by lookup budget")
    for name, service in services.items():
        if visibility_limited:
            continue
        if name == "mcp" and target_kind == "stdio":
            continue
        if service["active_state"] != "active":
            warnings.append(f"{name} service is {service['active_state']}/{service['sub_state']}")
        if service["n_restarts"] > 0:
            warnings.append(f"{name} service has restarted {service['n_restarts']} times")
    for listener in listeners:
        if listener["warning"]:
            warnings.append(listener["warning"])
    if not visibility_limited and mcp_http_expected and not has_mcp_http_listener:
        warnings.append(f"MCP listener {config.mcp_host}:{config.mcp_port} not found")
    if not visibility_limited and not has_tunnel_listener:
        warnings.append(f"Tunnel health listener {config.tunnel_host}:{config.tunnel_port} not found")
    if not visibility_limited and not tunnel_outbound:
        warnings.append("No established tunnel outbound TLS connection found")
    if journal["counts"]["error"]:
        warnings.append(f"{journal['counts']['error']} recent journal errors")
    if journal["counts"]["warning"]:
        warnings.append(f"{journal['counts']['warning']} recent journal warnings")
    metrics = probes["tunnel_metrics"].get("metrics", {})
    if metrics.get("failed"):
        warnings.append(f"{metrics['failed']} tunnel command failures since the current process started")
    if not mode.get("skipped") and not mode.get("ok"):
        warnings.append("MCP mode status probe failed")
    mode_result = mode.get("result", {})
    if mode_result.get("secret_tools_enabled"):
        warnings.append("active MCP HTTP service has secret tools enabled")
    target_flags = target.get("security_flags", {})
    if target_flags.get("available") and target_flags.get("write_tools_enabled"):
        warnings.append("tunnel MCP target has write tools enabled")
    if target_flags.get("available") and target_flags.get("secret_tools_enabled"):
        warnings.append("tunnel MCP target has secret tools enabled")
    usage_label = str(usage.get("provider_label") or "Usage")
    if not usage.get("available") and not usage.get("disabled"):
        warnings.append(f"{usage_label} usage limits unavailable: {usage.get('error') or usage.get('http_mcp_error') or 'unknown reason'}")
    warnings.extend(f"{usage_label} usage warning: {warning}" for warning in usage.get("warnings", []))

    return {
        "_meta": meta("mcp", limited=visibility_limited, reason=warnings[0] if warnings else None, source="systemctl/ss/journal/http", warnings=warnings),
        "services": services,
        "target": target,
        "listeners": listeners,
        "local_connections": local_connections,
        "tunnel_outbound": tunnel_outbound,
        "probes": probes,
        "mode": mode,
        "usage": usage,
        "journal": journal,
        "warnings": warnings,
        "visibility_limited": visibility_limited,
        "lookup_budget": budget.summary(),
        "geo_database": find_geo_db(geo_db) if geo else None,
        "profile": {"name": config.name, "source": config_source or "built-in"},
    }


def format_bytes(value: int | None) -> str:
    return bytes_to_human(value)
