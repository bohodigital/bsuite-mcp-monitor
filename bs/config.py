from __future__ import annotations

import ipaddress
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class MonitorConfig:
    name: str = "default"
    mcp_service: str = "mcp.service"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8765
    mcp_health_path: str = "/health"
    mcp_rpc_path: str = "/mcp"
    mode_tool: str = "mcp_mode_status"
    usage_tool: str = "read_codex_usage_limits"
    tunnel_service: str = "mcp-tunnel.service"
    tunnel_host: str = "127.0.0.1"
    tunnel_port: int = 8080
    tunnel_health_path: str = "/"
    tunnel_metrics_path: str = "/metrics"
    tunnel_process: str = "tunnel-client"
    startup_log_match: str = "tunnel-client startup summary"
    usage_command: tuple[str, ...] = ()
    usage_environment_variable: str = ""
    usage_timeout_seconds: float = 10.0
    write_tools_environment: str = "MCP_ENABLE_WRITE_TOOLS=1"
    secret_tools_environment: str = "MCP_ENABLE_SECRET_TOOLS=1"

    def endpoint(self, host: str, port: int, path: str) -> str:
        authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
        return f"http://{authority}:{port}{path}"

    @property
    def mcp_health_url(self) -> str:
        return self.endpoint(self.mcp_host, self.mcp_port, self.mcp_health_path)

    @property
    def mcp_rpc_url(self) -> str:
        return self.endpoint(self.mcp_host, self.mcp_port, self.mcp_rpc_path)

    @property
    def tunnel_health_url(self) -> str:
        return self.endpoint(self.tunnel_host, self.tunnel_port, self.tunnel_health_path)

    @property
    def tunnel_metrics_url(self) -> str:
        return self.endpoint(self.tunnel_host, self.tunnel_port, self.tunnel_metrics_path)


def _config_path(explicit_path: str | None) -> Path | None:
    if explicit_path:
        path = Path(explicit_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"configuration file not found: {path}")
        return path
    environment_path = os.environ.get("BS_CONFIG")
    if environment_path:
        path = Path(environment_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"BS_CONFIG file not found: {path}")
        return path
    user_config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    for path in (user_config_root / "bsuite" / "config.toml", Path("/etc/bsuite/config.toml")):
        if path.is_file():
            return path
    return None


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a TOML table")
    return value


def _string(table: dict[str, Any], key: str, default: str, *, allow_empty: bool = False) -> str:
    value = table.get(key, default)
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ConfigError(f"{key} must be a non-empty string")
    return value.strip()


def _port(table: dict[str, Any], key: str, default: int) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise ConfigError(f"{key} must be an integer between 1 and 65535")
    return value


def _loopback_host(table: dict[str, Any], key: str, default: str) -> str:
    value = _string(table, key, default)
    if value == "localhost":
        return value
    try:
        if ipaddress.ip_address(value).is_loopback:
            return value
    except ValueError:
        pass
    raise ConfigError(f"{key} must be a loopback address or localhost")


def _http_path(table: dict[str, Any], key: str, default: str) -> str:
    value = _string(table, key, default)
    if not value.startswith("/") or "\n" in value or "\r" in value:
        raise ConfigError(f"{key} must be an absolute HTTP path")
    return value


def _command(table: dict[str, Any]) -> tuple[str, ...]:
    value = table.get("command", [])
    if value == []:
        return ()
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ConfigError("usage.command must be a non-empty list of strings")
    if not Path(value[0]).is_absolute():
        raise ConfigError("usage.command requires an absolute executable path")
    if any("\x00" in item for item in value):
        raise ConfigError("usage.command cannot contain NUL bytes")
    return tuple(value)


def _timeout(table: dict[str, Any], key: str, default: float) -> float:
    value = table.get(key, default)
    if not isinstance(value, (int, float)) or not 0 < float(value) <= 60:
        raise ConfigError(f"{key} must be between 0 and 60 seconds")
    return float(value)


def _load(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read configuration {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("configuration root must be a TOML table")
    return data


def load_monitor_config(explicit_path: str | None = None) -> tuple[MonitorConfig, str]:
    path = _config_path(explicit_path)
    if path is None:
        return MonitorConfig(), "built-in default profile"

    data = _load(path)
    defaults = MonitorConfig()
    profile = _table(data, "profile")
    mcp = _table(data, "mcp")
    tunnel = _table(data, "tunnel")
    usage = _table(data, "usage")
    capabilities = _table(data, "capabilities")
    config = MonitorConfig(
        name=_string(profile, "name", defaults.name),
        mcp_service=_string(mcp, "service", defaults.mcp_service),
        mcp_host=_loopback_host(mcp, "host", defaults.mcp_host),
        mcp_port=_port(mcp, "port", defaults.mcp_port),
        mcp_health_path=_http_path(mcp, "health_path", defaults.mcp_health_path),
        mcp_rpc_path=_http_path(mcp, "rpc_path", defaults.mcp_rpc_path),
        mode_tool=_string(mcp, "mode_tool", defaults.mode_tool, allow_empty=True),
        usage_tool=_string(mcp, "usage_tool", defaults.usage_tool, allow_empty=True),
        tunnel_service=_string(tunnel, "service", defaults.tunnel_service),
        tunnel_host=_loopback_host(tunnel, "host", defaults.tunnel_host),
        tunnel_port=_port(tunnel, "port", defaults.tunnel_port),
        tunnel_health_path=_http_path(tunnel, "health_path", defaults.tunnel_health_path),
        tunnel_metrics_path=_http_path(tunnel, "metrics_path", defaults.tunnel_metrics_path),
        tunnel_process=_string(tunnel, "process", defaults.tunnel_process, allow_empty=True),
        startup_log_match=_string(tunnel, "startup_log_match", defaults.startup_log_match, allow_empty=True),
        usage_command=_command(usage),
        usage_environment_variable=_string(usage, "environment_variable", "", allow_empty=True),
        usage_timeout_seconds=_timeout(usage, "timeout_seconds", defaults.usage_timeout_seconds),
        write_tools_environment=_string(capabilities, "write_environment", "", allow_empty=True),
        secret_tools_environment=_string(capabilities, "secret_environment", "", allow_empty=True),
    )
    if config.usage_command and stat.S_IMODE(path.stat().st_mode) & 0o022:
        raise ConfigError("usage.command profile must not be group/world writable")
    return config, str(path)
