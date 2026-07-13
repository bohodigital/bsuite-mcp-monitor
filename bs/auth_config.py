from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bs.config import ConfigError


_PROVIDERS = {"cloudflare", "command", "github-cli", "http"}
_SHELL_EXECUTABLES = {"sh", "bash", "dash", "zsh", "fish"}
_CHECK_KEYS = {
    "name",
    "provider",
    "reference",
    "purpose",
    "environment_variable",
    "url",
    "hostname",
    "command",
    "expected_status",
    "timeout_seconds",
}


@dataclass(frozen=True)
class AuthCheck:
    name: str
    provider: str
    reference: str
    purpose: str
    environment_variable: str = ""
    url: str = ""
    hostname: str = "github.com"
    command: tuple[str, ...] = ()
    expected_status: int = 200
    timeout_seconds: float = 10.0


@dataclass(frozen=True)
class AuthConfig:
    checks: tuple[AuthCheck, ...] = ()


def _path(explicit_path: str | None) -> Path | None:
    if explicit_path:
        path = Path(explicit_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"authentication configuration file not found: {path}")
        return path
    environment_path = os.environ.get("BS_AUTH_CONFIG")
    if environment_path:
        path = Path(environment_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"BS_AUTH_CONFIG file not found: {path}")
        return path
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "bsuite" / "auth.toml"


def _string(table: dict[str, Any], key: str, default: str = "", *, required: bool = False) -> str:
    value = table.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"auth.check.{key} must be a string")
    value = value.strip()
    if required and not value:
        raise ConfigError(f"auth.check.{key} must be a non-empty string")
    return value


def _command(table: dict[str, Any]) -> tuple[str, ...]:
    value = table.get("command", [])
    if value == []:
        return ()
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ConfigError("auth.check.command must be a non-empty list of strings")
    executable = Path(value[0])
    if not executable.is_absolute() or executable.name in _SHELL_EXECUTABLES:
        raise ConfigError("auth.check.command requires a non-shell absolute executable path")
    return tuple(value)


def _timeout(table: dict[str, Any]) -> float:
    value = table.get("timeout_seconds", 10.0)
    if not isinstance(value, (int, float)) or not 0 < float(value) <= 60:
        raise ConfigError("auth.check.timeout_seconds must be between 0 and 60 seconds")
    return float(value)


def _http_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError("auth.check.url must be an HTTP(S) URL without credentials, query parameters, or fragments")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ConfigError("auth.check.url must use HTTPS unless it targets localhost")
    return value


def _check(table: dict[str, Any]) -> AuthCheck:
    unknown = set(table) - _CHECK_KEYS
    if unknown:
        raise ConfigError(f"unknown auth.check fields: {', '.join(sorted(unknown))}")
    provider = _string(table, "provider", required=True)
    if provider not in _PROVIDERS:
        raise ConfigError(f"auth.check.provider must be one of: {', '.join(sorted(_PROVIDERS))}")
    expected_status = table.get("expected_status", 200)
    if not isinstance(expected_status, int) or not 100 <= expected_status <= 599:
        raise ConfigError("auth.check.expected_status must be an HTTP status code")
    check = AuthCheck(
        name=_string(table, "name", required=True),
        provider=provider,
        reference=_string(table, "reference", required=True),
        purpose=_string(table, "purpose", required=True),
        environment_variable=_string(table, "environment_variable"),
        url=_string(table, "url"),
        hostname=_string(table, "hostname", "github.com", required=True),
        command=_command(table),
        expected_status=expected_status,
        timeout_seconds=_timeout(table),
    )
    if provider == "cloudflare" and not check.environment_variable:
        raise ConfigError("Cloudflare checks require environment_variable")
    if provider == "http" and not check.url:
        raise ConfigError("HTTP checks require url")
    if provider == "command" and not check.command:
        raise ConfigError("command checks require command")
    if check.url:
        _http_url(check.url)
    return check


def load_auth_config(explicit_path: str | None = None) -> tuple[AuthConfig, str]:
    path = _path(explicit_path)
    if path is None or not path.is_file():
        return AuthConfig(), "no authentication profile configured"
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read authentication configuration {path}: {exc}") from exc
    auth = data.get("auth", {})
    if not isinstance(auth, dict):
        raise ConfigError("[auth] must be a TOML table")
    unknown = set(auth) - {"check"}
    if unknown:
        raise ConfigError(f"unknown [auth] fields: {', '.join(sorted(unknown))}")
    checks = auth.get("check", [])
    if not isinstance(checks, list) or not all(isinstance(item, dict) for item in checks):
        raise ConfigError("[[auth.check]] must be an array of tables")
    parsed = tuple(_check(item) for item in checks)
    names = [item.name for item in parsed]
    if len(set(names)) != len(names):
        raise ConfigError("auth.check names must be unique")
    requires_private_profile = any(item.provider == "command" or (item.provider == "http" and item.environment_variable) for item in parsed)
    if requires_private_profile and stat.S_IMODE(path.stat().st_mode) & 0o022:
        raise ConfigError("authentication profile with command or authenticated HTTP checks must not be group/world writable")
    return AuthConfig(checks=parsed), str(path)
