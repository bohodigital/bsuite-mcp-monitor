from __future__ import annotations

import json
import os
import stat
import tempfile
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


def default_auth_config_path() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "bsuite" / "auth.toml"


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
    return default_auth_config_path()


def auth_config_path(explicit_path: str | None = None) -> Path:
    if explicit_path:
        return Path(explicit_path).expanduser()
    environment_path = os.environ.get("BS_AUTH_CONFIG")
    return Path(environment_path).expanduser() if environment_path else default_auth_config_path()


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


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


def validate_auth_config(config: AuthConfig) -> AuthConfig:
    checks = []
    for item in config.checks:
        table: dict[str, Any] = {
            "name": item.name,
            "provider": item.provider,
            "reference": item.reference,
            "purpose": item.purpose,
            "environment_variable": item.environment_variable,
            "url": item.url,
            "hostname": item.hostname,
            "command": list(item.command),
            "expected_status": item.expected_status,
            "timeout_seconds": item.timeout_seconds,
        }
        checks.append(_check({key: value for key, value in table.items() if value not in ("", []) or key in {"name", "provider", "reference", "purpose", "expected_status", "timeout_seconds"}}))
    names = [item.name for item in checks]
    if len(set(names)) != len(names):
        raise ConfigError("auth.check names must be unique")
    return AuthConfig(tuple(checks))


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
    parsed = validate_auth_config(AuthConfig(tuple(_check(item) for item in checks))).checks
    requires_private_profile = any(item.provider == "command" or (item.provider == "http" and item.environment_variable) for item in parsed)
    if requires_private_profile and stat.S_IMODE(path.stat().st_mode) & 0o022:
        raise ConfigError("authentication profile with command or authenticated HTTP checks must not be group/world writable")
    return AuthConfig(checks=parsed), str(path)


def render_auth_config(config: AuthConfig) -> str:
    lines = [
        "# Generated by `bs auth init`. This file contains references only, never secret values.",
        "# Keep command adapters read-only and store this profile with owner-only permissions.",
        "",
        "[auth]",
    ]
    for check in config.checks:
        lines.extend(
            [
                "",
                "[[auth.check]]",
                f"name = {_toml_string(check.name)}",
                f"provider = {_toml_string(check.provider)}",
                f"reference = {_toml_string(check.reference)}",
                f"purpose = {_toml_string(check.purpose)}",
            ]
        )
        if check.environment_variable:
            lines.append(f"environment_variable = {_toml_string(check.environment_variable)}")
        if check.provider == "http":
            lines.extend([f"url = {_toml_string(check.url)}", f"expected_status = {check.expected_status}"])
        if check.provider == "github-cli":
            lines.append(f"hostname = {_toml_string(check.hostname)}")
        if check.provider == "command":
            lines.append(f"command = {json.dumps(list(check.command), ensure_ascii=True)}")
        if check.timeout_seconds != 10.0:
            lines.append(f"timeout_seconds = {check.timeout_seconds:g}")
    return "\n".join(lines) + "\n"


def write_auth_config(path: Path, config: AuthConfig, *, replace: bool = False) -> None:
    if path.exists() and not replace:
        raise ConfigError(f"authentication configuration already exists: {path}; use --replace to overwrite it")
    config = validate_auth_config(config)
    parent_exists = path.parent.exists()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent_exists:
            path.parent.chmod(0o700)
    except OSError as exc:
        raise ConfigError(f"could not prepare authentication configuration directory {path.parent}: {exc}") from exc
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o022:
        raise ConfigError(f"authentication configuration directory must not be group/world writable: {path.parent}")
    content = render_auth_config(config)
    # Write beside the destination, then atomically replace it with owner-only mode.
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ConfigError(f"could not write authentication configuration {path}: {exc}") from exc
