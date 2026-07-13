from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

from bs.auth_config import AuthCheck, AuthConfig


def _checked_at() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _result(check: AuthCheck, status: str, detail: str, *, latency_ms: float | None = None, expires_at: str | None = None, capabilities: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": check.name,
        "provider": check.provider,
        "reference": check.reference,
        "purpose": check.purpose,
        "status": status,
        "detail": detail[:160],
        "checked_at": _checked_at(),
        "latency_ms": latency_ms,
        "expires_at": expires_at,
        "capabilities": capabilities or [],
    }


def _request(check: AuthCheck, url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes, float]:
    started = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": "bs-auth-health/0.1", **(headers or {})})
    with urllib.request.urlopen(request, timeout=check.timeout_seconds) as response:
        return response.status, response.read(64_000), round((time.monotonic() - started) * 1000, 1)


def _cloudflare(check: AuthCheck) -> dict[str, Any]:
    token = os.environ.get(check.environment_variable)
    if not token:
        return _result(check, "unknown", "credential is not available to this process")
    try:
        status, body, latency = _request(check, "https://api.cloudflare.com/client/v4/user/tokens/verify", {"Authorization": f"Bearer {token}"})
        payload = json.loads(body.decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return _result(check, "failed", "read-only provider verification failed")
    token_status = payload.get("result", {}).get("status") if isinstance(payload.get("result"), dict) else None
    expires_at = payload.get("result", {}).get("expires_on") if isinstance(payload.get("result"), dict) else None
    if status == 200 and payload.get("success") is True and token_status == "active":
        return _result(check, "healthy", "token is active", latency_ms=latency, expires_at=expires_at)
    return _result(check, "failed", "token is not active", latency_ms=latency, expires_at=expires_at)


def _github_cli(check: AuthCheck) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = subprocess.run(["gh", "auth", "status", "--hostname", check.hostname], check=False, capture_output=True, text=True, timeout=check.timeout_seconds)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return _result(check, "unknown", "GitHub CLI is unavailable")
    latency = round((time.monotonic() - started) * 1000, 1)
    return _result(check, "healthy" if result.returncode == 0 else "failed", "GitHub CLI authentication is valid" if result.returncode == 0 else "GitHub CLI authentication failed", latency_ms=latency)


def _http(check: AuthCheck) -> dict[str, Any]:
    headers: dict[str, str] = {}
    if check.environment_variable:
        token = os.environ.get(check.environment_variable)
        if not token:
            return _result(check, "unknown", "credential is not available to this process")
        headers["Authorization"] = f"Bearer {token}"
    try:
        status, _body, latency = _request(check, check.url, headers)
    except (urllib.error.URLError, TimeoutError, OSError):
        return _result(check, "failed", "HTTP verification failed")
    return _result(check, "healthy" if status == check.expected_status else "failed", f"HTTP status {status}", latency_ms=latency)


def _command(check: AuthCheck) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = subprocess.run(list(check.command), check=False, capture_output=True, text=True, timeout=check.timeout_seconds)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return _result(check, "failed", "adapter command failed")
    latency = round((time.monotonic() - started) * 1000, 1)
    if result.returncode != 0:
        return _result(check, "failed", "adapter command returned an error", latency_ms=latency)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return _result(check, "failed", "adapter command returned invalid JSON", latency_ms=latency)
    status = payload.get("status") if isinstance(payload, dict) else None
    if status not in {"healthy", "warning", "failed", "unknown"}:
        return _result(check, "failed", "adapter command returned an invalid status", latency_ms=latency)
    detail_code = payload.get("detail_code") if isinstance(payload.get("detail_code"), str) else ""
    detail = f"adapter result: {detail_code}" if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", detail_code) else "custom verification completed"
    expires_at = payload.get("expires_at") if isinstance(payload.get("expires_at"), str) else None
    capabilities = payload.get("capabilities") if isinstance(payload.get("capabilities"), list) and all(isinstance(item, str) for item in payload["capabilities"]) else []
    return _result(check, status, detail, latency_ms=latency, expires_at=expires_at, capabilities=capabilities[:12])


def collect_auth(config: AuthConfig, source: str) -> dict[str, Any]:
    handlers = {"cloudflare": _cloudflare, "command": _command, "github-cli": _github_cli, "http": _http}
    checks = [handlers[check.provider](check) for check in config.checks]
    summary = {status: sum(item["status"] == status for item in checks) for status in ("healthy", "warning", "failed", "unknown")}
    return {"profile": {"source": source}, "checks": checks, "summary": summary}
