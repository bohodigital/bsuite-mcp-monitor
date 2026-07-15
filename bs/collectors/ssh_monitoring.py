from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_BASELINE_FIELDS = (
    "pubkeyauthentication",
    "passwordauthentication",
    "permitrootlogin",
    "kbdinteractiveauthentication",
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
    "maxauthtries",
    "logingracetime",
    "maxstartups",
    "persourcemaxstartups",
    "persourcepenalties",
    "allowtcpforwarding",
    "allowagentforwarding",
    "gatewayports",
)
_LEVEL_ORDER = {"clear": 0, "guarded": 1, "elevated": 2, "high": 3}


def _path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.name:
        raise ValueError("path must name a file")
    return path


def _baseline_payload(data: dict[str, Any]) -> dict[str, Any]:
    server = data["server"]
    keys = [
        {"user": item.get("user"), "type": item.get("type"), "fingerprint": item.get("fingerprint")}
        for item in server.get("authorized_keys", [])
        if item.get("valid") and item.get("fingerprint")
    ]
    return {
        "schema": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "listeners": sorted(f"{item['address']}:{item['port']}" for item in server.get("listening_ips", [])),
        "settings": {field: server["summary"].get(field) for field in _BASELINE_FIELDS},
        "authorized_keys": sorted(keys, key=lambda item: (str(item["user"]), str(item["fingerprint"]))),
    }


def write_baseline(path_value: str, data: dict[str, Any], replace: bool = False) -> dict[str, Any]:
    if data.get("_meta", {}).get("limited"):
        raise ValueError("refusing to write a baseline while SSH service visibility is limited")
    path = _path(path_value)
    if path.exists() and not replace:
        raise ValueError(f"baseline already exists: {path}; use --replace-baseline to replace it")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = _baseline_payload(data)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return {"status": "written", "path": str(path), "created_at": payload["created_at"]}


def compare_baseline(path_value: str, data: dict[str, Any]) -> dict[str, Any]:
    path = _path(path_value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "missing", "path": str(path), "changes": []}
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "invalid", "path": str(path), "changes": [{"field": "baseline", "detail": str(exc)}]}
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        return {"status": "invalid", "path": str(path), "changes": [{"field": "baseline", "detail": "unsupported baseline schema"}]}

    current = _baseline_payload(data)
    changes = []
    for field in ("listeners", "authorized_keys"):
        if payload.get(field) != current[field]:
            changes.append({"field": field, "expected": payload.get(field), "observed": current[field]})
    for field in _BASELINE_FIELDS:
        expected = payload.get("settings", {}).get(field)
        observed = current["settings"].get(field)
        if expected != observed:
            changes.append({"field": field, "expected": expected, "observed": observed})
    return {"status": "match" if not changes else "drift", "path": str(path), "created_at": payload.get("created_at"), "changes": changes}


def append_snapshot(path_value: str, attacks: dict[str, Any]) -> dict[str, Any]:
    path = _path(path_value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window_hours": attacks.get("window_hours"),
        "level": attacks.get("level"),
        "counts": attacks.get("counts", {}),
    }
    with path.open("a", encoding="utf-8") as handle:
        os.chmod(path, 0o600)
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return {"status": "recorded", "path": str(path), "record": record}


def read_trend(path_value: str, limit: int = 30) -> dict[str, Any]:
    path = _path(path_value)
    try:
        if path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError("snapshot file exceeds 5 MiB")
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {"status": "missing", "path": str(path), "records": []}
    except (OSError, ValueError) as exc:
        return {"status": "invalid", "path": str(path), "records": [], "reason": str(exc)}
    records = []
    for line in lines[-max(limit, 1) :]:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("counts"), dict):
            records.append(record)
    return {"status": "available", "path": str(path), "records": records}


def run_alert(command: str, minimum_level: str, attacks: dict[str, Any]) -> dict[str, Any]:
    if _LEVEL_ORDER.get(attacks.get("level", "unknown"), -1) < _LEVEL_ORDER[minimum_level]:
        return {"status": "below-threshold", "minimum_level": minimum_level}
    executable = Path(command).expanduser()
    if not executable.is_absolute():
        return {"status": "invalid", "reason": "alert command must be an absolute path"}
    counts = attacks.get("counts", {})
    environment = {
        "PATH": "/usr/bin:/bin",
        "BS_SSH_LEVEL": str(attacks.get("level", "unknown")),
        "BS_SSH_WINDOW_HOURS": str(attacks.get("window_hours", "")),
        "BS_SSH_FAILED": str(counts.get("failed", 0)),
        "BS_SSH_INVALID_USERS": str(counts.get("invalid_user", 0)),
        "BS_SSH_PENALTIES": str(counts.get("penalty", 0)),
    }
    try:
        result = subprocess.run([str(executable)], check=False, capture_output=True, text=True, timeout=10.0, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "failed", "reason": str(exc)}
    return {"status": "sent" if result.returncode == 0 else "failed", "returncode": result.returncode}


def ssh_audit(data: dict[str, Any]) -> list[dict[str, str]]:
    server = data["server"]
    summary = server["summary"]
    attacks = data["attacks"]
    findings = []
    if attacks.get("level") in {"elevated", "high"}:
        findings.append({"severity": "high", "title": "Sustained SSH credential scanning", "recommendation": "restrict inbound SSH to VPN or explicit admin source ranges before changing daemon policy"})
    if not server.get("firewall_rules"):
        findings.append({"severity": "medium", "title": "No explicit SSH firewall rule detected", "recommendation": "preview and apply an allowlist only after confirming an out-of-band recovery path"})
    if not server.get("source_restrictions"):
        findings.append({"severity": "medium", "title": "No SSH user/source restriction detected", "recommendation": "use AllowUsers and, where IPs are stable, USER@CIDR patterns"})
    for field, recommendation in (("allowtcpforwarding", "disable or limit TCP forwarding unless the admin workflow needs it"), ("allowagentforwarding", "disable agent forwarding unless explicitly needed")):
        if str(summary.get(field, "")).lower() == "yes":
            findings.append({"severity": "low", "title": f"{field} is enabled", "recommendation": recommendation})
    return findings
