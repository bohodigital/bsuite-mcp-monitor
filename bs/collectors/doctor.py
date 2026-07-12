from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from bs.config import MonitorConfig
from bs.collectors.geo import find_geo_dbs
from bs.collectors.result import meta


TOOLS = (
    ("ip", "network interfaces/routes"),
    ("ss", "socket inventory"),
    ("systemctl", "service state"),
    ("journalctl", "service logs"),
    ("sudo", "privileged probes"),
    ("sshd", "effective SSH config"),
    ("nft", "nftables firewall"),
    ("iptables", "legacy firewall fallback"),
    ("vcgencmd", "Raspberry Pi power/thermal data"),
    ("geoipupdate", "GeoLite updates"),
    ("tcpdump", "packet capture"),
    ("tshark", "Wireshark CLI"),
)

PACKAGE_PLANS = {
    "apt-get": {
        "core": ("iproute2", "sudo"),
        "extras": ("openssh-server", "nftables", "geoipupdate", "tcpdump", "tshark"),
    },
    "dnf": {
        "core": ("iproute", "sudo"),
        "extras": ("openssh-server", "nftables", "geoipupdate", "tcpdump", "wireshark-cli"),
    },
    "pacman": {
        "core": ("iproute2", "sudo"),
        "extras": ("openssh", "nftables", "geoipupdate", "tcpdump", "wireshark-cli"),
    },
}


def _check(status: str, category: str, name: str, detail: str, hint: str = "") -> dict[str, str]:
    return {"status": status, "category": category, "name": name, "detail": detail, "hint": hint}


def _run(args: list[str], timeout: float = 2.0) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return None


def _tcp_probe(host: str, port: int) -> tuple[bool, str]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True, f"{round((time.monotonic() - started) * 1000, 1)} ms"
    except OSError as exc:
        return False, str(exc)


def _package_manager() -> str | None:
    return next((manager for manager in PACKAGE_PLANS if shutil.which(manager)), None)


def _install_commands(manager: str, packages: tuple[str, ...]) -> list[list[str]]:
    if manager == "apt-get":
        return [["apt-get", "update"], ["apt-get", "install", "-y", *packages]]
    if manager == "dnf":
        return [["dnf", "install", "-y", *packages]]
    return [["pacman", "--noconfirm", "-Sy", *packages]]


def install_linux_tools(include_extras: bool = False) -> dict[str, Any]:
    if os.geteuid() != 0:
        return {
            "ok": False,
            "manager": None,
            "packages": [],
            "message": "run sudo bs doctor --install to install Linux dependencies",
        }
    manager = _package_manager()
    if not manager:
        return {
            "ok": False,
            "manager": None,
            "packages": [],
            "message": "no supported package manager found (apt-get, dnf, or pacman)",
        }
    plan = PACKAGE_PLANS[manager]
    packages = tuple(plan["core"] + (plan["extras"] if include_extras else ()))
    for command in _install_commands(manager, packages):
        result = _run(command, timeout=300.0)
        if result is None:
            return {"ok": False, "manager": manager, "packages": list(packages), "message": f"could not run {' '.join(command[:2])}"}
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            return {"ok": False, "manager": manager, "packages": list(packages), "message": detail[-1] if detail else f"{' '.join(command[:2])} failed"}
    return {"ok": True, "manager": manager, "packages": list(packages), "message": "Linux dependencies installed"}


def collect_doctor(config: MonitorConfig | None = None) -> dict[str, Any]:
    config = config or MonitorConfig()
    checks: list[dict[str, str]] = []

    for tool, purpose in TOOLS:
        path = shutil.which(tool)
        if path:
            checks.append(_check("ok", "tool", tool, path))
        else:
            severity = "warn" if tool in {"vcgencmd", "geoipupdate", "tcpdump", "tshark", "iptables"} else "fail"
            checks.append(_check(severity, "tool", tool, f"missing; needed for {purpose}", f"install {tool} if this view matters"))

    for package in ("rich", "geoip2"):
        found = importlib.util.find_spec(package) is not None
        checks.append(
            _check(
                "ok" if found else "fail",
                "python",
                package,
                "installed" if found else "not importable",
                ".venv/bin/python -m pip install -e ." if not found else "",
            )
        )

    dbs = find_geo_dbs()
    if dbs:
        checks.append(_check("ok", "geoip", "GeoLite databases", ", ".join(f"{name}: {path}" for name, path in sorted(dbs.items()))))
    else:
        checks.append(_check("warn", "geoip", "GeoLite databases", "no .mmdb database found", "run geoipupdate or set BS_GEOIP_DB"))

    systemctl = _run(["systemctl", "show", config.tunnel_service, "--property=ActiveState", "--no-pager"])
    if systemctl and systemctl.returncode == 0 and "ActiveState=" in systemctl.stdout:
        checks.append(_check("ok", "visibility", "systemd", systemctl.stdout.strip()))
    else:
        detail = (systemctl.stderr or systemctl.stdout).strip() if systemctl else "systemctl unavailable"
        checks.append(_check("warn", "visibility", "systemd", detail or "systemd state hidden", "run from host context for full service state"))

    ss = _run(["ss", "-H", "-tunap"])
    if ss and ss.returncode == 0 and ss.stdout.strip():
        checks.append(_check("ok", "visibility", "sockets", f"{len(ss.stdout.splitlines())} socket rows visible"))
    else:
        detail = (ss.stderr or ss.stdout).strip() if ss else "ss unavailable"
        checks.append(_check("warn", "visibility", "sockets", detail or "socket list hidden", "run from host context for process/socket owners"))

    ok, detail = _tcp_probe(config.tunnel_host, config.tunnel_port)
    checks.append(_check("ok" if ok else "warn", "visibility", f"loopback {config.tunnel_host}:{config.tunnel_port}", detail, "needed for configured tunnel health probes"))

    sudo = _run(["sudo", "-n", "true"])
    checks.append(
        _check(
            "ok" if sudo and sudo.returncode == 0 else "warn",
            "sudo",
            "passwordless sudo",
            "available" if sudo and sudo.returncode == 0 else "not available for this process",
            "some security/firewall views will be partial without sudo -n",
        )
    )

    bs_path = shutil.which("bs")
    expected = str(Path.cwd() / ".venv" / "bin" / "bs")
    checks.append(_check("ok" if bs_path else "warn", "install", "bs on PATH", bs_path or "not found", f"expected local script near {expected}"))
    checks.append(_check("ok", "python", "interpreter", sys.executable))
    checks.append(_check("ok" if os.access(Path.cwd(), os.W_OK) else "warn", "filesystem", "workspace writable", str(Path.cwd())))

    counts = {name: sum(1 for check in checks if check["status"] == name) for name in ("ok", "warn", "fail")}
    warnings = [check["name"] for check in checks if check["status"] in {"warn", "fail"}]
    return {
        "_meta": meta("doctor", available=True, limited=bool(warnings), reason=", ".join(warnings[:3]) if warnings else None, source="local probes", warnings=warnings),
        "summary": counts,
        "checks": checks,
    }
