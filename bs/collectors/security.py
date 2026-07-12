from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from bs.config import MonitorConfig
from bs.collectors.common import run_command
from bs.collectors.disk import collect_mounts
from bs.collectors.mcp import collect_mcp
from bs.collectors.result import meta
from bs.collectors.ssh import collect_ssh_server


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}


def _finding(severity: str, area: str, title: str, detail: str, recommendation: str = "") -> dict[str, str]:
    return {
        "severity": severity,
        "area": area,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    }


def _value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _ssh_findings() -> tuple[dict[str, Any], list[dict[str, str]]]:
    server = collect_ssh_server()
    summary = server["summary"]
    findings: list[dict[str, str]] = []

    if server["service"]["active"] != "active":
        findings.append(_finding("high", "ssh", "SSH service not confirmed active", f"{server['service']['active']} / {server['service']['enabled']}", "confirm intended SSH service state"))

    listeners = server.get("listeners", [])
    wildcard = [sock for sock in listeners if sock["local"]["address"] in {"0.0.0.0", "::", "*"}]
    if wildcard:
        findings.append(_finding("medium", "ssh", "SSH listens on wildcard addresses", ", ".join(f"{sock['local']['address']}:{sock['local']['port']}" for sock in wildcard), "restrict ListenAddress or enforce firewall source rules"))

    if _value(summary.get("passwordauthentication")).lower() == "yes":
        findings.append(_finding("high", "ssh", "Password authentication is enabled", "passwordauthentication yes", "prefer public-key-only SSH for this hub"))

    permit_root = _value(summary.get("permitrootlogin")).lower()
    if permit_root not in {"no", ""}:
        findings.append(_finding("medium", "ssh", "Root SSH login is not fully disabled", f"permitrootlogin {permit_root}", "set PermitRootLogin no unless explicitly required"))

    if not server.get("source_restrictions"):
        findings.append(_finding("medium", "ssh", "No SSH source/user restrictions found", "no AllowUsers/DenyUsers/Match Address rules", "add AllowUsers and/or Match Address rules for expected admin clients"))

    if not server.get("firewall_rules"):
        findings.append(_finding("medium", "firewall", "No explicit SSH firewall rule found", "no nftables/iptables rule references SSH port 22", "restrict port 22 to known LAN/VPN/admin IPs"))

    for key in ("x11forwarding", "allowtcpforwarding", "allowagentforwarding"):
        if _value(summary.get(key)).lower() == "yes":
            findings.append(_finding("low", "ssh", f"{key} is enabled", f"{key} yes", "disable unless this hub needs it"))

    return server, findings


def _ssh_file_findings() -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.exists():
        return [_finding("info", "secrets", "No ~/.ssh directory", str(ssh_dir), "create it only when needed")]
    try:
        entries = list(ssh_dir.iterdir())
    except OSError as exc:
        return [_finding("low", "secrets", "Cannot inspect ~/.ssh", str(exc), "check permissions manually")]

    for path in entries:
        try:
            st = path.stat()
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        if path.is_file() and path.name not in {"authorized_keys", "known_hosts", "config"} and not path.name.endswith(".pub"):
            if mode & 0o077:
                findings.append(_finding("high", "secrets", "Private SSH key is group/world accessible", f"{path} mode {mode:o}", "chmod 600 private keys"))
        if path.name == "authorized_keys" and mode & 0o022:
            findings.append(_finding("medium", "secrets", "authorized_keys is writable by group/other", f"{path} mode {mode:o}", "chmod 600 authorized_keys"))
    return findings


def _firewall_findings() -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    nft = run_command(["sudo", "-n", "nft", "list", "ruleset"], timeout=2.0)
    if nft is None:
        findings.append(_finding("medium", "firewall", "Cannot inspect nftables ruleset", "sudo -n nft list ruleset unavailable", "grant read-only sudo for nft or inspect manually"))
    elif not nft.strip():
        findings.append(_finding("medium", "firewall", "nftables ruleset is empty", "no nftables rules returned", "define an allowlist firewall policy before exposing this hub"))
    return findings


def _mcp_findings(config: MonitorConfig | None = None, config_source: str | None = None) -> tuple[dict[str, Any], list[dict[str, str]]]:
    kwargs: dict[str, Any] = {"lines": 40, "lookup_limit": 10}
    if config is not None:
        kwargs.update({"config": config, "config_source": config_source})
    data = collect_mcp(**kwargs)
    findings: list[dict[str, str]] = []
    for warning in data.get("warnings", []):
        severity = "low" if warning.startswith("limited view") else "medium"
        findings.append(_finding(severity, "mcp", "MCP/tunnel warning", warning, "run bs mcp for details"))
    target = data.get("target", {})
    target_flags = target.get("security_flags", {})
    if not target_flags:
        profile = config or MonitorConfig()
        target_value = str(target.get("value") or "")
        target_flags = {
            "write_tools_enabled": bool(profile.write_tools_environment and profile.write_tools_environment in target_value),
            "secret_tools_enabled": bool(profile.secret_tools_environment and profile.secret_tools_environment in target_value),
        }
    service_flags = data.get("services", {}).get("mcp", {}).get("security_flags", {})
    if service_flags.get("secret_tools_enabled"):
        findings.append(_finding("high", "mcp", "MCP service configuration enables secret tools", "configured secret-tool marker is active", "disable it in the service unit unless the HTTP MCP service is required"))
    if service_flags.get("write_tools_enabled"):
        findings.append(_finding("medium", "mcp", "MCP service configuration enables write tools", "configured write-tool marker is active", "disable it in the service unit unless the HTTP MCP service is required"))
    if target_flags.get("secret_tools_enabled"):
        findings.append(_finding("high", "mcp", "MCP secret tools are enabled", "configured secret-tool marker is active", "disable secret tools unless actively needed"))
    if target_flags.get("write_tools_enabled"):
        findings.append(_finding("medium", "mcp", "MCP write tools are enabled", "configured write-tool marker is active", "keep write tools scoped and audited"))
    return data, findings


def _mount_findings() -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    mounts = collect_mounts()
    by_mount = {item["mountpoint"]: item for item in mounts}
    root = by_mount.get("/")
    boot = by_mount.get("/boot/firmware")
    if root and not root.get("writable"):
        findings.append(_finding("info", "mounts", "Root filesystem appears read-only", "/", "expected only in restricted/sandboxed views or intentional read-only mode"))
    if boot and boot.get("writable"):
        findings.append(_finding("low", "mounts", "Boot firmware partition is writable", "/boot/firmware", "remount read-only if you want a tighter appliance posture"))
    return findings


def _update_findings() -> list[dict[str, str]]:
    output = run_command(["apt", "list", "--upgradable"], timeout=4.0)
    if output is None:
        return [_finding("info", "updates", "Cannot inspect apt upgrades", "apt list --upgradable unavailable", "run apt update/list manually")]
    packages = [line for line in output.splitlines() if line and not line.startswith("Listing")]
    if packages:
        severity = "medium" if len(packages) >= 10 else "low"
        return [_finding(severity, "updates", "Packages are upgradable", f"{len(packages)} packages", "review and patch during a maintenance window")]
    return [_finding("ok", "updates", "No apt upgrades reported", "apt list --upgradable returned no packages")]


def collect_security(config: MonitorConfig | None = None, config_source: str | None = None) -> dict[str, Any]:
    server, ssh_findings = _ssh_findings()
    mcp, mcp_findings = _mcp_findings(config, config_source)
    findings = ssh_findings + _ssh_file_findings() + _firewall_findings() + mcp_findings + _mount_findings() + _update_findings()
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["area"], item["title"]))
    counts = {severity: sum(1 for item in findings if item["severity"] == severity) for severity in ("high", "medium", "low", "info", "ok")}
    warnings = [item["title"] for item in findings if item["severity"] in {"high", "medium"}]
    ssh_summary = {
        "service": server["service"],
        "listeners": [f"{sock['local']['address']}:{sock['local']['port']}" for sock in server.get("listeners", [])],
        "settings": server["summary"],
        "source_restrictions": len(server.get("source_restrictions", [])),
        "firewall_rules": len(server.get("firewall_rules", [])),
        "authorized_keys": len(server.get("authorized_keys", [])),
    }
    target = mcp.get("target", {})
    target_flags = target.get("security_flags", {})
    mcp_summary = {
        "visibility_limited": mcp.get("visibility_limited", False),
        "warnings": mcp.get("warnings", []),
        "target": {
            "kind": target.get("kind"),
            "transport": target.get("transport"),
            "profile": target.get("profile"),
            "source": target.get("source"),
            "write_tools_enabled": target_flags.get("write_tools_enabled", False),
            "secret_tools_enabled": target_flags.get("secret_tools_enabled", False),
        },
        "services": {
            role: {
                "active_state": service.get("active_state"),
                "sub_state": service.get("sub_state"),
                "enabled": service.get("enabled"),
                "main_pid": service.get("main_pid"),
                "security_flags": service.get("security_flags", {}),
            }
            for role, service in mcp.get("services", {}).items()
        },
        "listeners": [f"{item['role']} {item['local']['address']}:{item['local']['port']}" for item in mcp.get("listeners", [])],
        "tunnel_outbound": [f"{item['peer']['address']}:{item['peer']['port']}" for item in mcp.get("tunnel_outbound", [])],
    }
    return {
        "_meta": meta("security", available=True, limited=bool(mcp.get("visibility_limited")), reason=", ".join(warnings[:3]) if warnings else None, source="ssh/firewall/mcp/filesystem/apt", warnings=warnings),
        "summary": counts,
        "ssh": ssh_summary,
        "mcp": mcp_summary,
        "findings": findings,
    }
