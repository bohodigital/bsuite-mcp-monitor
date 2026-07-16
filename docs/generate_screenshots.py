"""Render safe, reproducible terminal screenshots for the public documentation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from bs.render.ssh import build_ssh_renderable


OUTPUT = Path(__file__).parent / "screenshots"


def save_svg(console: Console, name: str, title: str) -> None:
    path = OUTPUT / name
    console.save_svg(str(path), title=title)
    # Rich's SVG exporter can leave trailing spaces in text nodes; keep git diffs clean.
    path.write_text("\n".join(line.rstrip() for line in path.read_text(encoding="utf-8").splitlines()) + "\n", encoding="utf-8")


def save_setup() -> None:
    console = Console(record=True, width=118, force_terminal=True, color_system="truecolor")
    steps = Table.grid(expand=True)
    steps.add_column(style="bold cyan", width=4)
    steps.add_column()
    steps.add_row("1", "Create a known-good baseline after reviewing the live SSH policy.")
    steps.add_row("2", "Append count-only snapshots from a timer, cron job, or existing scheduler.")
    steps.add_row("3", "Run the audit and add an absolute-path notification hook when ready.")
    commands = Syntax(
        """bs ssh --write-baseline ~/.local/state/bsuite/ssh-baseline.json
bs ssh --baseline ~/.local/state/bsuite/ssh-baseline.json \\
  --snapshot ~/.local/state/bsuite/ssh-attacks.jsonl \\
  --trend ~/.local/state/bsuite/ssh-attacks.jsonl \\
  --audit
bs ssh --alert-command /usr/local/libexec/bs-ssh-alert --alert-level high""",
        "bash",
        theme="monokai",
        line_numbers=False,
    )
    console.print("[bold]B-Suite SSH Monitoring[/bold]\n[dim]Baseline, trends, audit, and optional alerts[/dim]")
    console.print(Panel(steps, title="Configuration Steps"))
    console.print(Panel(commands, title="Operator Commands"))
    save_svg(console, "ssh-configuration.svg", "B-Suite SSH monitoring configuration")


def dashboard_data() -> dict:
    return {
        "geo_database": "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "attacks": {
            "available": True,
            "level": "guarded",
            "window_hours": 24,
            "first_seen": "2026-07-15T00:00:00Z",
            "last_seen": "2026-07-15T23:59:00Z",
            "counts": {"accepted": 18, "failed": 7, "invalid_user": 4, "preauth": 11, "penalty": 3, "transport": 1},
            "sources": [
                {"ip": "203.0.113.42", "signals": 8, "failed": 4, "invalid_user": 2, "preauth": 2, "penalty": 1, "transport": 0, "last_seen": "2026-07-15T22:41:00Z", "hostname": "scanner.example.net", "geo": {"available": True, "city": "Example City", "country": "US"}},
                {"ip": "198.51.100.25", "signals": 5, "failed": 3, "invalid_user": 2, "preauth": 0, "penalty": 1, "transport": 0, "last_seen": "2026-07-15T18:12:00Z", "hostname": "probe.example.org", "geo": {"available": True, "city": "Example Town", "country": "CA"}},
            ],
            "recent": [
                {"time": "2026-07-15T22:41:00Z", "type": "failed", "user": "root", "ip": "203.0.113.42", "raw": "sshd: Failed password for root from 203.0.113.42 port 51000 ssh2"},
                {"time": "2026-07-15T22:41:01Z", "type": "penalty", "user": "", "ip": "203.0.113.42", "raw": "sshd: source penalty applied after repeated failed authentication"},
            ],
        },
        "server": {
            "service": {"active": "active", "enabled": "enabled"},
            "listeners": [{"local": {"address": "0.0.0.0", "port": 22}}, {"local": {"address": "::", "port": 22}}],
            "listening_ips": [{"address": "192.0.2.10", "port": 22, "interface": "eth0"}],
            "summary": {
                "ports": "22", "listenaddress": "any", "pubkeyauthentication": "yes", "passwordauthentication": "no", "permitrootlogin": "no", "kbdinteractiveauthentication": "no", "authenticationmethods": "publickey", "maxauthtries": "3", "logingracetime": "20", "maxstartups": "10:30:60", "persourcemaxstartups": "3", "persourcepenalties": "authfail:5 noauth:1", "persourcenetblocksize": "32:128", "maxsessions": "10", "allowusers": "operator", "allowgroups": "not set", "denyusers": "not set", "denygroups": "not set", "x11forwarding": "no", "allowtcpforwarding": "no", "allowagentforwarding": "no", "disableforwarding": "no", "gatewayports": "no", "permituserenvironment": "no", "permitemptypasswords": "no", "loglevel": "VERBOSE",
            },
            "source_restrictions": [{"file": "/etc/ssh/sshd_config.d/00-hardening.conf", "rule": "AllowUsers operator@192.0.2.0/24"}],
            "firewall_rules": [{"source": "nft", "rule": "tcp dport 22 ip saddr @admin_networks accept"}],
            "authorized_keys": [{"user": "operator", "readable": True, "valid": True, "type": "ssh-ed25519", "fingerprint": "SHA256:EXAMPLEfingerprint", "comment": "admin-laptop", "path": "/home/operator/.ssh/authorized_keys", "line": 1}],
        },
        "current": [{"remote": {"address": "192.0.2.22", "port": 51234}, "local": {"address": "192.0.2.10", "port": 22}, "pid": 4242, "process": "sshd-session", "uptime": "14m", "remote_hostname": "admin.example.net", "geo": {"available": True, "city": "Example City", "country": "US"}, "local_geo": {"available": False, "reason": "private documentation address"}}],
        "history": [],
        "baseline": {"status": "match", "path": "~/.local/state/bsuite/ssh-baseline.json", "changes": []},
        "snapshot": {"status": "recorded", "path": "~/.local/state/bsuite/ssh-attacks.jsonl", "record": {"timestamp": "2026-07-15T23:59:00Z", "level": "guarded", "counts": {"failed": 7, "invalid_user": 4, "penalty": 3}}},
        "trend": {"status": "available", "path": "~/.local/state/bsuite/ssh-attacks.jsonl", "records": [{"timestamp": "2026-07-14T23:59:00Z", "level": "clear", "counts": {"failed": 0, "invalid_user": 0, "penalty": 0}}, {"timestamp": "2026-07-15T23:59:00Z", "level": "guarded", "counts": {"failed": 7, "invalid_user": 4, "penalty": 3}}]},
        "audit": [{"severity": "medium", "title": "Sustained SSH credential scanning", "recommendation": "Review allowlist coverage and alert routing."}],
        "alert": {"status": "sent", "minimum_level": "guarded"},
    }


def save_dashboard() -> None:
    console = Console(record=True, width=150, force_terminal=True, color_system="truecolor")
    console.print(build_ssh_renderable(dashboard_data()))
    save_svg(console, "ssh-dashboard.svg", "B-Suite SSH dashboard")


if __name__ == "__main__":
    OUTPUT.mkdir(parents=True, exist_ok=True)
    save_setup()
    save_dashboard()
