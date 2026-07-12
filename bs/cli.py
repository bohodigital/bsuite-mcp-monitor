from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from bs.config import ConfigError, MonitorConfig, load_monitor_config
from bs.collectors.doctor import collect_doctor, install_linux_tools
from bs.collectors.dashboard import collect_dashboard
from bs.collectors.enrichment import DEFAULT_LOOKUP_LIMIT
from bs.collectors.fan import PROFILES, auto_step, collect_fan, write_state
from bs.collectors.mcp import collect_mcp
from bs.collectors.network_detail import collect_network_detail
from bs.collectors.security import collect_security
from bs.collectors.ssh import collect_ssh
from bs.collectors.status import collect_status
from bs.render.dashboard import render_dash, render_dash_watch, render_status, render_watch
from bs.render.doctor import render_doctor
from bs.render.fan import render_fan, render_fan_step
from bs.render.mcp import render_mcp, render_mcp_watch
from bs.render.network import render_network, render_network_watch
from bs.render.security import render_security
from bs.render.ssh import render_ssh, render_ssh_watch


def add_watch_flags(parser: argparse.ArgumentParser, noun: str) -> None:
    parser.add_argument("-w", "--watch", action="store_true", help=f"Refresh the {noun} dashboard")
    parser.add_argument("-i", "--interval", type=float, default=2.0, help="Refresh interval in seconds")


def add_json_flag(parser: argparse.ArgumentParser, noun: str) -> None:
    parser.add_argument("-j", "--json", action="store_true", help=f"Print structured {noun} data")


def add_enrichment_flags(parser: argparse.ArgumentParser, target: str = "remote") -> None:
    parser.set_defaults(resolve=True, geo=True)
    parser.add_argument("--no-resolve", action="store_false", dest="resolve", help="Skip reverse DNS lookups")
    parser.add_argument("--no-geo", action="store_false", dest="geo", help="Skip GeoLite lookups")
    parser.add_argument("--geo-db", help="Path to a GeoLite2 or GeoIP2 .mmdb database")
    parser.add_argument("--lookup-limit", type=int, default=DEFAULT_LOOKUP_LIMIT, help="Maximum uncached DNS/GeoLite lookups per refresh; default -1 is unlimited")


def add_monitor_config_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="Path to an MCP monitor TOML profile")


def _monitor_config(args: argparse.Namespace) -> tuple[MonitorConfig, str] | None:
    try:
        return load_monitor_config(args.config)
    except ConfigError as exc:
        print(f"bs: invalid MCP monitor configuration: {exc}", file=sys.stderr)
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "B-Suite local system tools.\n\n"
            "Available commands:\n"
            "  status, st, stat System dashboard: CPU, memory, disks, mounts, temps, power, processes\n"
            "  dash             Summary dashboard: system, network, SSH, and MCP services\n"
            "  network, net     Network dashboard: interfaces, routes, DNS, sockets, traffic rates\n"
            "  ssh              SSH server posture: service, listeners, config, keys, sessions\n"
            "  fan              Fan status, manual fan state, and automatic cooling control\n"
            "  mcp              MCP server, proxy, and tunnel health\n"
            "  doctor           Dependency and visibility self-check\n"
            "  security         Local hardening review"
        ),
        epilog=(
            "Common examples:\n"
            "  bs status -a\n"
            "  bs status -w -i 1\n"
            "  bs dash -w\n"
            "  bs net\n"
            "  bs net -w -i 1\n"
            "  bs net --no-geo\n"
            "  bs ssh --history\n"
            "  bs ssh -w --history\n"
            "  bs fan status\n"
            "  bs fan auto --once\n"
            "  bs fan set 3\n"
            "  bs mcp\n"
            "  bs mcp -w\n"
            "  bs mcp --no-resolve\n"
            "  bs doctor\n"
            "  bs security\n\n"
            "Use 'bs <command> --help' for command-specific flags and examples."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser(
        "status",
        aliases=["st", "stat"],
        help="Show local system status",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Show a local system status dashboard.\n\n"
            "Includes host info, uptime, load, CPU, RAM, swap, temperatures, fan speed,\n"
            "Raspberry Pi throttle/voltage data when available, disks, mounts,\n"
            "top processes, and basic network counters."
        ),
        epilog=(
            "Examples:\n"
            "  bs status -a              Full one-shot dashboard\n"
            "  bs status -w              Live dashboard, refresh every 2 seconds\n"
            "  bs status -w -i 1         Live dashboard, refresh every 1 second\n"
            "  bs status -j              JSON output for scripts\n"
            "  bs st -a                  Same as 'bs status -a'\n"
            "  bs stat -a                Same as 'bs status -a'"
        ),
    )
    status.add_argument("-a", "--all", action="store_true", help="Show the full status printout")
    add_watch_flags(status, "status")
    add_json_flag(status, "status")

    dash = subparsers.add_parser(
        "dash",
        aliases=["dashboard"],
        help="Show a summary of system, network, SSH, and MCP status",
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Show a compact four-pane summary of the system, network, SSH, and MCP commands.\n\n"
            "Reverse DNS and GeoLite enrichment are enabled by default when data is available."
        ),
        epilog=(
            "Examples:\n"
            "  bs dash                       One-shot summary dashboard\n"
            "  bs dash -w -i 2               Live summary dashboard\n"
            "  bs dash --no-resolve          Skip reverse DNS lookups\n"
            "  bs dash --no-geo              Skip GeoLite lookups\n"
            "  bs dash -j                    Structured JSON output"
        ),
    )
    add_watch_flags(dash, "summary")
    add_json_flag(dash, "dashboard")
    add_enrichment_flags(dash)
    add_monitor_config_flag(dash)

    network = subparsers.add_parser(
        "network",
        aliases=["net"],
        help="Show network interfaces, routes, sockets, and traffic counters",
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Show network interfaces, routes, sockets, and traffic counters.\n\n"
            "Includes interface state, local IPs, RX/TX totals, RX/s and TX/s,\n"
            "default route, DNS servers, listening sockets, active sockets, and\n"
            "owning process/PID when visible."
        ),
        epilog=(
            "Examples:\n"
            "  bs net                         Network dashboard\n"
            "  bs network                     Same as 'bs net'\n"
            "  bs net -w -i 1                 Live network dashboard\n"
            "  bs net -j                      JSON output\n"
            "  bs net                         Includes reverse DNS and GeoLite by default\n"
            "  bs net --no-resolve            Skip reverse DNS lookups\n"
            "  bs net --no-geo                Skip GeoLite lookups\n"
            "  bs net --lookup-limit 20       Cap uncached DNS/GeoLite lookups\n"
            "  bs net --geo-db PATH           Use a specific GeoLite database\n\n"
            "GeoLite search order includes BS_GEOIP_DB, ~/.local/share/bs, /var/lib/GeoIP,\n"
            "and /usr/share/GeoIP. Private LAN IPs are not geolocated."
        ),
    )
    add_watch_flags(network, "network")
    add_json_flag(network, "network")
    add_enrichment_flags(network)

    ssh = subparsers.add_parser(
        "ssh",
        help="Show current and recent SSH activity",
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Show current SSH connections and recent SSH authentication events.\n\n"
            "Default output focuses on the SSH server: service state, listeners,\n"
            "effective sshd config, source/user restrictions, and authorized key\n"
            "fingerprints. Current sessions are detected from sockets on port 22.\n"
            "History is parsed from the ssh/sshd systemd journal with --history."
        ),
        epilog=(
            "Examples:\n"
            "  bs ssh                         SSH server posture and current sessions\n"
            "  bs ssh --history               Include recent auth events\n"
            "  bs ssh -w --history            Live SSH dashboard with history\n"
            "  bs ssh --history -n 200        Inspect more journal lines\n"
            "  bs ssh                         Includes reverse DNS and GeoLite by default\n"
            "  bs ssh --no-resolve            Skip reverse DNS lookups\n"
            "  bs ssh --no-geo                Skip GeoLite lookups\n"
            "  bs ssh --lookup-limit 20       Cap uncached DNS/GeoLite lookups\n"
            "  bs ssh --geo-db PATH           Use a specific GeoLite database\n\n"
            "GeoLite search order includes BS_GEOIP_DB, ~/.local/share/bs, /var/lib/GeoIP,\n"
            "and /usr/share/GeoIP. Private LAN IPs are not geolocated."
        ),
    )
    add_watch_flags(ssh, "SSH")
    add_json_flag(ssh, "SSH")
    ssh.add_argument("-H", "--history", action="store_true", help="Include recent SSH journal events")
    ssh.add_argument("-n", "--lines", type=int, default=80, help="Journal lines to inspect for SSH history")
    add_enrichment_flags(ssh)

    fan = subparsers.add_parser(
        "fan",
        help="Show and control the system fan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Show and control the Raspberry Pi pwm-fan cooling device.\n\n"
            "The controller uses /sys/class/thermal/cooling_device0/cur_state as\n"
            "the primary control path and reads CPU temperature from thermal_zone0.\n"
            "State 0 is off; the detected max state is usually 4."
        ),
        epilog=(
            "Examples:\n"
            "  bs fan status                  Show temp, fan state, PWM, RPM\n"
            "  bs fan set 2                   Manually set fan state 2\n"
            "  bs fan set 4                   Full fan\n"
            "  bs fan auto --once             Run one automatic control step\n"
            "  bs fan auto                    Keep controlling the fan until stopped\n"
            "  bs fan auto --profile cool     Aggressive cooling curve\n"
            "  bs fan auto --profile quiet    Quieter cooling curve\n\n"
            "Profiles:\n"
            "  quiet:    state up at 52/60/67/74 C\n"
            "  balanced: state up at 48/56/64/70 C\n"
            "  cool:     state up at 43/50/58/65 C\n\n"
            "Writing fan state requires root. The command will use sudo -n when needed."
        ),
    )
    fan_sub = fan.add_subparsers(dest="fan_command", required=True)
    fan_status = fan_sub.add_parser("status", help="Show fan temperature, state, PWM, and RPM")
    fan_status.add_argument("-j", "--json", action="store_true", help="Print structured fan data")
    fan_set = fan_sub.add_parser("set", help="Manually set fan cooling state")
    fan_set.add_argument("state", type=int, help="Cooling state, usually 0 through 4")
    fan_set.add_argument("-j", "--json", action="store_true", help="Print structured result")
    fan_auto = fan_sub.add_parser("auto", help="Run the automatic fan controller")
    fan_auto.add_argument("-p", "--profile", choices=sorted(PROFILES), default="cool", help="Cooling curve profile")
    fan_auto.add_argument("-i", "--interval", type=float, default=5.0, help="Seconds between control steps")
    fan_auto.add_argument("--once", action="store_true", help="Run one control step and exit")
    fan_auto.add_argument("-j", "--json", action="store_true", help="Print structured step data")

    mcp = subparsers.add_parser(
        "mcp",
        help="Show local MCP server, proxy, and tunnel health",
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Inspect local MCP server, proxy, or tunnel health from a Linux host.\n\n"
            "It checks configured systemd services, local listeners, TCP/HTTP probes,\n"
            "MCP runtime state, process resource use, recent journal activity,\n"
            "and bind-safety warnings."
        ),
        epilog=(
            "Examples:\n"
            "  bs mcp                         MCP monitoring dashboard\n"
            "  bs mcp -w -i 2                 Live MCP monitoring dashboard\n"
            "  bs mcp --config monitor.toml   Use a deployment profile\n"
            "  bs mcp -j                      JSON output\n"
            "  bs mcp                         Includes reverse DNS and GeoLite by default\n"
            "  bs mcp --no-resolve            Skip reverse DNS lookups\n"
            "  bs mcp --no-geo                Skip GeoLite lookups\n"
            "  bs mcp --lookup-limit 20       Cap uncached DNS/GeoLite lookups\n"
            "  bs mcp -n 100                  Inspect more journal lines\n\n"
            "Use config.example.toml as a starting point for service names, ports,\n"
            "health paths, and optional MCP usage-limit probes."
        ),
    )
    add_watch_flags(mcp, "MCP")
    add_json_flag(mcp, "MCP")
    mcp.add_argument("-n", "--lines", type=int, default=40, help="Journal lines to inspect")
    add_enrichment_flags(mcp, "tunnel remote")
    add_monitor_config_flag(mcp)

    doctor = subparsers.add_parser(
        "doctor",
        help="Check B-Suite dependencies and host visibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Run local self-checks for tools, Python packages, GeoLite databases, system visibility, loopback probes, sudo, and install path.",
        epilog=(
            "Examples:\n"
            "  bs doctor\n"
            "  bs doctor -j\n"
            "  sudo bs doctor --install\n"
            "  sudo bs doctor --install --install-extras"
        ),
    )
    add_json_flag(doctor, "doctor")
    add_monitor_config_flag(doctor)
    doctor.add_argument("--install", action="store_true", help="Install core non-Python Linux dependencies; requires root")
    doctor.add_argument("--install-extras", action="store_true", help="Also install optional SSH, firewall, GeoIP, and packet tools; requires root")

    security = subparsers.add_parser(
        "security",
        aliases=["sec"],
        help="Show local hardening findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Review SSH, firewall, MCP/tunnel, secret-file, mount, and update posture from the local machine.",
        epilog=(
            "Examples:\n"
            "  bs security\n"
            "  bs sec\n"
            "  bs security -j"
        ),
    )
    add_json_flag(security, "security")
    add_monitor_config_flag(security)

    return parser


def run_status(args: argparse.Namespace) -> int:
    if args.watch:
        render_watch(interval=max(args.interval, 0.5))
        return 0

    data: dict[str, Any] = collect_status()
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    render_status(data, show_all=args.all)
    return 0


def run_dash(args: argparse.Namespace) -> int:
    profile = _monitor_config(args)
    if profile is None:
        return 2
    config, config_source = profile
    if args.watch:
        render_dash_watch(
            interval=max(args.interval, 0.5),
            resolve=args.resolve,
            geo=args.geo,
            geo_db=args.geo_db,
            lookup_limit=args.lookup_limit,
            monitor_config=config,
            monitor_config_source=config_source,
        )
        return 0

    data = collect_dashboard(resolve=args.resolve, geo=args.geo, geo_db=args.geo_db, lookup_limit=args.lookup_limit, monitor_config=config, monitor_config_source=config_source)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    render_dash(data)
    return 0


def run_network(args: argparse.Namespace) -> int:
    if args.watch:
        render_network_watch(
            interval=max(args.interval, 0.5),
            resolve=args.resolve,
            geo=args.geo,
            geo_db=args.geo_db,
            lookup_limit=args.lookup_limit,
        )
        return 0

    data = collect_network_detail(resolve=args.resolve, geo=args.geo, geo_db=args.geo_db, lookup_limit=args.lookup_limit)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    render_network(data)
    return 0


def run_ssh(args: argparse.Namespace) -> int:
    if args.watch:
        render_ssh_watch(
            interval=max(args.interval, 0.5),
            include_history=args.history,
            lines=args.lines,
            resolve=args.resolve,
            geo=args.geo,
            geo_db=args.geo_db,
            lookup_limit=args.lookup_limit,
        )
        return 0

    data = collect_ssh(
        include_history=args.history,
        lines=args.lines,
        resolve=args.resolve,
        geo=args.geo,
        geo_db=args.geo_db,
        lookup_limit=args.lookup_limit,
    )
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    render_ssh(data)
    return 0


def run_fan(args: argparse.Namespace) -> int:
    if args.fan_command == "status":
        data = collect_fan()
        if args.json:
            print(json.dumps(data, indent=2, sort_keys=True))
        else:
            render_fan(data)
        return 0

    if args.fan_command == "set":
        write_state(args.state)
        data = collect_fan()
        if args.json:
            print(json.dumps(data, indent=2, sort_keys=True))
        else:
            render_fan(data)
        return 0

    if args.fan_command == "auto":
        if args.once:
            data = auto_step(args.profile)
            if args.json:
                print(json.dumps(data, indent=2, sort_keys=True))
            else:
                render_fan_step(data)
            return 0

        while True:
            data = auto_step(args.profile)
            if args.json:
                print(json.dumps(data, sort_keys=True), flush=True)
            else:
                render_fan_step(data)
            time.sleep(max(args.interval, 1.0))

    raise ValueError(f"unknown fan command: {args.fan_command}")


def run_mcp(args: argparse.Namespace) -> int:
    profile = _monitor_config(args)
    if profile is None:
        return 2
    config, config_source = profile
    if args.watch:
        render_mcp_watch(
            interval=max(args.interval, 0.5),
            lines=args.lines,
            resolve=args.resolve,
            geo=args.geo,
            geo_db=args.geo_db,
            lookup_limit=args.lookup_limit,
            config=config,
            config_source=config_source,
        )
        return 0

    data = collect_mcp(lines=args.lines, resolve=args.resolve, geo=args.geo, geo_db=args.geo_db, lookup_limit=args.lookup_limit, config=config, config_source=config_source)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    render_mcp(data)
    return 0


def run_doctor(args: argparse.Namespace) -> int:
    profile = _monitor_config(args)
    if profile is None:
        return 2
    config, _ = profile
    installation = install_linux_tools(include_extras=args.install_extras) if args.install or args.install_extras else None
    data = collect_doctor(config)
    if installation:
        data["installation"] = installation
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0 if not installation or installation["ok"] else 2
    render_doctor(data)
    return 0 if not installation or installation["ok"] else 2


def run_security(args: argparse.Namespace) -> int:
    profile = _monitor_config(args)
    if profile is None:
        return 2
    config, config_source = profile
    data = collect_security(config, config_source)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    render_security(data)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command in {"status", "st", "stat"}:
        return run_status(args)
    if args.command in {"dash", "dashboard"}:
        return run_dash(args)
    if args.command in {"network", "net"}:
        return run_network(args)
    if args.command == "ssh":
        return run_ssh(args)
    if args.command == "fan":
        return run_fan(args)
    if args.command == "mcp":
        return run_mcp(args)
    if args.command == "doctor":
        return run_doctor(args)
    if args.command in {"security", "sec"}:
        return run_security(args)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
