# B-Suite MCP Monitor

[![CI](https://github.com/bohodigital/bsuite-mcp-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/bohodigital/bsuite-mcp-monitor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)

B-Suite is a lightweight, all-in-one Linux terminal dashboard for operating
MCP servers. It brings service health, local listeners, MCP runtime capability
state, proxy or tunnel reachability, command telemetry, usage limits, network
identity, SSH posture, and explicit authentication-health checks into one
practical operator view.

> **Quick description:** a single command-line control room for the Linux host
> that runs your MCP service, including its health, access posture, network
> path, and configured Codex or Claude Code usage limits.

It is designed for a single Linux host. It does not run a web service, send
telemetry, manage MCP configuration, or call write/secret tools.

```text
B-Suite MCP Monitor: production-mcp

MCP IP        up | 127.0.0.1:8765
HTTP mode     admin | 20 tools
Tunnel IP     up | 127.0.0.1:8080
Tunnel peer   203.0.113.18:443
Usage limits  5h 82% | week 94%
Commands      148 total | 0 errors
```

## Highlights

- `bs mcp`: detailed MCP server, proxy, and tunnel dashboard.
- `bs dash`: compact live system, network, SSH, and MCP overview.
- `bs auth`: read-only health for explicitly configured credential references.
- Configurable systemd units, loopback endpoints, health paths, MCP tool names,
  capability markers, and optional usage probes.
- Listener safety checks, outbound TLS visibility, process resource use,
  journal errors, and Prometheus-style tunnel metrics when available.
- Structured JSON for scripts and existing observability pipelines.
- Linux host, network, SSH, fan, and security views for the machine operating
  the MCP service.

## Requirements

- Linux with Python 3.11 or newer.
- `iproute2` (`ip`, `ss`), `systemd` (`systemctl`, `journalctl`), and access to
  the services or sockets you want to monitor.
- Optional: `geoip2` database for GeoLite enrichment, `sudo -n` for richer SSH
  and firewall inspection.

## Install

```bash
git clone https://github.com/bohodigital/bsuite-mcp-monitor.git
cd bsuite-mcp-monitor
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/bs --help
```

## Install Linux Tools

Python is the only prerequisite B-Suite does not install. After creating the
virtual environment, install the core non-Python Linux tools with:

```bash
sudo .venv/bin/bs doctor --install
```

This detects `apt-get`, `dnf`, or `pacman` and installs the core packages that
provide `ip`, `ss`, and `sudo`. For optional SSH, firewall, GeoIP, and packet
inspection tools:

```bash
sudo .venv/bin/bs doctor --install --install-extras
```

Package installation is never automatic during normal monitoring commands.
Use `bs doctor` first to see exactly what is missing.

For a user-local command:

```bash
mkdir -p ~/.local/bin
ln -sf "$PWD/.venv/bin/bs" ~/.local/bin/bs
```

## Configure an MCP Deployment

Copy the neutral example and set the unit names and loopback ports used by your
deployment:

```bash
mkdir -p ~/.config/bsuite
cp config.example.toml ~/.config/bsuite/config.toml
${EDITOR:-vi} ~/.config/bsuite/config.toml
bs mcp
```

Configuration lookup order is:

1. `bs mcp --config PATH` or `bs dash --config PATH`
2. `BS_CONFIG`
3. `~/.config/bsuite/config.toml`
4. `/etc/bsuite/config.toml`
5. Built-in default profile

The configured MCP and tunnel endpoints must be loopback addresses. This keeps
the tool focused on local operations rather than becoming a network scanner.
See [MCP configuration and monitoring](docs/mcp-monitoring.md) for every field.

## Common Commands

| Command | Purpose |
| --- | --- |
| `bs mcp` | Detailed MCP server, proxy, or tunnel health. |
| `bs mcp -w -i 2` | Refresh the MCP dashboard every two seconds. |
| `bs mcp -j` | Emit structured MCP monitoring JSON. |
| `bs mcp --config monitor.toml` | Monitor a named deployment profile. |
| `bs auth` | Check configured credential references without exposing secret values. |
| `bs auth --config auth.toml` | Use a named authentication-health profile. |
| `bs dash -w` | Live four-pane host and MCP summary. |
| `bs doctor --config monitor.toml` | Validate host visibility for a profile. |
| `bs security --config monitor.toml` | Combine SSH/firewall checks with MCP posture. |
| `bs net` | Inspect local addresses, routes, sockets, and traffic. |
| `bs ssh --history` | Inspect SSH listeners, sessions, and recent auth events. |

Hostname and GeoLite enrichment are on by default for public remote endpoints.
Use `--no-resolve` or `--no-geo` on `mcp`, `dash`, `net`, or `ssh` to disable
them. `--lookup-limit N` caps uncached enrichment work; `-1` is unlimited.

## Optional Usage Limits

When a Codex MCP server provides a read-only usage-limit tool, B-Suite records
its five-hour and weekly windows, reset times, credits, and token totals.
Operators can also configure a local read-only command as an explicit TOML
array. Set `usage.provider = "claude-code"` when monitoring Claude Code; its
documented CLI has no native read-only usage-limit command, so the configured
adapter must emit B-Suite's normalized JSON contract.

Usage collection is optional. Keep its command out of version control and treat
the profile file as operator-owned configuration.

## Authentication Health

`bs auth` verifies only the checks you explicitly configure. It supports
Cloudflare token verification, GitHub CLI authentication, loopback or HTTPS
health endpoints such as Umami, and custom read-only adapters for Google or
other providers. It never stores, displays, or accepts secret values in TOML.

```bash
mkdir -p ~/.config/bsuite
cp auth.example.toml ~/.config/bsuite/auth.toml
bs auth
```

See [authentication health](docs/auth-health.md) for the adapter contract and
the planned, private-only credential migration boundary.

## Validate a Checkout

```bash
.venv/bin/python -m compileall -q bs
.venv/bin/python -m pip wheel --no-deps --wheel-dir dist .
```

See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), and the
[configuration reference](docs/mcp-monitoring.md).

## License

[MIT](LICENSE), Copyright 2026 Bohol Digital.
