# Command Reference

All commands support `-h` or `--help`. JSON output is intended for local
automation and contains no configured secret values.

## Host Status

| Command | What it does |
| --- | --- |
| `bs status` / `bs st` / `bs stat` | Compact CPU, memory, disk, thermal, power, process, and network state. |
| `bs status -a` | Full status output. |
| `bs status -w -i 2` | Live status dashboard. |
| `bs status -j` | Structured status JSON. |

## Summary Dashboard

| Command | What it does |
| --- | --- |
| `bs dash` | Combined system, network, SSH, and MCP view. |
| `bs dash -w -i 2` | Live combined dashboard. |
| `bs dash -j` | Structured dashboard JSON. |
| `bs dash --config PATH` | Select an MCP monitor profile. |
| `--no-resolve`, `--no-geo`, `--geo-db PATH`, `--lookup-limit N` | Disable or tune remote IP enrichment. |

## Network And SSH

| Command | What it does |
| --- | --- |
| `bs net` / `bs network` | Interfaces, addresses, routes, DNS, listeners, connections, and traffic. |
| `bs net -w -i 2` | Live network dashboard. |
| `bs net -j` | Structured network JSON. |
| `bs ssh` | SSH exposure, 24-hour attack summary, listeners, settings, keys, and sessions. |
| `bs ssh --attack-window 6` | Summarize the last six hours of SSH attack signals. |
| `bs ssh --history -n 80` | Add recent SSH journal events. |
| `bs ssh -w --history` | Live SSH dashboard with history. |

`net`, `ssh`, `mcp`, and `dash` resolve hostnames and locate public IPs by
default. Use `--no-resolve` or `--no-geo` only when those lookups are unwanted.

## MCP And Tunnel

| Command | What it does |
| --- | --- |
| `bs mcp` | Service state, listeners, health probes, MCP capability state, tunnel telemetry, and usage limits. |
| `bs mcp -w -i 2` | Live MCP dashboard. |
| `bs mcp -j` | Structured MCP JSON. |
| `bs mcp -n 100` | Inspect more journal lines. |
| `bs mcp --config PATH` | Use a named profile. |

See [MCP monitoring](mcp-monitoring.md) for every profile field and safe usage
adapter configuration.

## Authentication Health

| Command | What it does |
| --- | --- |
| `bs auth` | Run configured read-only credential-reference checks once. |
| `bs auth -w -i 900` | Refresh checks; the minimum interval is 60 seconds. |
| `bs auth -j` | Structured authentication-health JSON. |
| `bs auth init` | Interactive portable profile intake wizard. |
| `bs auth init --config PATH` | Create a profile at an explicit path. |
| `bs auth init --replace` | Explicitly replace an existing profile. |
| `bs auth --config PATH` | Use an existing named profile. |

See [Authentication health](auth-health.md) for templates, adapter results, and
the no-secret configuration rules.

## Fan, Doctor, And Security

| Command | What it does |
| --- | --- |
| `bs fan status` | Show temperature, state, PWM, and RPM. |
| `bs fan set N` | Set a cooling state; root may be required. |
| `bs fan auto --once` | Run one automatic cooling decision. |
| `bs fan auto -p cool -i 5` | Run continuous automatic control. |
| `bs doctor` | Check required tools, visibility, GeoLite, and local setup. |
| `sudo bs doctor --install` | Install core Linux dependencies. |
| `sudo bs doctor --install --install-extras` | Also install optional security and network tooling. |
| `bs security` / `bs sec` | Review SSH, firewall, mounts, secret-file posture, and MCP/tunnel risks. |

See [Doctor and security](doctor-security.md) and [Fan controller](fan-controller.md)
for operating details.
