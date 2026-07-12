# MCP Monitoring and Configuration

`bs mcp` is a Linux host dashboard for a local MCP server and its optional
proxy or tunnel. It is read-only: health probes use TCP, HTTP GET, and named
read-only MCP tools; it never invokes write or secret tools.

## Commands

```bash
bs mcp
bs mcp --watch --interval 2
bs mcp --json
bs mcp --config ./monitor.toml
bs dash --config ./monitor.toml
bs doctor --config ./monitor.toml
bs security --config ./monitor.toml
```

## Profile File

Start from [`config.example.toml`](../config.example.toml). Profiles are found
through `--config`, `BS_CONFIG`, `~/.config/bsuite/config.toml`, then
`/etc/bsuite/config.toml`. The built-in default profile uses conventional local
service names; production installations should supply their own file.

| Table | Fields | Purpose |
| --- | --- | --- |
| `[profile]` | `name` | Human-readable dashboard label. |
| `[mcp]` | `service`, `host`, `port`, `health_path`, `rpc_path` | MCP systemd unit and local HTTP endpoints. |
| `[mcp]` | `mode_tool`, `usage_tool` | Optional read-only MCP tools; set either to `""` to disable it. |
| `[tunnel]` | `service`, `host`, `port`, `health_path`, `metrics_path` | Proxy/tunnel unit and loopback health endpoints. |
| `[tunnel]` | `process`, `startup_log_match` | Optional process and structured-journal identifiers. |
| `[usage]` | `provider`, `format` | `codex` uses native Codex usage data; `claude-code` uses a configured normalized adapter. |
| `[usage]` | `command`, `timeout_seconds` | Optional absolute executable argument list that prints usage JSON. |
| `[usage]` | `environment_variable` | Optional systemd environment key containing a usage command. Leave empty for new profiles. |
| `[capabilities]` | `write_environment`, `secret_environment` | Markers used to identify privileged tool settings. |

`host` fields accept only `127.0.0.1`, `::1`, or `localhost`. Ports must be
between 1 and 65535, and HTTP paths must begin with `/`.

## What the Dashboard Checks

- systemd active/enabled state, PID, uptime, memory, tasks, and restarts
- configured local listeners and loopback-only bind safety
- MCP and tunnel TCP/HTTP health with latency
- MCP runtime mode, active tool count, and write/secret tool capability state
- tunnel target transport and capability state from structured startup evidence
- outbound TLS sockets associated with the configured tunnel process
- command totals, failures, status codes, and average latency from `/metrics`
- recent service journal activity and errors
- optional Codex-style usage windows, credits, and token totals
- reverse DNS and GeoLite/ASN context for public remote endpoints

## Usage Commands

`[usage].command` is intended for a small local adapter. It must be an argument
list, for example:

```toml
[usage]
command = ["/usr/local/bin/codex-usage-probe", "--usage"]
timeout_seconds = 10
environment_variable = ""
```

For Codex, use `provider = "codex"` and `format = "codex"`; B-Suite accepts
the native limits object returned by the configured MCP tool or Codex adapter.

For Claude Code, use `provider = "claude-code"` and `format = "normalized"`.
Anthropic's [CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-usage)
supports scripted JSON output but does not document a read-only usage-limit
command, so do not call `claude -p` just to ask for limits. Instead, configure a
provider-owned or operator-owned read-only adapter that emits this JSON shape:

```json
{
  "windows": {
    "5h": {"remaining_percent": 72, "resets_at": 1760000000},
    "weekly": {"remaining_percent": 91, "resets_at": 1760500000}
  },
  "plan_type": "team",
  "reset_credits_available": 0,
  "latest_daily_date": "2026-07-12",
  "latest_daily_tokens": 123456
}
```

Install Claude Code using Anthropic's [documented installation
method](https://docs.anthropic.com/en/docs/claude-code/getting-started), not the
root-only B-Suite system-tool installer. B-Suite does not install or authenticate
either AI CLI.

B-Suite requires an absolute executable path, refuses common shell executables,
sets a timeout, requires the profile not be group/world writable, and renders
only a summary. It does not log the command itself. Do not put tokens or
credentials in the command or committed profile.

## Warnings

The monitor warns about inactive or restarted services, unexpected binds,
missing listeners, no outbound tunnel TLS connection, recent journal errors,
failed tunnel commands, enabled write/secret capability markers, unavailable
usage data, and usage windows with 25% or less remaining.
