# Configuration And Portability

## Profiles

MCP monitoring looks for a profile in this order:

1. `bs mcp --config PATH`, `bs dash --config PATH`, `bs doctor --config PATH`,
   or `bs security --config PATH`
2. `BS_CONFIG`
3. `~/.config/bsuite/config.toml`
4. `/etc/bsuite/config.toml`
5. Built-in defaults

Authentication health uses a separate profile:

1. `bs auth --config PATH`
2. `BS_AUTH_CONFIG`
3. `~/.config/bsuite/auth.toml`

Use `config.example.toml` and `auth.example.toml` as neutral starting points.
Both are portable: replace service names, loopback ports, health paths, and
credential references for the target host.

## Permissions

`bs auth init` creates its profile atomically with mode `600` and its parent
directory with mode `700`. B-Suite rejects group/world-writable authentication
profiles when they contain a command adapter or an authenticated HTTP check.

Keep secret values out of every TOML profile. Use an environment variable,
system secret manager, or an operator-owned adapter instead. B-Suite reports
the reference and verification result, not the secret.

## Portable Install

```bash
git clone https://github.com/bohodigital/bsuite-mcp-monitor.git
cd bsuite-mcp-monitor
python3 -m venv .venv
.venv/bin/python -m pip install -e .
mkdir -p ~/.local/bin
ln -sf "$PWD/.venv/bin/bs" ~/.local/bin/bs
```

For a system-managed install, keep the checkout in an administrator-owned path,
create profiles under `/etc/bsuite`, and run B-Suite from a dedicated service
account with only the visibility it needs.

## Moving Between Hosts

1. Install B-Suite and required Linux tools on the new host.
2. Create a fresh MCP profile with the local unit names and loopback endpoints.
3. Run `bs doctor`, then `bs mcp` to verify visibility.
4. Run `bs auth init` to recreate credential references. Do not copy token
   values through B-Suite configuration.
5. Give any provider adapter access to the host's secret manager, then run
   `bs auth` and confirm its read-only result.
