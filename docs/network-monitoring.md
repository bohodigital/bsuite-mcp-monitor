# B-Suite Network Monitoring

This document covers the network and SSH monitoring pieces of `bs`.

## Commands

```bash
bs net
bs net -w -i 1
bs net -j
bs net --no-resolve
bs net --no-geo
bs net --lookup-limit 20
bs net --geo-db ~/.local/share/bs/GeoLite2-City.mmdb

bs dash
bs dash -w -i 2
bs dash --no-resolve
bs dash --no-geo

bs ssh
bs ssh --history
bs ssh -w --history
bs ssh --no-resolve
bs ssh --no-geo
bs ssh --lookup-limit 20
bs ssh --geo-db ~/.local/share/bs/GeoLite2-City.mmdb
```

Aliases:

```bash
bs network
bs net
```

## What `bs net` Shows

- Network interfaces and state
- Local IPv4/IPv6 addresses
- Lifetime RX/TX counters
- Current RX/s and TX/s rates
- Default route and DNS servers
- Listening, established, and recent sockets
- Owning process/PID when `ss` exposes it
- Reverse DNS lookup for public remote IPs by default
- GeoLite location/ASN lookup by default when a database is available
- Local, private, loopback, link-local, multicast, and wildcard addresses are explicitly classified when geographic lookup is not applicable
- Cached lookup budget with `--lookup-limit`

## What `bs ssh` Shows

- SSH service state
- Whether the service is enabled
- Listening SSH addresses/ports
- Key effective `sshd -T` settings
- Configured AllowUsers/DenyUsers/AllowGroups/DenyGroups/Match Address rules
- nftables/iptables rules that explicitly reference SSH port `22`
- Authorized public key fingerprints by user, without printing raw keys
- Current SSH connections on port `22`
- Remote endpoint
- Local endpoint
- Owning `sshd` PID/process when visible
- Approximate connection uptime from process age
- Recent accepted, failed, and disconnected SSH events with `--history`
- Reverse DNS lookup for public remote IPs by default
- GeoLite location/ASN lookup by default when a database is available
- Local endpoint location/classification alongside each remote endpoint
- Cached lookup budget with `--lookup-limit`

## What `bs dash` Shows

- A compact pane for system status
- A compact pane for network addresses, routing, DNS, and an established remote
- A compact pane for SSH service state, listening IPs, and current sessions
- A compact pane for MCP/tunnel services, outbound connection, and journal health
- Reverse DNS and GeoLite context by default for public remote IPs

## Packet Inspection Tools

These are installed:

```bash
tcpdump --version
tshark --version
mmdblookup --version
geoipupdate --version
```

`tshark` is Wireshark's CLI. `tcpdump` is useful for quick captures. `bs` does
not yet wrap packet capture directly; current `bs net` and `bs ssh` are passive
status views.

## GeoLite Setup

MaxMind's GeoLite databases require a MaxMind account and a license key.
According to MaxMind's developer docs, GeoLite is available as downloadable
databases and web services, the binary `.mmdb` format is the right format for
fast lookups, and GeoLite users should keep the databases current.

The easiest path on this machine is `geoipupdate`.

Create or edit:

```bash
sudoedit /etc/GeoIP.conf
```

Use your own MaxMind account ID and license key:

```text
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory /usr/share/GeoIP
```

Then download/update:

```bash
sudo geoipupdate
```

After that, `bs` will automatically check common locations including:

```text
/var/lib/GeoIP/GeoLite2-City.mmdb
/var/lib/GeoIP/GeoLite2-Country.mmdb
/var/lib/GeoIP/GeoLite2-ASN.mmdb
/usr/share/GeoIP/GeoLite2-City.mmdb
/usr/share/GeoIP/GeoLite2-Country.mmdb
/usr/share/GeoIP/GeoLite2-ASN.mmdb
~/.local/share/bs/GeoLite2-City.mmdb
```

You can also pass the database directly:

```bash
bs net --geo-db /usr/share/GeoIP/GeoLite2-City.mmdb
bs ssh --history --geo-db /usr/share/GeoIP/GeoLite2-City.mmdb
```

Reverse DNS and GeoLite are on by default. Use opt-out flags when needed:

```bash
bs net --no-resolve
bs net --no-geo
bs ssh --history --no-resolve --no-geo
bs dash --no-resolve --no-geo
```

Live dashboards cache reverse DNS and GeoLite results. They locate every
observed endpoint by default. Use `--lookup-limit N` only when you need to cap
uncached lookups per refresh; `-1` is the unlimited default.

Or set an environment variable:

```bash
export BS_GEOIP_DB=/usr/share/GeoIP/GeoLite2-City.mmdb
bs net
```

Do not commit `/etc/GeoIP.conf` or any file containing your MaxMind license key
to this repo.

## Notes

- IP geolocation is approximate. Treat it as context, not proof.
- Private LAN addresses like `192.168.x.x` are intentionally not geolocated.
- `bs net` can run unprivileged for status views.
- Full packet capture usually requires root or capture capabilities.
