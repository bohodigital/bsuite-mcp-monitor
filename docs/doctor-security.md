# B-Suite Doctor and Security

`bs doctor` checks whether B-Suite can see the host clearly.

```bash
bs doctor
bs doctor -j
sudo bs doctor --install
sudo bs doctor --install --install-extras
```

It checks local tools, Python packages, GeoLite databases, systemd visibility,
socket visibility, loopback probes, passwordless sudo availability, and the
installed `bs` path.

`--install` is explicit and requires root. It detects `apt-get`, `dnf`, or
`pacman` and installs only core non-Python dependencies. `--install-extras`
adds optional SSH, firewall, GeoIP, and packet-inspection packages. B-Suite
never installs packages during normal monitoring commands.

`bs security` reviews hardening posture from the local machine.

```bash
bs security
bs sec
bs security -j
```

It checks SSH posture, firewall visibility, MCP/tunnel posture, SSH file
permissions, mount posture, and apt upgrade state. Findings are sorted by
severity.

`bs security` is passive inspection. `bs doctor` is also passive unless the
explicit root-only installation flags are used; neither command changes
firewall, service, SSH, or file settings.
