# B-Suite Fan Controller

`bs fan` controls the Raspberry Pi `pwm-fan` cooling device.

## Commands

```bash
bs fan status
bs fan set 2
bs fan set 4
bs fan auto --once
bs fan auto
bs fan auto --profile cool
bs fan auto --profile balanced
bs fan auto --profile quiet
```

## Control Surface

Primary control path:

```text
/sys/class/thermal/cooling_device0/cur_state
```

The detected cooling device is:

```text
pwm-fan
```

The state range on this machine is:

```text
0..4
```

State `0` is off. State `4` is full fan.

## Profiles

The controller uses hysteresis so it does not rapidly bounce between fan states.

| Profile | State-up thresholds | State-down thresholds | Emergency |
| --- | --- | --- | --- |
| `quiet` | 52 / 60 / 67 / 74 C | 47 / 55 / 62 / 69 C | 80 C |
| `balanced` | 48 / 56 / 64 / 70 C | 44 / 52 / 60 / 66 C | 78 C |
| `cool` | 43 / 50 / 58 / 65 C | 40 / 47 / 55 / 62 C | 74 C |

The default profile is `cool`.

## Recommended Use

Run one control step:

```bash
bs fan auto --once
```

Run continuously in a terminal:

```bash
bs fan auto --profile cool --interval 5
```

Run continuously with systemd:

```bash
sudo install -m 0644 deploy/bs-fan.service /etc/systemd/system/bs-fan.service
sudo systemctl daemon-reload
sudo systemctl enable --now bs-fan.service
systemctl status bs-fan.service
```

Watch logs:

```bash
journalctl -u bs-fan.service -f
```

Set full fan manually:

```bash
bs fan set 4
```

Return to automatic control:

```bash
bs fan auto --profile cool
```

## Notes

- Writing fan state requires root. `bs` uses `sudo -n` when needed.
- The controller reads CPU temperature from `/sys/class/thermal/thermal_zone0/temp`.
- The status view also reads PWM and RPM from `/sys/class/hwmon/hwmon2`.
- If the fan reports `0 RPM` after setting state above `0`, inspect the physical fan connection.
