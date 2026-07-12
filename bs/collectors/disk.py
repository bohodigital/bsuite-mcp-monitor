from __future__ import annotations

import shutil
from typing import Any

from bs.collectors.common import percent, read_lines


_SKIP_FS = {
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "proc",
    "pstore",
    "securityfs",
    "sysfs",
    "tmpfs",
    "tracefs",
}


def _decode_mount(value: str) -> str:
    return value.replace("\\040", " ")


def collect_mounts() -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    for line in read_lines("/proc/mounts"):
        parts = line.split()
        if len(parts) < 4:
            continue
        device, mountpoint, fs_type, options = parts[:4]
        mountpoint = _decode_mount(mountpoint)
        option_list = options.split(",")
        mounts.append(
            {
                "device": _decode_mount(device),
                "mountpoint": mountpoint,
                "fs_type": fs_type,
                "options": option_list,
                "writable": "rw" in option_list,
            }
        )
    return mounts


def collect_disks() -> list[dict[str, Any]]:
    disks_by_device: dict[tuple[str, int], dict[str, Any]] = {}
    seen: set[str] = set()
    for mount in collect_mounts():
        fs_type = mount["fs_type"]
        mountpoint = mount["mountpoint"]
        if fs_type in _SKIP_FS or mountpoint in seen:
            continue
        seen.add(mountpoint)
        try:
            usage = shutil.disk_usage(mountpoint)
        except OSError:
            continue
        item = {
            **mount,
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "used_percent": percent(usage.used, usage.total),
        }
        key = (mount["device"], usage.total)
        current = disks_by_device.get(key)
        if current is None or len(mountpoint) < len(current["mountpoint"]):
            disks_by_device[key] = item
    return sorted(disks_by_device.values(), key=lambda item: item["mountpoint"])
