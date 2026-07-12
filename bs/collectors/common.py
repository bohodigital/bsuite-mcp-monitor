from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from typing import Any


def read_text(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (FileNotFoundError, PermissionError, OSError, UnicodeDecodeError):
        return None


def read_lines(path: str | Path) -> list[str]:
    text = read_text(path)
    if text is None:
        return []
    return text.splitlines()


def run_command(args: list[str], timeout: float = 1.0) -> str | None:
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def bytes_to_human(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    units = ["B", "K", "M", "G", "T", "P"]
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{amount:.0f}{unit}"
            return f"{amount:.1f}{unit}"
        amount /= 1024.0
    return f"{amount:.1f}P"


def percent(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 1)


def base_host_info() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "kernel": os.uname().release,
        "machine": os.uname().machine,
    }
