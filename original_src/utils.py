"""
NetTrace — Utility Helpers
==========================
Timestamps, path helpers, cross-platform file openers, safe conversions.
"""
from __future__ import annotations
import os
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from config import FILENAME_TIMESTAMP_FORMAT, TIMESTAMP_FORMAT
def now_timestamp() -> str:
    """Return the current local time as a formatted string."""
    return datetime.now().strftime(TIMESTAMP_FORMAT)
def filename_timestamp() -> str:
    """Return a compact timestamp suitable for filenames."""
    return datetime.now().strftime(FILENAME_TIMESTAMP_FORMAT)
def ensure_dir(path: Path | str) -> Path:
    """Create a directory (and parents) if it does not exist."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
def safe_int(value: Any, default: int = 0) -> int:
    """Best-effort conversion to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
def human_bytes(num: int | float) -> str:
    """Format a byte count as a human-readable string."""
    try:
        n = float(num)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"
def open_path(path: Path | str) -> None:
    """Open a file or folder with the OS default application."""
    p = Path(path)
    target = str(p)
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(target)  # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
    except Exception as exc:  # pragma: no cover
        print(f"[NetTrace] Could not open {target!r}: {exc}", file=sys.stderr)
def truncate(text: str, width: int = 60) -> str:
    """Shorten a string with an ellipsis if it exceeds width."""
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"
