"""Short duration strings such as ``30m`` or ``4h``, as used by verdicts and CrowdSec."""

from __future__ import annotations

import re
from datetime import timedelta

# Verdict durations are deliberately restricted to minutes and hours (DESIGN §4.2).
VERDICT_DURATION_RE = re.compile(r"^\d+(m|h)$")
# Config and CLI durations may also use seconds and days.
_DURATION_RE = re.compile(r"^(\d+)(s|m|h|d)$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str) -> timedelta:
    """Parse ``<int><s|m|h|d>`` into a timedelta. Raises ValueError on anything else."""
    match = _DURATION_RE.match(value.strip())
    if not match:
        raise ValueError(f"invalid duration {value!r}, expected e.g. 30m, 4h or 1d")
    return timedelta(seconds=int(match.group(1)) * _UNITS[match.group(2)])


def format_duration(delta: timedelta) -> str:
    """Format a timedelta for CrowdSec (Go ``time.ParseDuration`` compatible: h, m, s)."""
    seconds = int(delta.total_seconds())
    if seconds <= 0:
        raise ValueError("duration must be positive")
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"
