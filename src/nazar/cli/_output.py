"""Output helpers shared by commands."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import Any


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str, ensure_ascii=False))


def print_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
    cells = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        widths = [max(w, len(c)) for w, c in zip(widths, row, strict=True)]
    line = "  ".join(f"{{:<{w}}}" for w in widths)
    print(line.format(*headers))
    print(line.format(*("-" * w for w in widths)))
    for row in cells:
        print(line.format(*row))


def err(message: str) -> None:
    print(message, file=sys.stderr)
