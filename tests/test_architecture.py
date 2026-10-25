"""Module dependency rules from docs/lld/README.md, checked on the source tree."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "nazar"
STAGES = {"collector", "prefilter", "enrich", "analyst", "actuator", "notify"}
ALLOWED: dict[str, set[str]] = {
    "models": set(),
    "core": set(),
    "config": {"models", "core"},
    "policy": {"models", "config", "core"},
    "store": {"models", "core"},
    **{stage: {"models", "config", "store", "core", ""} for stage in STAGES},
}


def _package(path: Path) -> str:
    rel = path.relative_to(SRC)
    return rel.parts[0].removesuffix(".py") if len(rel.parts) > 1 else rel.stem


def _nazar_imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            parts = name.split(".")
            if parts[0] == "nazar":
                found.add(parts[1] if len(parts) > 1 else "")
    return found


@pytest.mark.parametrize("path", sorted(SRC.rglob("*.py")), ids=lambda p: str(p.relative_to(SRC)))
def test_import_rules(path: Path) -> None:
    package = _package(path)
    if package not in ALLOWED:
        return  # wiring modules (app, pipeline, daemon, cli) may import anything
    imported = _nazar_imports(path) - {package}
    forbidden = imported - ALLOWED[package]
    assert not forbidden, f"{package} must not import {sorted(forbidden)}"
