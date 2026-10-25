"""Cleaning of untrusted text (log lines, user agents, third-party data)."""

from __future__ import annotations

import re

# C0/C1 control characters except tab, plus Unicode bidi overrides and zero-width characters
# that can hide or reorder text.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_SPACES = re.compile(r"[ \t\r\n]+")


def clean(text: object) -> str:
    """Remove control characters and collapse whitespace to single spaces."""
    value = text if isinstance(text, str) else str(text)
    value = _CONTROL.sub("", value)
    return _SPACES.sub(" ", value).strip()


def truncate(text: str, limit: int) -> str:
    """Cut to ``limit`` characters, marking the cut with an ellipsis."""
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    return text[: max(limit - 1, 0)] + "…"


def clean_line(text: object, limit: int) -> str:
    return truncate(clean(text), limit)
