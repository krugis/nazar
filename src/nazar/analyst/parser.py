"""Model output parsing: strip reasoning, find the JSON object, validate (LLD 07)."""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from nazar.models import Verdict

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
_FENCE = re.compile(r"```[a-zA-Z]*")


class ParseError(ValueError):
    """Model output is not a valid verdict. The message never echoes the output."""


def strip_reasoning(text: str) -> str:
    text = _THINK_BLOCK.sub("", text)
    lower = text.lower()
    if "</think>" in lower:
        # Reasoning without an opening tag (some templates add it to the prompt): keep the tail.
        text = text[lower.rfind("</think>") + len("</think>") :]
    elif "<think>" in lower:
        # Unterminated reasoning: nothing after it can be trusted as the answer.
        text = text[: lower.find("<think>")]
    return text


def first_json_object(text: str) -> str | None:
    """The first balanced top-level ``{...}``, aware of JSON strings and escapes."""
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        start = text.find("{", start + 1)
    return None


def parse_verdict(text: str) -> Verdict:
    body = _FENCE.sub("", strip_reasoning(text or ""))
    candidate = first_json_object(body)
    if candidate is None:
        raise ParseError("no JSON object found")
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON at position {exc.pos}") from None
    if not isinstance(data, dict):
        raise ParseError("top-level value is not an object")
    try:
        return Verdict.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'root'}: {err['type']}"
            for err in exc.errors()[:5]
        )
        raise ParseError(f"schema violation ({problems})") from None
