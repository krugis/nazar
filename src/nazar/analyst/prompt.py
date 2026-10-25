"""Prompt loading and message construction (LLD 07)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from nazar.core.errors import ConfigError
from nazar.core.sanitize import clean, truncate
from nazar.models import Incident

PROMPT_FILE = "triage.md"
_VERSION_RE = re.compile(r"^<!--\s*prompt-version:\s*([A-Za-z0-9._-]+)\s*-->\s*$")
_REPO_PROMPTS = Path(__file__).resolve().parents[3] / "prompts"

Messages = list[dict[str, str]]


@dataclass(frozen=True)
class PromptTemplate:
    version: str
    system: str

    @classmethod
    def from_text(cls, text: str) -> PromptTemplate:
        first, _, rest = text.partition("\n")
        match = _VERSION_RE.match(first.strip())
        if not match:
            raise ConfigError("prompt file must start with <!-- prompt-version: NAME -->")
        return cls(version=match.group(1), system=rest.strip())

    @classmethod
    def load(cls, path: Path | None = None) -> PromptTemplate:
        """Load from ``path``, the installed package, or the source checkout, in that order."""
        if path is not None:
            return cls.from_text(path.read_text(encoding="utf-8"))
        try:
            text = (resources.files("nazar") / "prompts" / PROMPT_FILE).read_text(encoding="utf-8")
        except (FileNotFoundError, NotADirectoryError):
            text = (_REPO_PROMPTS / PROMPT_FILE).read_text(encoding="utf-8")
        return cls.from_text(text)


def escape_data(value: Any) -> str:
    """JSON for a <data> block. ``<``, ``>`` and ``&`` are escaped, so untrusted text can never
    form a literal tag such as ``</data>`` or ``<think>``."""
    text = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=1)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def build_messages(template: PromptTemplate, incident: Incident) -> Messages:
    user = (
        "Triage this incident. Respond with the JSON object only.\n"
        f"<data>\n{escape_data(incident.model_input())}\n</data>"
    )
    return [{"role": "system", "content": template.system}, {"role": "user", "content": user}]


def repair_messages(original: Messages, bad_output: str, error: str) -> Messages:
    shown = escape_data(truncate(clean(bad_output), 1000))
    return [
        *original,
        {"role": "assistant", "content": shown},
        {
            "role": "user",
            "content": f"Your previous answer was invalid: {truncate(clean(error), 200)}. "
            "Reply again with only the JSON object.",
        },
    ]
