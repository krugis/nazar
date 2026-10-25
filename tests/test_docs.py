"""Documentation that must stay in sync with the code."""

from __future__ import annotations

import json
import re

import yaml

from nazar.config import Config
from tests.conftest import REPO


def test_configuration_reference_matches_defaults() -> None:
    text = (REPO / "docs" / "configuration.md").read_text()
    block = re.search(r"```yaml\n(.*?)```", text, re.S)
    assert block is not None
    documented = yaml.safe_load(block.group(1))
    defaults = json.loads(Config().model_dump_json())
    assert documented == defaults
    # and it is a valid config by itself
    Config.model_validate(documented)


def test_example_config_is_valid() -> None:
    Config.model_validate(yaml.safe_load((REPO / "examples" / "config.yaml").read_text()))
