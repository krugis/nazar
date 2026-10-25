from __future__ import annotations

import os
from pathlib import Path

import pytest

from nazar.config import (
    Config,
    ConfigError,
    Mode,
    check_config,
    load_config,
    load_secrets,
    parse_env_file,
)
from nazar.models import Action
from tests.conftest import REPO


def test_example_config_loads() -> None:
    cfg = load_config(REPO / "examples" / "config.yaml")
    assert cfg.mode is Mode.DRY_RUN
    assert cfg.dry_run


def test_defaults_match_design() -> None:
    cfg = Config()
    assert cfg.collector.interval_seconds == 30
    assert cfg.prefilter.dedupe_window_seconds == 300
    assert cfg.prefilter.incident_window_minutes == 30
    assert cfg.analyst.timeout_seconds == 60
    assert cfg.analyst.max_calls_per_minute == 10
    assert cfg.policy.auto_actions == [Action.BAN, Action.NOTIFY]
    assert cfg.policy.auto_min_confidence == 0.85
    assert cfg.policy.approval_min_confidence == 0.6
    assert cfg.policy.max_ban_duration == "24h"
    assert cfg.policy.max_auto_actions_per_hour == 20
    assert cfg.notifier.approval_ttl_minutes == 60
    assert cfg.store.retention_days == 90


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return path


@pytest.mark.parametrize(
    "text",
    [
        "mode: yolo",
        "unknown_key: 1",
        "policy: {approval_min_confidence: 0.9, auto_min_confidence: 0.8}",
        "policy: {default_ban_duration: 48h, max_ban_duration: 24h}",
        "policy: {allowlist_cidrs: [not-a-cidr]}",
        "policy: {auto_actions: [shell]}",
        "policy: {max_ban_duration: 1 day}",
        "notifier: {daily_summary_time: '25:00'}",
        "notifier: {timezone: Mars/Olympus}",
        "notifier: {telegram: {enabled: true}}",
        "- a list",
        "key: [unclosed",
    ],
)
def test_invalid_config_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")


def test_with_mode_does_not_mutate() -> None:
    cfg = Config(mode=Mode.ACTIVE)
    dry = cfg.with_mode(Mode.DRY_RUN)
    assert cfg.mode is Mode.ACTIVE and dry.mode is Mode.DRY_RUN


def test_parse_env_file() -> None:
    text = "# comment\nA=1\nexport B='two words'\nC=\"x\"\n\nbad line\n"
    assert parse_env_file(text) == {"A": "1", "B": "two words", "C": "x"}


def test_load_secrets_does_not_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "secrets.env"
    path.write_text("NAZAR_T1=file\nNAZAR_T2=file\n")
    monkeypatch.setenv("NAZAR_T1", "env")
    monkeypatch.delenv("NAZAR_T2", raising=False)
    load_secrets(path)
    assert os.environ["NAZAR_T1"] == "env"
    assert os.environ["NAZAR_T2"] == "file"
    monkeypatch.delenv("NAZAR_T2")


def test_check_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NAZAR_LAPI_PASSWORD", raising=False)
    issues = check_config(Config(mode=Mode.ACTIVE))
    levels = {(i.level, i.message.split(" ")[0]) for i in issues}
    assert ("error", "LAPI") in levels
    assert any("allowlist" in i.message for i in issues)
    monkeypatch.setenv("NAZAR_LAPI_PASSWORD", "pw")
    assert not [i for i in check_config(Config()) if i.level == "error"]
