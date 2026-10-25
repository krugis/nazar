from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import respx

from nazar.cli import main
from tests.cli.test_cli import _args, _restore_logging  # noqa: F401
from tests.cli.test_cli_m2 import _services

CONFIG = (
    "mode: active\n"
    "crowdsec: {{lapi_url: 'http://lapi.test'}}\n"
    "analyst: {{ollama_url: 'http://ollama.test', max_calls_per_minute: 60}}\n"
    "policy: {{allowlist_cidrs: [{allow}]}}\n"
    "store: {{path: '{db}'}}\n"
)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "config.yaml").write_text(
        CONFIG.format(allow="'192.0.2.0/24'", db=tmp_path / "n.db")
    )
    (tmp_path / "secrets.env").write_text("NAZAR_LAPI_PASSWORD=pw\n")
    monkeypatch.delenv("NAZAR_LAPI_PASSWORD", raising=False)
    return tmp_path


def _approval_id(env: Path, capsys: pytest.CaptureFixture[str]) -> str:
    with respx.mock(assert_all_called=False) as router:
        _services(router)
        assert main(_args(env, "--json", "run", "--once")) == 0
    capsys.readouterr()
    con = sqlite3.connect(env / "n.db")
    (approval_id,) = con.execute("SELECT id FROM approvals WHERE status = 'pending'").fetchone()
    con.close()
    return str(approval_id)


def test_approve(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    approval_id = _approval_id(env, capsys)
    with respx.mock(assert_all_called=False) as router:
        _services(router)
        assert main(_args(env, "--json", "approve", approval_id)) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["outcome"] == "approved" and out["applied"] == "applied"
        assert main(_args(env, "approve", approval_id)) == 1  # not pending any more


def test_approve_refused_by_policy(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    approval_id = _approval_id(env, capsys)
    (env / "config.yaml").write_text(CONFIG.format(allow="'198.51.100.0/24'", db=env / "n.db"))
    with respx.mock(assert_all_called=False) as router:
        _services(router)
        assert main(_args(env, "approve", approval_id)) == 3
    assert "R1 hard deny" in capsys.readouterr().out


def test_reject_and_report(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    approval_id = _approval_id(env, capsys)
    assert main(_args(env, "reject", approval_id)) == 0
    capsys.readouterr()
    assert main(_args(env, "--json", "report", "--daily")) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["approvals"] == {"rejected": 1} and report["incidents"] == 2
    assert main(_args(env, "report")) == 0
    assert "Approvals: rejected 1" in capsys.readouterr().out
