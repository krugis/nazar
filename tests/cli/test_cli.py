from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx

from nazar.cli import build_parser, main
from tests.conftest import FIXTURES

VALID = (FIXTURES / "model_outputs" / "valid_clean.txt").read_text()


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "crowdsec: {lapi_url: 'http://lapi.test'}\n"
        "analyst: {ollama_url: 'http://ollama.test', max_calls_per_minute: 60}\n"
        f"store: {{path: '{tmp_path / 'nazar.db'}'}}\n"
    )
    (tmp_path / "secrets.env").write_text("NAZAR_LAPI_PASSWORD=pw\n")
    monkeypatch.delenv("NAZAR_LAPI_PASSWORD", raising=False)
    return tmp_path


def _args(env: Path, *rest: str) -> list[str]:
    return [
        "--config",
        str(env / "config.yaml"),
        "--secrets",
        str(env / "secrets.env"),
        "--log-format",
        "json",
        *rest,
    ]


def test_every_command_wired() -> None:
    parser = build_parser()
    for argv in (["run"], ["status"], ["config", "check"], ["test-model"]):
        assert callable(parser.parse_args(argv).handler)


def test_config_check_ok(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(_args(env, "config", "check")) == 0
    assert "configuration OK" in capsys.readouterr().out


def test_config_check_invalid(env: Path) -> None:
    (env / "config.yaml").write_text("mode: yolo\n")
    assert main(_args(env, "config", "check")) == 2


def test_config_check_missing_password(env: Path) -> None:
    (env / "secrets.env").write_text("")
    assert main(_args(env, "config", "check")) == 2


def _mock_services(router: respx.MockRouter) -> None:
    alerts = json.loads((FIXTURES / "lapi" / "alerts.json").read_text())
    router.post("http://lapi.test/v1/watchers/login").mock(
        return_value=httpx.Response(200, json={"token": "t", "expire": "2099-01-01T00:00:00Z"})
    )
    router.get("http://lapi.test/v1/alerts").mock(return_value=httpx.Response(200, json=alerts))
    router.get("http://ollama.test/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.12.0"})
    )
    router.get("http://ollama.test/api/tags").mock(
        return_value=httpx.Response(
            200, json={"models": [{"name": "hf.co/Nguuma/security-slm-unsloth-1.5b:latest"}]}
        )
    )
    router.post("http://ollama.test/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"content": VALID}})
    )


def test_run_once_dry_run(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with respx.mock(assert_all_called=False) as router:
        _mock_services(router)
        assert main(_args(env, "run", "--once", "--dry-run")) == 0
    out = capsys.readouterr().out
    assert "2 incident(s) triaged" in out
    assert out.count("would=report_only") == 2


def test_run_once_json(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with respx.mock(assert_all_called=False) as router:
        _mock_services(router)
        assert main(_args(env, "--json", "run", "--once")) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2 and data[0]["verdict"]["verdict"] == "malicious"


def test_status(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with respx.mock(assert_all_called=False) as router:
        _mock_services(router)
        assert main(_args(env, "--json", "status")) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["healthy"] and info["model"]["present"] and info["mode"] == "dry_run"


def test_status_down(env: Path) -> None:
    with respx.mock() as router:
        router.route().mock(side_effect=httpx.ConnectError("refused"))
        assert main(_args(env, "status")) == 1


def test_test_model(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with respx.mock(assert_all_called=False) as router:
        _mock_services(router)
        assert main(_args(env, "--json", "test-model", "--limit", "3")) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["cases"] == 3 and report["invalid_output_pct"] == 0.0
    assert report["prompt_version"] == "triage-v1"
