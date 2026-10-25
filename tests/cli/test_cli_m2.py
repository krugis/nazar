from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from nazar.cli import main
from tests.cli.test_cli import _args, _mock_services, _restore_logging  # noqa: F401
from tests.conftest import FIXTURES

SMOKE = json.loads((FIXTURES / "cti" / "smoke_malicious.json").read_text())


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "config.yaml").write_text(
        "mode: active\n"
        "crowdsec: {lapi_url: 'http://lapi.test', cti_api_key_env: NAZAR_CTI_KEY,"
        " cti_url: 'http://cti.test/v2'}\n"
        "analyst: {ollama_url: 'http://ollama.test', max_calls_per_minute: 60}\n"
        "policy: {allowlist_cidrs: ['192.0.2.0/24']}\n"
        f"store: {{path: '{tmp_path / 'nazar.db'}'}}\n"
    )
    (tmp_path / "secrets.env").write_text("NAZAR_LAPI_PASSWORD=pw\nNAZAR_CTI_KEY=k\n")
    monkeypatch.delenv("NAZAR_LAPI_PASSWORD", raising=False)
    monkeypatch.delenv("NAZAR_CTI_KEY", raising=False)
    return tmp_path


def _services(router: respx.MockRouter) -> None:
    _mock_services(router)
    router.get(url__regex=r"http://cti\.test/v2/smoke/.*").mock(
        return_value=httpx.Response(200, json=SMOKE)
    )
    router.post("http://lapi.test/v1/alerts").mock(return_value=httpx.Response(201, json=["900"]))
    router.get("http://lapi.test/v1/alerts/900").mock(
        return_value=httpx.Response(200, json={"id": 900, "decisions": [{"id": 31}]})
    )
    router.delete("http://lapi.test/v1/decisions/31").mock(
        return_value=httpx.Response(200, json={"nbDeleted": "1"})
    )


def _seed(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with respx.mock(assert_all_called=False) as router:
        _services(router)
        assert main(_args(env, "run", "--once")) == 0
    capsys.readouterr()


def _json(env: Path, capsys: pytest.CaptureFixture[str], *argv: str) -> Any:
    assert main(_args(env, "--json", *argv)) == 0
    return json.loads(capsys.readouterr().out)


def test_incidents_and_explain(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _seed(env, capsys)
    items = _json(env, capsys, "incidents", "--since", "3650d")
    by_ip = {i["ip"]: i for i in items}
    assert by_ip["198.51.100.7"]["applied"] is True
    assert by_ip["198.51.100.7"]["outcome"] == "auto"
    assert by_ip["203.0.113.45"]["outcome"] == "report_only"

    data = _json(env, capsys, "explain", by_ip["198.51.100.7"]["id"])
    assert data["verdicts"][0]["enrichment"]["cti_reputation"] == "malicious"
    assert data["decisions"][0]["crowdsec_alert_id"] == "900"
    assert [a["kind"] for a in data["audit"]] == ["verdict", "decision", "applied"]

    assert main(_args(env, "explain", by_ip["198.51.100.7"]["id"])) == 0
    text = capsys.readouterr().out
    assert "R8 corroborated by CTI malicious" in text and "CrowdSec alert 900" in text
    assert main(_args(env, "explain", "inc_nope")) == 1


def test_rollback(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _seed(env, capsys)
    with respx.mock(assert_all_called=False) as router:
        _services(router)
        results = _json(env, capsys, "rollback", "--since", "3650d", "--yes")
        assert [r["removed"] for r in results] == [1]
        assert _json(env, capsys, "rollback", "--since", "3650d", "--yes") == []
    items = _json(env, capsys, "incidents", "--since", "3650d")
    assert not any(i["applied"] for i in items)


def test_rollback_needs_confirmation(
    env: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(env, capsys)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    with respx.mock(assert_all_called=False) as router:
        _services(router)
        assert main(_args(env, "rollback", "--since", "3650d")) == 1
    assert "aborted" in capsys.readouterr().out


def test_incidents_without_db(env: Path) -> None:
    assert main(_args(env, "incidents")) == 1
