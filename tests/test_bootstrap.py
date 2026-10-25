from __future__ import annotations

import json
import os
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from nazar import bootstrap
from nazar.cli import main
from nazar.config import load_config, parse_env_file

CREDS = "url: http://127.0.0.1:8080\nlogin: nazar\npassword: s3cret-from-cscli\n"


class FakeRunner:
    def __init__(self, add_rc: int = 0, add_err: str = "", bouncers: str = "[]") -> None:
        self.calls: list[list[str]] = []
        self.add_rc, self.add_err, self.bouncers = add_rc, add_err, bouncers

    def __call__(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["cscli", "machines", "add"]:
            return subprocess.CompletedProcess(argv, self.add_rc, CREDS if not self.add_rc else "",
                                               self.add_err)  # fmt: skip
        return subprocess.CompletedProcess(argv, 0, self.bouncers, "")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_init_creates_everything(tmp_path: Path) -> None:
    paths = bootstrap.Paths(tmp_path)
    runner = FakeRunner()
    report = bootstrap.init(paths, run=runner)
    assert not report.failed
    assert _mode(paths.config) == 0o640 and _mode(paths.secrets) == 0o600
    assert _mode(paths.etc) == 0o750
    secrets = parse_env_file(paths.secrets.read_text())
    assert secrets["NAZAR_LAPI_PASSWORD"] == "s3cret-from-cscli"
    assert len(bytes.fromhex(secrets["NAZAR_HMAC_KEY"])) == 32
    add = runner.calls[0]
    # credentials go to stdout, never to the agent's default credentials file
    assert add == ["cscli", "machines", "add", "nazar", "--auto", "-f", "-"]
    assert load_config(paths.config).mode.value == "dry_run"


def test_init_is_idempotent(tmp_path: Path) -> None:
    paths = bootstrap.Paths(tmp_path)
    bootstrap.init(paths, run=FakeRunner())
    paths.config.write_text(paths.config.read_text() + "\n# my edit\n")
    before = paths.secrets.read_text()
    runner = FakeRunner()
    report = bootstrap.init(paths, run=runner)
    assert "# my edit" in paths.config.read_text()
    assert paths.secrets.read_text() == before
    assert not any(c[:3] == ["cscli", "machines", "add"] for c in runner.calls)
    assert ("config", "skipped") in [(s, st) for s, st, _ in report.steps]


def test_existing_machine_needs_force(tmp_path: Path) -> None:
    paths = bootstrap.Paths(tmp_path)
    report = bootstrap.init(paths, run=FakeRunner(1, "machine 'nazar' already exists"))
    assert report.failed
    detail = next(d for s, st, d in report.steps if s == "crowdsec machine")
    assert "--force-register" in detail
    # the HMAC key is still created; the password is not
    assert "NAZAR_LAPI_PASSWORD" not in parse_env_file(paths.secrets.read_text())
    runner = FakeRunner()
    assert not bootstrap.init(paths, run=runner, force_register=True).failed
    assert runner.calls[0][-1] == "--force"


def test_captcha_bouncer_suggestion(tmp_path: Path) -> None:
    bouncers = json.dumps([{"name": "cs-firewall-bouncer", "type": "crowdsec-firewall-bouncer"},
                           {"name": "nginx-1", "type": "crowdsec-nginx-bouncer"}])  # fmt: skip
    report = bootstrap.init(bootstrap.Paths(tmp_path), run=FakeRunner(bouncers=bouncers))
    assert report.suggestions and "nginx-1" in report.suggestions[0]


def test_cli_init_with_fake_cscli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "cscli"
    fake.write_text(
        "#!/bin/sh\n"
        'if [ "$1 $2" = "machines add" ]; then printf "' + CREDS.replace("\n", "\\n") + '"; '
        "else echo '[]'; fi\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    root = tmp_path / "root"
    code = main(["--log-format", "json", "--json", "init", "--root", str(root), "--skip-checks"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["ok"], out
    assert parse_env_file((root / "etc/nazar/secrets.env").read_text())["NAZAR_LAPI_PASSWORD"]


def test_cli_init_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert main(["init"]) == 1


def test_existing_config_made_readable_for_service_group(tmp_path: Path) -> None:
    paths = bootstrap.Paths(tmp_path)
    paths.etc.mkdir(parents=True)
    paths.config.write_text("mode: dry_run\n")
    paths.config.chmod(0o604)  # world-readable, not group-readable
    bootstrap.init(paths, run=FakeRunner())
    assert _mode(paths.config) == 0o640
    assert paths.config.read_text() == "mode: dry_run\n"


def test_credentials_on_stderr_like_cscli_1_8(tmp_path: Path) -> None:
    """cscli 1.8.1 prints a status line and the credentials on stderr, nothing on stdout."""

    def runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if list(argv[:3]) == ["cscli", "machines", "add"]:
            err = "Machine 'nazar' successfully added to the local API.\n" + CREDS
            return subprocess.CompletedProcess(list(argv), 0, "", err)
        return subprocess.CompletedProcess(list(argv), 0, "[]", "")

    paths = bootstrap.Paths(tmp_path)
    assert not bootstrap.init(paths, run=runner).failed
    assert parse_env_file(paths.secrets.read_text())["NAZAR_LAPI_PASSWORD"] == "s3cret-from-cscli"
