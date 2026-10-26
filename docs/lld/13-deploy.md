# 13: Deployment and packaging

## Packaging

- `pyproject.toml` with `hatchling`; package name `nazar-sec`, command `nazar`.
- Packaged data: `nazar/prompts/triage.md` (from `prompts/`), `nazar/data/eval_incidents.jsonl`,
  `nazar/data/config.example.yaml` (from `examples/config.yaml`) and `nazar/data/nazar.service`
  (from `deploy/`), all mapped at build time with hatch `force-include`. Loaders fall back to the
  source checkout, so an editable install works too.
- Install: `deploy/install.sh` (below) or `pipx install nazar-sec`. Later: `.deb` built from the
  wheel. Optional Docker image (`Dockerfile`).
- Third-party licenses (model, GeoLite2 if used) in `THIRD_PARTY_LICENSES.md`.

## Files on the host

| Path | Owner / mode | Purpose |
|---|---|---|
| `/etc/nazar/config.yaml` | `root:nazar 0640` | configuration |
| `/etc/nazar/secrets.env` | `nazar:nazar 0600` | secrets |
| `/var/lib/nazar/nazar.db` | `nazar:nazar 0640` | store |
| `/etc/systemd/system/nazar.service` | `root 0644` | unit |

## systemd unit (`deploy/nazar.service`)

```ini
[Unit]
Description=Nazar AI triage for CrowdSec
After=network-online.target crowdsec.service ollama.service
Wants=network-online.target

[Service]
Type=exec
User=nazar
Group=nazar
EnvironmentFile=-/etc/nazar/secrets.env
ExecStart=/usr/local/bin/nazar run
Restart=on-failure
RestartSec=10
TimeoutStopSec=90

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/nazar
StateDirectory=nazar
StateDirectoryMode=0750
UMask=0027

[Install]
WantedBy=multi-user.target
```

Network restriction: LAPI and Ollama are local, CTI and Telegram are remote, so `IPAddressDeny=`
cannot be tight without breaking CTI/Telegram. Documented option: when neither is used, add
`IPAddressAllow=localhost` + `IPAddressDeny=any`.
The cscli fallback needs access to the CrowdSec DB/socket and is therefore off by default; enabling
it requires relaxing the unit (documented, not default).

## `deploy/ollama-nazar.conf`

Optional systemd drop-in for Ollama: `LLAMA_ARG_CACHE_RAM=0` (llama.cpp's host prompt cache otherwise
grows memory with every distinct prompt, found live with Ollama 0.40.11), one loaded model, one
request at a time, and a commented `MemoryMax` for shared hosts. `install.sh` does not install it,
because it changes another service's configuration; the install guide shows the two commands.

## `deploy/install.sh`

POSIX `sh`, idempotent, `set -eu`, run as root:
1. Check OS, Python ≥ 3.11 (first of `python3.13`…`python3` on `PATH`, or `--python PATH`),
   `cscli` present, Ollama reachable (warn only). An interpreter under `/root` or `/home` is refused:
   the venv links to it and the `nazar` user could not read it.
2. Create system user `nazar` (`useradd --system --home /var/lib/nazar --shell /usr/sbin/nologin`).
3. Install into a dedicated venv `/opt/nazar/venv` (`--from` a PyPI name, path, wheel or git URL;
   default `nazar-sec`) and link `/usr/local/bin/nazar`. A plain venv instead of pipx: one less
   prerequisite on servers.
4. `nazar init` (creates the database owned by `nazar`; a failure is reported, not fatal).
5. Install the unit (from `deploy/` or the packaged copy), `systemctl daemon-reload`, enable but do
   **not** start; print next steps (`nazar run --dry-run --once`, review, then
   `systemctl start nazar`).

Verified in a clean `python:3.12-slim` container with a fake `cscli`: files, owners and modes as
in the table above, idempotent second run, and the `nazar` user can run the CLI.

Root-run CLI commands open the daemon's database too; `Database` keeps SQLite's `-wal`/`-shm` files
owned by the database owner so the daemon can still write them.

## Docker image (`Dockerfile`)

Two stages on `python:3.12-slim-bookworm`: build a venv in `/opt/nazar`, copy it into a clean image
with a `nazar` user (uid/gid 10001), `ENTRYPOINT ["nazar"]`, `CMD ["run"]`, volume
`/var/lib/nazar`. Config is mounted read-only at `/etc/nazar`; `--network host` reaches LAPI and
Ollama on localhost. Verified: builds (152 MB), runs as uid 10001, `config check` passes with a
mounted config.

## Releasing

1. Bump `version` in `pyproject.toml` and `nazar/__init__.py`, update `TRACKER.md`.
2. `uv build` → `dist/*.whl` and `dist/*.tar.gz`. The wheel built from the sdist must contain
   `nazar/prompts/triage.md` and the `nazar/data/` files (checked in CI).
3. Tag `vX.Y.Z` and publish with `uv publish` (maintainer's PyPI token; trusted publishing from a
   GitHub Actions release workflow is preferred once the workflow can be pushed).

## CI (`.github/workflows/ci.yml`)

On push/PR: matrix Python 3.11, 3.12 → `pip install -e .[dev]` → `ruff check` → `ruff format --check`
→ `mypy` → `pytest`. A `build` job builds the wheel and checks the packaged data exists.

## End-to-end (M4, DESIGN §10)

`deploy/e2e/`: `docker-compose.yml` (CrowdSec with the sshd/nginx collections and local API only,
Ollama, Nazar built from the `Dockerfile`), `acquis.yaml`, a Nazar `config.yaml`, and `run.sh`,
which registers the machine, pulls the model, replays SSH and HTTP attack logs (one with a
prompt-injection user agent, one from an allow-listed range) and asserts properties that hold
whatever the model answers: dry run changes nothing, every incident has a verdict, the
allow-listed IP is never banned in active mode, rollback removes all Nazar decisions. `check.py`
parses `cscli decisions list -o json`. Not run in normal CI (model size); run manually or in a
scheduled workflow.
