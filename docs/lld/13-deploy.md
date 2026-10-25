# 13: Deployment and packaging

## Packaging

- `pyproject.toml` with `hatchling`; package name `nazar-sec`, command `nazar`.
- Packaged data: `nazar/prompts/triage.md` (from `prompts/`), `nazar/data/eval_incidents.jsonl`,
  `nazar/data/config.example.yaml` (copy of `examples/config.yaml`, kept in sync by a test).
- Install: `pipx install nazar-sec` (M4). Later: `.deb` built from the wheel, optional Docker image.
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
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/nazar
StateDirectory=nazar
UMask=0027

[Install]
WantedBy=multi-user.target
```

Network restriction: LAPI and Ollama are local, CTI and Telegram are remote, so `IPAddressDeny=`
cannot be tight without breaking CTI/Telegram. Documented option: when neither is used, add
`IPAddressAllow=localhost` + `IPAddressDeny=any`.
The cscli fallback needs access to the CrowdSec DB/socket and is therefore off by default; enabling
it requires relaxing the unit (documented, not default).

## `deploy/install.sh`

POSIX `sh`, idempotent, `set -eu`, run as root:
1. Check OS, Python ≥ 3.11, `cscli` present, Ollama reachable (warn only).
2. Create system user `nazar` (`useradd --system --home /var/lib/nazar --shell /usr/sbin/nologin`).
3. Install with `pipx` into `/opt/nazar` (`PIPX_HOME=/opt/nazar PIPX_BIN_DIR=/usr/local/bin`).
4. `nazar init`.
5. Install the unit, `systemctl daemon-reload`, enable but do **not** start in active mode; print
   next steps (`nazar run --dry-run --once`, review, then `systemctl start nazar`).

## CI (`.github/workflows/ci.yml`)

On push/PR: matrix Python 3.11, 3.12 → `pip install -e .[dev]` → `ruff check` → `ruff format --check`
→ `mypy` → `pytest`. A `build` job builds the wheel and checks the packaged data exists.

## End-to-end (M4, DESIGN §10)

`deploy/e2e/docker-compose.yml`: CrowdSec, Ollama (with the model volume), Nazar; a replay script
feeds sample SSH/HTTP attack logs; assertions check verdicts, `cscli decisions list` and rollback.
Not run in normal CI (model size); run manually or in a scheduled workflow.
