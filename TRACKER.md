# Nazar implementation tracker

How to use: one row per unit of work, implemented in order within a milestone. Each item lands
with its tests and with the matching LLD file updated if anything changed. Status:
`todo` · `wip` · `done` · `blocked`. Reference the ID in commit messages (`feat(policy): P1 …`).

Design: [DESIGN.md](DESIGN.md) (what/why) · [docs/lld/](docs/lld/README.md) (how).

## Phase 0: Design

| ID | Item | LLD | Status |
|---|---|---|---|
| D-1 | High-level design | DESIGN.md | done |
| D-2 | Low-level design documents | [lld/](docs/lld/README.md) | done |
| D-3 | Review LLD, confirm decision D1 (stdlib logging + argparse instead of structlog + typer) | [README](docs/lld/README.md#design-decisions-log) | done |

## M1: Foundations (v0.1)

| ID | Item | LLD | Status | Notes |
|---|---|---|---|---|
| F-1 | Project skeleton: `pyproject.toml`, `.gitignore`, ruff/mypy/pytest config, package layout | [00](docs/lld/00-conventions.md) | wip | draft pyproject exists; drop typer/structlog per D1, entry point `nazar.cli:main` |
| F-2 | CI workflow (lint, format, mypy, tests on 3.11/3.12, build) | [13](docs/lld/13-deploy.md#ci-githubworkflowsciyml) | todo | |
| F-3 | `core`: clock, errors, JSON logging + redaction, sanitize | [00](docs/lld/00-conventions.md) | todo | |
| F-4 | Models: enums, durations, Event, Incident, Verdict + flat JSON schema, Decision, Approval | [01](docs/lld/01-models.md) | wip | draft in `src/nazar/models/`, split into files per LLD |
| F-5 | Config: schema, loading, secrets, `check_config`; `examples/config.yaml` | [02](docs/lld/02-config.md) | wip | draft `src/nazar/config.py` |
| F-6 | Store: DB, migrations, repositories, audit log, retention | [03](docs/lld/03-store.md) | todo | |
| F-7 | LAPI client: login, token refresh, 401 retry, alerts, errors | [04](docs/lld/04-collector.md) | todo | |
| F-8 | Alert normalization + polling source with cursor | [04](docs/lld/04-collector.md) | todo | |
| F-9 | Allow-list (protected ranges, host addresses, config CIDRs) | [05](docs/lld/05-prefilter.md) | todo | |
| F-10 | Grouper: dedupe, incidents, needs-triage, skip-trivial | [05](docs/lld/05-prefilter.md) | todo | |
| F-11 | Triage queue: priority, token bucket, overflow bulk summary | [05](docs/lld/05-prefilter.md) | todo | |
| F-12 | Enricher framework + alert_geo + history providers | [06](docs/lld/06-enrich.md) | todo | CTI in M2 |
| F-13 | Prompt `prompts/triage.md` (triage-v1) + prompt builder + escaping | [07](docs/lld/07-analyst.md) | todo | |
| F-14 | Verdict parser (`<think>` stripping, fences, JSON scan) | [07](docs/lld/07-analyst.md) | todo | |
| F-15 | Ollama backend + Analyst (retry once, fallback `unknown`) | [07](docs/lld/07-analyst.md) | todo | |
| F-16 | App composition + Pipeline + Daemon (collect, triage, housekeeping) | [11](docs/lld/11-daemon.md) | todo | policy stub = report_only until P-1 |
| F-17 | CLI skeleton + `run [--dry-run] [--once]`, `config check`, `status` | [12](docs/lld/12-cli.md) | todo | |
| F-18 | `test-model` + ~20 labelled eval incidents | [07](docs/lld/07-analyst.md#evaluation-nazar-test-model) | todo | |
| F-19 | M1 acceptance on a live CrowdSec + Ollama (dry-run, valid verdicts, no CrowdSec changes) | DESIGN §9 | blocked | dev host has <1 GB free disk; needs a test VM. Also verify LAPI `include_capi`, default `limit`, sort order |

## M2: Policy and enforcement (v0.2)

| ID | Item | LLD | Status | Notes |
|---|---|---|---|---|
| P-1 | Policy engine rules R1–R11 + table and property tests | [08](docs/lld/08-policy.md) | todo | |
| P-2 | Actuator: LAPI backend, idempotency, refusal guards | [09](docs/lld/09-actuator.md) | todo | |
| P-3 | Rollback (by alert ID, by filter) + crash reconcile | [09](docs/lld/09-actuator.md#rollback) | todo | |
| P-4 | cscli fallback backend | [09](docs/lld/09-actuator.md#cscli-fallback) | todo | off by default |
| P-5 | CTI provider + cache + circuit breaker | [06](docs/lld/06-enrich.md#cti-crowdsec-cti) | todo | |
| P-6 | Optional GeoIP provider | [06](docs/lld/06-enrich.md#geoip) | todo | |
| P-7 | `active` mode wired in the pipeline | [11](docs/lld/11-daemon.md) | todo | |
| P-8 | CLI: `incidents`, `explain`, `rollback` | [12](docs/lld/12-cli.md) | todo | |
| P-9 | M2 acceptance: allow-listed never banned (tests), decisions visible in `cscli decisions list`, removable by rollback | DESIGN §9 | todo | live part needs the test VM; verify payload fields and custom origin |

## M3: Human in the loop (v0.3)

| ID | Item | LLD | Status |
|---|---|---|---|
| H-1 | Notification types, plain-text rendering, fan-out, log notifier | [10](docs/lld/10-notify.md) | todo |
| H-2 | ApprovalService (request, approve with policy re-check, reject, expire) | [10](docs/lld/10-notify.md#approvalservice) | todo |
| H-3 | Callback signing/verification | [10](docs/lld/10-notify.md#callback-security) | todo |
| H-4 | Telegram notifier: send, edit, long polling, buttons | [10](docs/lld/10-notify.md#telegram) | todo |
| H-5 | Health monitor + health notifications | [11](docs/lld/11-daemon.md#health) | todo |
| H-6 | Daily summary + `report [--daily] [--send]` | [10](docs/lld/10-notify.md#daily-summary) | todo |
| H-7 | CLI `approve` / `reject` | [12](docs/lld/12-cli.md) | todo |
| H-8 | M3 acceptance: expiry safe, forged callback rejected, click re-validated | DESIGN §9 | todo |

## M4: Packaging and hardening (v0.4)

| ID | Item | LLD | Status |
|---|---|---|---|
| K-1 | `nazar init` (machine registration, secrets, bouncer detection, self-test) | [12](docs/lld/12-cli.md) | todo |
| K-2 | Hardened systemd unit + `install.sh` | [13](docs/lld/13-deploy.md) | todo |
| K-3 | Prompt-injection test corpus (user agents, usernames, URLs) | [00](docs/lld/00-conventions.md#testing) | todo |
| K-4 | Docs: install, configuration, safety model, FAQ; `THIRD_PARTY_LICENSES.md` | [13](docs/lld/13-deploy.md) | todo |
| K-5 | pipx package publishing; optional Docker image | [13](docs/lld/13-deploy.md#packaging) | todo |
| K-6 | E2E docker-compose stack (CrowdSec + Ollama + Nazar) | [13](docs/lld/13-deploy.md#end-to-end-m4-design-10) | todo |
| K-7 | M4 acceptance: clean Ubuntu 24.04 install in < 15 min | DESIGN §9 | todo |

## v1.0

| ID | Item | Status |
|---|---|---|
| V-1 | Freeze config format and data contracts | todo |
| V-2 | Performance: p95 < 60 s per incident on 4 vCPU, 500 alerts/h in dry-run | todo |
| V-3 | Model comparison (security-slm-1.5b vs Qwen3-4B-Instruct, …) via `test-model` (DESIGN open question 1) | todo |

## Open items to verify (from the LLD)

- LAPI: `include_capi` default, default `limit`, alert sort order, auth for `GET /v1/allowlists` (04, 05)
- LAPI: `POST /v1/alerts` with `events: []`, `labels`, custom decision origin (09)
- Ollama: behaviour of `format` schema + `think` with the default GGUF model (07)
