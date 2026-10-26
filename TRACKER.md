# Nazar implementation tracker

How to use: one row per unit of work, implemented in order within a milestone. Each item lands
with its tests and with the matching LLD file updated if anything changed. Status:
`todo` · `wip` · `done` · `blocked`. Reference the ID in commit messages (`feat(policy): P1 …`).

Design: [DESIGN.md](DESIGN.md) (what/why) · [docs/lld/](docs/lld/README.md) (how).

## Live validation log (resume here)

**Oct 25, 2026: detect-only install on a shared 2-vCPU / 7.8 GB Debian 11 host.**
CrowdSec 1.8.1 without a bouncer (LAPI moved to a free port), Ollama 0.40.11 capped at 2.4 GB RAM
with a systemd drop-in, Python 3.12 under `/opt`, Nazar from this checkout via
`install.sh --python`. `nazar init`, `status` and `config check` all pass.

Bugs found and fixed live: `install.sh --python` + refusal of interpreters under home dirs;
cscli 1.8.1 credentials on stderr; existing config unreadable by the service group;
`num_predict` 512 too small for reasoning models (now 2048); `think` auto (`false` for reasoning
models); approval IDs starting with `-`; a wall-clock dependency in a test fixture.

Model work ([docs/models.md](docs/models.md)): `granite4:micro-h` (3B) scored 21/22 and became the
default, but on this host it needs ~2.45 GB (Ollama repacks CPU weights; `num_ctx` barely matters),
so it was OOM-killed inside its cap. `granite4:1b-h` (1.5B, Q8_0, 1.6 GB): **72.7% / 77.3%**, 0% invalid, ~36 s, no OOM;
its misses under-report (4 attacks rated benign, incl. the prompt-injection case). Usable for
pipeline testing on this host; not good enough as the default.

**Oct 26:** freed ~0.55 GB on the host (stopped stale processes), raised the Ollama cap to
2.9 GB, re-pulled `granite4:micro-h`: **22/22, 0% invalid, ~47 s, 0 OOM kills**, host never below
630 MB available. The 1B was removed; the 3B is used for the remaining live tests.

Next steps, in order:
1. ~~Model decision~~ done: `granite4:micro-h` with a 2.9 GB Ollama cap.
2. Dry run with controlled attacks from a second server (SSH brute force + HTTP probing with a
   prompt-injection user agent), then `nazar explain` one incident.
3. Active-mode test (P-9): delete CrowdSec's own ban for the attacker, reset Nazar's database,
   `mode: active`, run once, check `cscli decisions list` for `nazar/ai-triage`, approve if needed,
   `nazar rollback`. No bouncer is installed, so nothing is actually blocked.
4. Start the daemon (`systemctl start nazar`), watch `journalctl -u nazar`, `nazar report`.
5. Later, on a dedicated VM: K-6 e2e stack, K-7 timed clean install, 4B/8B model candidates.

## Phase 0: Design

| ID | Item | LLD | Status |
|---|---|---|---|
| D-1 | High-level design | DESIGN.md | done |
| D-2 | Low-level design documents | [lld/](docs/lld/README.md) | done |
| D-3 | Review LLD, confirm decision D1 (stdlib logging + argparse instead of structlog + typer) | [README](docs/lld/README.md#design-decisions-log) | done |

## M1: Foundations (v0.1)

| ID | Item | LLD | Status | Notes |
|---|---|---|---|---|
| F-1 | Project skeleton: `pyproject.toml`, `.gitignore`, ruff/mypy/pytest config, package layout | [00](docs/lld/00-conventions.md) | done | |
| F-2 | CI workflow (lint, format, mypy, tests on 3.11/3.12, build) | [13](docs/lld/13-deploy.md#ci-githubworkflowsciyml) | done | green on GitHub Actions (run 40227829938): 412 tests on 3.11 and 3.12, sdist→wheel install check |
| F-3 | `core`: clock, errors, JSON logging + redaction, sanitize | [00](docs/lld/00-conventions.md) | done | |
| F-4 | Models: enums, durations, Event, Incident, Verdict + flat JSON schema, Decision, Approval | [01](docs/lld/01-models.md) | done | |
| F-5 | Config: schema, loading, secrets, `check_config`; `examples/config.yaml` | [02](docs/lld/02-config.md) | done | |
| F-6 | Store: DB, migrations, repositories, audit log, retention | [03](docs/lld/03-store.md) | done | |
| F-7 | LAPI client: login, token refresh, 401 retry, alerts, errors | [04](docs/lld/04-collector.md) | done | |
| F-8 | Alert normalization + polling source with cursor | [04](docs/lld/04-collector.md) | done | |
| F-9 | Allow-list (protected ranges, host addresses, config CIDRs) | [05](docs/lld/05-prefilter.md) | done | CrowdSec allow-list import (`import_allowlists`) moved to P-10 |
| F-10 | Grouper: dedupe, incidents, needs-triage, skip-trivial | [05](docs/lld/05-prefilter.md) | done | skip-trivial check runs in the pipeline (F-16) |
| F-11 | Triage queue: priority, token bucket, overflow bulk summary | [05](docs/lld/05-prefilter.md) | done | evicted IDs are recorded by the daemon (F-16) |
| F-12 | Enricher framework + alert_geo + history providers | [06](docs/lld/06-enrich.md) | done | CTI in M2 |
| F-13 | Prompt `prompts/triage.md` (triage-v1) + prompt builder + escaping | [07](docs/lld/07-analyst.md) | done | |
| F-14 | Verdict parser (`<think>` stripping, fences, JSON scan) | [07](docs/lld/07-analyst.md) | done | |
| F-15 | Ollama backend + Analyst (retry once, fallback `unknown`) | [07](docs/lld/07-analyst.md) | done | |
| F-16 | App composition + Pipeline + Daemon (collect, triage, housekeeping) | [11](docs/lld/11-daemon.md) | done | |
| F-17 | CLI skeleton + `run [--dry-run] [--once]`, `config check`, `status` | [12](docs/lld/12-cli.md) | done | |
| F-18 | `test-model` + ~20 labelled eval incidents | [07](docs/lld/07-analyst.md#evaluation-nazar-test-model) | done | 22 cases |
| F-19 | M1 acceptance on a live CrowdSec + Ollama (dry-run, valid verdicts, no CrowdSec changes) | DESIGN §9 | wip | Oct 25: dry run on 145 real alerts (17 incidents) made **0** CrowdSec changes; grouping and policy correct. Valid-verdict part pending: 8/17 fell back to `unknown` because Ollama hit the host's memory cap (see Live validation log). LAPI `include_capi`/`limit`/sort order not yet checked |

## M2: Policy and enforcement (v0.2)

| ID | Item | LLD | Status | Notes |
|---|---|---|---|---|
| P-1 | Policy engine rules R1–R11 + table and property tests | [08](docs/lld/08-policy.md) | done | engine takes an `IpMatcher` protocol so policy never imports prefilter |
| P-2 | Actuator: LAPI backend, idempotency, refusal guards | [09](docs/lld/09-actuator.md) | done | |
| P-3 | Rollback (by alert ID, by filter) + crash reconcile | [09](docs/lld/09-actuator.md#rollback) | done | |
| P-4 | cscli fallback backend | [09](docs/lld/09-actuator.md#cscli-fallback) | done | off by default |
| P-5 | CTI provider + cache + circuit breaker | [06](docs/lld/06-enrich.md#cti-crowdsec-cti) | done | |
| P-6 | Optional GeoIP provider | [06](docs/lld/06-enrich.md#geoip) | done | config `enrich.geoip_country_db` / `geoip_asn_db`; untested against real .mmdb files |
| P-7 | `active` mode wired in the pipeline | [11](docs/lld/11-daemon.md) | done | approval requests are stored; notifications and approve/reject come in M3 |
| P-8 | CLI: `incidents`, `explain`, `rollback` | [12](docs/lld/12-cli.md) | done | |
| P-9 | M2 acceptance: allow-listed never banned (tests), decisions visible in `cscli decisions list`, removable by rollback | DESIGN §9 | blocked | test part done (property tests + active-mode e2e); live part needs the test VM: check payload fields, custom origin, `cscli decisions list` output |
| P-10 | Import CrowdSec allow-lists (`crowdsec.import_allowlists`, LAPI `GET /v1/allowlists`, hourly refresh) | [05](docs/lld/05-prefilter.md#allowlist) | done | watcher JWT per the swagger; `with_content` param to verify live |

## M3: Human in the loop (v0.3)

| ID | Item | LLD | Status |
|---|---|---|---|
| H-1 | Notification types, plain-text rendering, fan-out, log notifier | [10](docs/lld/10-notify.md) | done |
| H-2 | ApprovalService (request, approve with policy re-check, reject, expire) | [10](docs/lld/10-notify.md#approvalservice) | done |
| H-3 | Callback signing/verification | [10](docs/lld/10-notify.md#callback-security) | done |
| H-4 | Telegram notifier: send, edit, long polling, buttons | [10](docs/lld/10-notify.md#telegram) | done |
| H-5 | Health monitor + health notifications | [11](docs/lld/11-daemon.md#health) | done |
| H-6 | Daily summary + `report [--daily] [--send]` | [10](docs/lld/10-notify.md#daily-summary) | done |
| H-7 | CLI `approve` / `reject` | [12](docs/lld/12-cli.md) | done |
| H-8 | M3 acceptance: expiry safe, forged callback rejected, click re-validated | DESIGN §9 | done |

## M4: Packaging and hardening (v0.4)

| ID | Item | LLD | Status |
|---|---|---|---|
| K-1 | `nazar init` (machine registration, secrets, bouncer detection, self-test) | [12](docs/lld/12-cli.md) | done |
| K-2 | Hardened systemd unit + `install.sh` | [13](docs/lld/13-deploy.md) | done |
| K-3 | Prompt-injection test corpus (user agents, usernames, URLs) | [00](docs/lld/00-conventions.md#testing) | done |
| K-4 | Docs: install, configuration, safety model, FAQ; `THIRD_PARTY_LICENSES.md` | [13](docs/lld/13-deploy.md) | done |
| K-5 | pipx package publishing; optional Docker image | [13](docs/lld/13-deploy.md#packaging) | wip | wheel + sdist verified (packaged data, licenses, works without the checkout); Dockerfile verified; **PyPI publish pending** (maintainer account/token) |
| K-6 | E2E docker-compose stack (CrowdSec + Ollama + Nazar) | [13](docs/lld/13-deploy.md#end-to-end-m4-design-10) | wip | written (`deploy/e2e/`), **not yet executed**: dev host lacks disk for the images and model; run on the test VM together with F-19, P-9, K-7 |
| K-7 | M4 acceptance: clean Ubuntu 24.04 install in < 15 min | DESIGN §9 | blocked | install.sh verified in a python:3.12-slim container with a fake cscli; needs a real Ubuntu 24.04 VM with CrowdSec |

## v1.0

| ID | Item | Status |
|---|---|---|
| V-1 | Freeze config format and data contracts | todo |
| V-2 | Performance: p95 < 60 s per incident on 4 vCPU, 500 alerts/h in dry-run | todo |
| V-3 | Model comparison via `test-model` (DESIGN open question 1) | wip | Oct 25, 2 vCPU host: **granite4:micro-h 21/22, 0% invalid, ~50 s** → new default; security-slm-1.5b rejected (reasoning overruns, no answer in 2/3 runs); Cybersecurity-Qwen2.5-3B rejected (everything malicious at 1.0). granite4:1b-h 72.7%/77.3% (fits small hosts, under-reports); micro-h 22/22 with a 2.9 GB cap. Details: [docs/models.md](docs/models.md). Next: 4B/8B candidates on a host with 8 GB RAM |

## Open items to verify (from the LLD)

- LAPI: `include_capi` default, default `limit`, alert sort order, auth for `GET /v1/allowlists` (04, 05)
- LAPI: `POST /v1/alerts` with `events: []`, `labels`, custom decision origin (09)
- Ollama: behaviour of `format` schema + `think` with the default GGUF model (07)
