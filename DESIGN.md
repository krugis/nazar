# Nazar: High-Level Design

> Status: draft v0.1. This document is the source of truth for building **v1**. v2 (Nazar Radar) is described at a higher level and will get its own design pass later.
>
> **Note for implementers (including AI coding agents):** where this document says *"verify"*, check the official documentation or API spec before coding. Do not assume. Specifically, check the CrowdSec LAPI swagger and the Ollama API docs for exact endpoints and fields.

---

## 1. Goals and non-goals

### Goals
1. Add a **local AI triage layer** on top of CrowdSec that reduces noise, correlates events, explains incidents and proposes or applies bounded actions.
2. Run fully **on-host, on CPU**, with a small model (~1.5–4B parameters, quantized).
3. **Never weaken** the existing CrowdSec protection. If Nazar fails, CrowdSec keeps working exactly as before.
4. Every action is **bounded, tagged, auditable and reversible**.
5. Simple to install and operate for a single server. The design must not block a later multi-server or commercial layer.

### Non-goals (v1)
- Replacing CrowdSec detection or acting as a bouncer. Nazar never touches the firewall directly.
- Inline or real-time request inspection (CrowdSec AppSec does that).
- Running arbitrary remediation commands (patching, restarts). That is v2, and only with human approval.
- Multi-tenant SaaS, web dashboard or fleet management. These are commercial-layer candidates, out of scope for the open core.

---

## 2. Architecture overview

```
┌──────────────────────────────── Linux host ────────────────────────────────┐
│                                                                            │
│  logs ─► CrowdSec Log Processor ─► CrowdSec LAPI ◄── bouncers (enforce)    │
│          (parsers, scenarios,       │      ▲                               │
│           AppSec WAF)               │      │ decisions (bans)              │
│                                     ▼      │                               │
│                         ┌─────────── Nazar daemon ───────────┐             │
│                         │ 1 Collector   (poll LAPI alerts)   │             │
│                         │ 2 Pre-filter  (dedupe, group)      │             │
│                         │ 3 Enricher    (CTI, GeoIP, history)│             │
│                         │ 4 Analyst     (SLM via Ollama)     │──► Ollama   │
│                         │ 5 Policy      (deterministic)      │   (local)   │
│                         │ 6 Actuator    (CrowdSec decisions) │             │
│                         │ 7 Notifier    (Telegram)           │──► you      │
│                         │ 8 Store       (SQLite audit log)   │             │
│                         └────────────────────────────────────┘             │
└────────────────────────────────────────────────────────────────────────────┘
```

**Core principle:** *the model proposes, the policy decides, CrowdSec enforces.*

---

## 3. Components

### 3.1 Collector
- Authenticates to the CrowdSec **Local API (LAPI)** as a registered **machine** (watcher), created with `cscli machines add nazar --auto` during `nazar init`. *Verify* the login endpoint and token refresh behaviour in the LAPI swagger.
- Polls new alerts every `collector.interval_seconds` (default 30), using a persisted cursor (last alert ID or timestamp) so restarts don't reprocess or miss alerts.
- Normalizes each alert into an internal `Event` model: source IP, scenario, timestamp, event count, relevant log lines and labels.
- Ignores alerts that Nazar itself created (identified by the `nazar/` scenario prefix) to avoid feedback loops.

### 3.2 Pre-filter (no LLM)
Cheap, deterministic steps before calling the model:
- **Allow-list check:** drop events whose source is allow-listed (see §5.3). They are never actioned, only logged.
- **Deduplication:** merge repeated alerts for the same IP and scenario within `prefilter.dedupe_window_seconds`.
- **Grouping into incidents:** events for the same source IP within `prefilter.incident_window_minutes` (default 30) form one `Incident`.
- **Skip trivial cases:** if CrowdSec already issued a ban and there are no new signals, record the event and skip the model. The model is used only for gray areas, correlation and explanation.
- **Rate limiting:** limit model calls (`analyst.max_calls_per_minute`). Excess incidents are queued, and the oldest low-priority ones are summarized in bulk.

### 3.3 Enricher
For each incident, gather context (all optional, all cached):
- **CrowdSec CTI** (smoke endpoint with an API key from config): reputation, behaviours, classifications. Cache for 24 hours. *Verify* the endpoint and response fields.
- **GeoIP / ASN:** from CrowdSec enrichment data if present, otherwise a local MaxMind GeoLite2 database (optional).
- **Local history:** previous incidents and decisions for this IP from the Nazar store.
- **Host context:** services the host exposes (from config) to judge relevance, for example a WordPress probe against a host that doesn't run WordPress.

Enrichment failures never block triage; missing fields are passed as `null`.

### 3.4 Analyst (SLM)
- **Runtime:** Ollama on `127.0.0.1:11434`. *Verify* the `/api/chat` request format, including `format` (JSON schema) and the `think` option for reasoning models.
- **Default model:** `granite4:micro-h` (IBM Granite 4.0 Micro-H, 3B, Q4_K_M, ~1.9 GB download, ~2.5 GB RAM, Apache-2.0, non-reasoning). Chosen after live evaluation (see [docs/models.md](docs/models.md)); the first default, a 1.5B security reasoning model, could not answer reliably on CPU. The model name is configurable so other models can be swapped in.
- **Reasoning models are supported but not preferred.** Request JSON-schema-constrained output; for models with the thinking capability send `think: false`. If `<think>…</think>` content is present, strip it before parsing. Never treat the reasoning text as the answer.
- **Input:** a compact, structured incident summary. Raw log lines are truncated, escaped and wrapped in clearly marked data blocks (see §5.2).
- **Output:** must validate against the `Verdict` schema (§4.2). On invalid output, retry once with a short repair prompt, then fall back to `verdict = "unknown"`, which means no action and the incident is reported.
- **Settings:** low temperature (0.1–0.2), timeout `analyst.timeout_seconds` (default 60), fixed context limit.
- The system prompt lives in `prompts/triage.md`, is versioned, and every verdict records the prompt version.

### 3.5 Policy engine (deterministic, no LLM)
Turns a `Verdict` and its `Incident` into a `Decision`, the final action. Rules are evaluated in order:

1. **Hard deny:** allow-listed or protected targets → `no_action`.
2. **Mode gate:** in `dry_run` mode every action becomes `report_only`.
3. **Action whitelist:** only actions in §4.3 are possible. Anything else → `no_action` and a warning.
4. **Bounds:** clamp `duration` to `policy.max_ban_duration` (default `24h`). Range bans (`/24` etc.) are disabled by default.
5. **Confidence and severity thresholds:**
   - `auto` if `confidence ≥ policy.auto_min_confidence` (default 0.85) **and** severity ≥ `high` **and** the action is in `policy.auto_actions`
   - `approval` if `confidence ≥ policy.approval_min_confidence` (default 0.6)
   - otherwise `report_only`
6. **Corroboration:** auto-ban also requires at least one independent signal, such as CrowdSec CTI marking the IP malicious, two or more distinct scenarios, or repeat history. One alert plus the model's opinion is not enough.
7. **Budget:** at most `policy.max_auto_actions_per_hour` (default 20) automatic actions. Above the budget everything goes to approval, and an alert is sent ("unusual volume").

The policy engine must be **fully unit-testable** without the model.

### 3.6 Actuator
- Applies decisions **only through CrowdSec**: it creates an alert with an attached decision through LAPI under scenario `nazar/ai-triage`. *Verify* the `POST /v1/alerts` payload in the swagger. A fallback using `cscli decisions add` may be implemented behind a flag.
- Every decision includes: type (`ban` or `captcha`), scope (`ip`), value, duration, scenario `nazar/ai-triage`, and a reason containing the incident ID.
- **Rollback:** `nazar rollback --incident <id>` or `nazar rollback --since 1h` removes the decisions Nazar created.
- Actions are **idempotent**: re-applying the same decision for the same incident does nothing.

### 3.7 Notifier
- **v1 channel:** Telegram bot (token and chat ID in config). The interface is designed so Slack, email or webhooks can be added later.
- **Messages:**
  - *Auto action taken:* what happened, why, and a **Rollback** button
  - *Approval needed:* summary plus **Approve / Reject** buttons, which expire after `notifier.approval_ttl_minutes` (default 60). An expired request means no action.
  - *Daily summary* at a configurable time
  - *Health alerts:* Ollama down, LAPI unreachable, repeated invalid model output
- **Callback security:** only the configured chat ID is accepted, callback data is signed with HMAC, and every action is checked again by the policy engine at click time.

### 3.8 Store
- SQLite at `/var/lib/nazar/nazar.db`, with migrations.
- **Tables:** `incidents`, `events`, `verdicts` (including model name and prompt version), `decisions`, `approvals`, `cursor`, `cti_cache`.
- **Append-only audit log:** every verdict, decision, approval and rollback, with timestamp and actor (`model`, `policy`, `user:<telegram_id>`).
- **Retention:** `store.retention_days` (default 90).

### 3.9 CLI (`nazar`)
| Command | Purpose |
|---|---|
| `nazar init` | Create config, register the CrowdSec machine, check Ollama and the model, run a self-test |
| `nazar run [--dry-run]` | Run the daemon in the foreground (systemd uses this) |
| `nazar status` | Health of LAPI, Ollama and the model, queue size, mode, last cursor |
| `nazar incidents [--since 24h]` | List incidents and verdicts |
| `nazar explain <incident_id>` | Show the full reasoning trail: events, enrichment, verdict, policy result |
| `nazar approve <id>` / `nazar reject <id>` | Approve or reject from the CLI instead of Telegram |
| `nazar rollback --incident <id> \| --since <dur>` | Remove decisions created by Nazar |
| `nazar report [--daily]` | Print or send the summary |
| `nazar test-model` | Run sample incidents through the model and validate the output |
| `nazar config check` | Validate the configuration file |

---

## 4. Data contracts

### 4.1 Incident (model input, simplified)
```json
{
  "incident_id": "inc_2026_10_25_0001",
  "source_ip": "203.0.113.45",
  "first_seen": "2026-10-25T17:02:11Z",
  "last_seen": "2026-10-25T17:09:40Z",
  "scenarios": ["crowdsecurity/ssh-bf", "crowdsecurity/http-probing"],
  "event_count": 57,
  "sample_lines": ["<escaped, truncated log lines>"],
  "enrichment": {
    "cti_reputation": "malicious",
    "cti_behaviors": ["ssh:bruteforce", "http:scan"],
    "country": "XX",
    "asn": "AS64500 Example Hosting",
    "history": {"previous_incidents": 2, "previous_bans": 1}
  },
  "host_context": {"exposed_services": ["ssh", "nginx", "php-fpm"]},
  "crowdsec_already_banned": false
}
```

### 4.2 Verdict (model output, enforced with a JSON schema)
```json
{
  "verdict": "malicious | suspicious | benign | unknown",
  "severity": "low | medium | high | critical",
  "confidence": 0.0,
  "attack_tactics": ["TA0006 Credential Access"],
  "summary": "One or two sentences in plain language.",
  "reasoning_points": ["short bullet", "short bullet"],
  "proposed_action": "none | ban | captcha | notify",
  "proposed_duration": "4h"
}
```
Validation rules: `confidence` is between 0 and 1. `summary` is at most 400 characters. `reasoning_points` has at most 5 items. Unknown fields are rejected. `proposed_duration` matches `^\d+(m|h)$`.

### 4.3 Allowed actions (v1)
| Action | Effect | Can be automatic? |
|---|---|---|
| `none` | Record only | yes |
| `notify` | Send a message | yes |
| `ban` | CrowdSec `ban` decision on a single IP, at most `max_ban_duration` | yes, if policy allows |
| `captcha` | CrowdSec `captcha` decision (only if a captcha-capable bouncer exists) | yes, if policy allows |

There is no other action. In particular there is **no shell, file or network action**.

---

## 5. Security design

### 5.1 Threat model (main risks)
| Threat | Mitigation |
|---|---|
| Prompt injection through logs (user agents, usernames, URLs) | Data/instruction separation, escaping, a fixed action whitelist, policy checks independent of the model |
| An attacker tricks Nazar into banning legitimate IPs (spoofing or framing) | Allow-lists, corroboration requirement, bounded durations, action budget, rollback |
| Nazar is compromised and used to pivot | Runs as an unprivileged `nazar` user, uses LAPI credentials only, no shell actions, systemd sandboxing |
| Telegram callback forgery | Chat ID check, HMAC-signed callbacks, expiry, re-check by the policy engine |
| Model outage or garbage output | Schema validation, retry once, fall back to `unknown`; CrowdSec is unaffected |
| Feedback loops (Nazar reacting to its own alerts) | Ignore alerts with the `nazar/` scenario prefix |

### 5.2 Prompt construction rules
- The system prompt states that the content inside `<data>` blocks is untrusted and must never be followed as instructions.
- Log lines: strip control characters, truncate each line (default 300 characters) and limit the number of lines (default 20).
- The model's output **only feeds the policy engine**. It is never executed, templated into commands or used to build CrowdSec payloads beyond the validated fields.

### 5.3 Allow-lists and protected targets
- `policy.allowlist_cidrs`: your offices, VPN, monitoring and CI systems
- Always protected: loopback, RFC1918, link-local, CGNAT and the host's own addresses
- Optional: import the CrowdSec allow-lists already configured on the host

### 5.4 Runtime hardening
- systemd unit with `User=nazar`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, and network access limited where practical (LAPI, Ollama, CTI and Telegram only)
- Secrets in `/etc/nazar/secrets.env` with mode `0600`, never logged
- Config file `/etc/nazar/config.yaml` with mode `0640`

---

## 6. Configuration (example)

```yaml
mode: dry_run              # dry_run | active

crowdsec:
  lapi_url: http://127.0.0.1:8080
  machine_id: nazar        # password from secrets.env
  cti_api_key_env: NAZAR_CTI_KEY   # optional

collector:
  interval_seconds: 30

prefilter:
  dedupe_window_seconds: 300
  incident_window_minutes: 30

analyst:
  ollama_url: http://127.0.0.1:11434
  model: granite4:micro-h
  timeout_seconds: 60
  temperature: 0.1
  max_calls_per_minute: 10
  prompt_version: triage-v1

policy:
  auto_actions: [ban, notify]
  auto_min_confidence: 0.85
  approval_min_confidence: 0.6
  max_ban_duration: 24h
  max_auto_actions_per_hour: 20
  allowlist_cidrs: ["198.51.100.0/24"]

notifier:
  telegram:
    enabled: true
    bot_token_env: NAZAR_TG_TOKEN
    chat_id: "123456789"
  approval_ttl_minutes: 60
  daily_summary_time: "09:00"
  timezone: Europe/Istanbul

host_context:
  exposed_services: [ssh, nginx, php-fpm]

store:
  path: /var/lib/nazar/nazar.db
  retention_days: 90
```

---

## 7. Technology choices

| Area | Choice | Reason |
|---|---|---|
| Language | Python 3.11+ | Fast iteration, a good ecosystem, easy for contributors |
| HTTP | `httpx` (async) | LAPI, Ollama, CTI and Telegram calls |
| Models and validation | `pydantic` v2 | Config, events and the verdict schema |
| CLI | `typer` | Simple, typed CLI |
| Storage | SQLite (`sqlite3` or `SQLAlchemy Core`) and simple migrations | No extra services needed |
| Logging | `structlog` (JSON logs) | Machine-readable and auditable |
| Telegram | Bot API through `httpx` (long polling) | No inbound port needed |
| Tests | `pytest`, `pytest-asyncio`, `respx` (HTTP mocks) | The policy engine and actuator are fully mockable |
| Lint and format | `ruff`, `mypy` (strict on `policy/` and `models/`) | Code quality |
| Packaging | `pyproject.toml` (hatch), pipx, later .deb and Docker | Easy installation |

---

## 8. Repository layout

```
nazar/
├── README.md
├── DESIGN.md
├── LICENSE
├── pyproject.toml
├── src/nazar/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py            # pydantic settings, loading and validation
│   ├── daemon.py            # main loop and task scheduling
│   ├── models/              # Event, Incident, Verdict, Decision
│   ├── collector/           # CrowdSec LAPI client and cursor
│   ├── prefilter/           # dedupe, grouping, allow-list
│   ├── enrich/              # CTI, GeoIP, history
│   ├── analyst/             # Ollama client, prompt builder, output parser
│   ├── policy/              # deterministic rules (no I/O)
│   ├── actuator/            # CrowdSec decisions and rollback
│   ├── notify/              # Telegram (pluggable interface)
│   └── store/               # SQLite, migrations, audit log
├── prompts/
│   └── triage.md
├── deploy/
│   ├── nazar.service        # hardened systemd unit
│   └── install.sh
├── examples/
│   └── config.yaml
└── tests/
    ├── fixtures/            # sample CrowdSec alerts, model outputs (valid and invalid)
    ├── test_policy.py
    ├── test_prefilter.py
    ├── test_analyst_parser.py
    ├── test_actuator.py
    └── test_prompt_injection.py
```

---

## 9. Feature list and milestones (v1)

### M1: Foundations (v0.1)
- [ ] Project skeleton, `pyproject.toml`, ruff/mypy/pytest, CI on GitHub Actions
- [ ] Config loading and validation (`nazar config check`)
- [ ] Pydantic data models (§4)
- [ ] SQLite store with migrations and an audit log
- [ ] CrowdSec LAPI client: machine login, token refresh, alert polling with cursor
- [ ] Pre-filter: allow-list, dedupe, incident grouping
- [ ] Ollama client, prompt builder, schema-constrained output, `<think>` stripping, retry and fallback
- [ ] `nazar run --dry-run`: produce incidents and verdicts, record them, print a report
- [ ] `nazar test-model` with fixtures

**Acceptance:** running against a live CrowdSec instance in dry-run mode produces valid verdicts for every incident, never crashes on invalid model output, and makes no changes to CrowdSec.

### M2: Policy and enforcement (v0.2)
- [ ] Policy engine (§3.5) with complete unit tests
- [ ] Actuator: create tagged decisions through LAPI; idempotency; rollback commands
- [ ] Enrichment: CrowdSec CTI with cache, local history
- [ ] `active` mode
- [ ] `nazar incidents`, `nazar explain`, `nazar rollback`

**Acceptance:** allow-listed IPs are never banned (test-proven); every Nazar decision is visible in `cscli decisions list` with scenario `nazar/ai-triage` and is removable through `nazar rollback`.

### M3: Human in the loop (v0.3)
- [ ] Telegram notifier: auto-action messages with rollback, approval requests with expiry, health alerts
- [ ] HMAC-signed callbacks and chat ID check
- [ ] Daily summary
- [ ] `nazar approve` / `nazar reject` from the CLI

**Acceptance:** an approval request expires safely, a forged callback is rejected, and a click is re-validated by the policy engine.

### M4: Packaging and hardening (v0.4)
- [ ] Hardened systemd unit, `install.sh`, `nazar init`
- [ ] Prompt-injection test suite (malicious user agents, usernames, URLs)
- [ ] Documentation: install, configuration, safety model, FAQ
- [ ] pipx package; Docker image (optional)

**Acceptance:** a clean install on Ubuntu 24.04 with CrowdSec works in under 15 minutes by following the README.

### v1.0
- [ ] Stable configuration format and data contracts
- [ ] Performance: on a 4-vCPU server, triage of one incident takes under 60 seconds at p95, and Nazar keeps up with 500 alerts per hour in dry-run mode, aided by grouping

---

## 10. Testing strategy
- **Unit tests:** policy (exhaustive table-driven tests), pre-filter, parser (valid, invalid, partial and `<think>` outputs), allow-list matching.
- **Contract tests:** LAPI and Ollama clients against recorded fixtures (`respx`).
- **Security tests:** a prompt-injection corpus that must never produce an action on allow-listed targets or bypass the policy; forged Telegram callbacks.
- **Model evaluation:** `nazar test-model` runs a labelled set of about 50 incidents and reports accuracy, invalid-output rate and latency. It is used to compare models and prompt versions.
- **End-to-end:** a docker-compose stack with CrowdSec, Ollama and Nazar; replay sample attack logs; check the decisions.

---

## 11. v2: Nazar Radar (outline, not for the first build)

Goal: turn trusted threat news into fast, safe, host-specific action. Example: PHP2Shell (CVE-2026-109618 / CVE-2026-109619, October 2026).

```
Sources (trusted only): CISA KEV, NVD, vendor advisories (e.g. php.net), CERT-EU,
                        CrowdSec CTI / exploit tracking, curated RSS
   │
   ▼
Extractor (SLM, JSON only): cve_ids, product, affected_versions, fixed_versions,
                            exploited_in_wild, source_urls
   │
   ▼
Verifier: at least 2 trusted sources, or 1 official advisory
   │
   ▼
Inventory matcher: installed packages and versions (dpkg/rpm, php -v, container images)
   │   not affected → record and stop
   ▼
Response tiers
   AUTO:      cscli hub update/upgrade, make sure the virtual-patching collections are installed,
              tighten thresholds for affected services, send an urgent notification
   APPROVAL:  apply the vendor patch, restart services (e.g. php-fpm), apply the vendor's
              temporary mitigations
   NEVER:     any command, URL, IP or rule taken directly from the news text
```

Additional v2 ideas:
- Draft CrowdSec AppSec rules or scenarios for new CVEs, for **human review** and optional contribution to the CrowdSec Hub.
- An inventory module that is also useful on its own (`nazar inventory`).
- Candidate for the commercial layer: a hosted, curated intelligence feed so each user's server doesn't have to scrape and verify news itself.

---

## 12. Open questions
1. ~~Is a 1.5B reasoning model accurate enough for triage?~~ Answered (Oct 2026, [docs/models.md](docs/models.md)): no on CPU (its reasoning overran the token budget). A 3B non-reasoning generalist (Granite 4.0 Micro-H) scored 21/22. Re-evaluate 4B models (Qwen3-4B-Instruct, Phi-4-mini) and Foundation-Sec-8B on a larger host before v1.0.
2. Polling vs. streaming: does LAPI offer a better way to receive new alerts than polling? *Verify.*
3. Captcha support depends on the bouncer. Detect what is available during `nazar init`.
4. Should there be a local web UI in the open core, or only CLI and Telegram? Currently CLI and Telegram only, with a dashboard as a commercial candidate.
5. Licensing of the default model and any bundled data: record it in `THIRD_PARTY_LICENSES.md`.
