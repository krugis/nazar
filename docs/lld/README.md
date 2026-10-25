# Nazar: Low-Level Design

> Status: draft v0.1 for **v1** (milestones M1–M4 in [DESIGN.md](../../DESIGN.md) §9).
> DESIGN.md says *what* and *why*. These documents say *how*: module boundaries, interfaces,
> data schemas, algorithms and error handling. If the two disagree, fix one of them in the same PR.

## Documents

| # | Document | Package | Milestone |
|---|---|---|---|
| 00 | [Conventions](00-conventions.md) (engineering rules, deps, errors, logging, testing) | all | M1 |
| 01 | [Models](01-models.md) | `nazar.models` | M1 |
| 02 | [Config](02-config.md) | `nazar.config` | M1 |
| 03 | [Store](03-store.md) | `nazar.store` | M1 |
| 04 | [Collector](04-collector.md) | `nazar.collector` | M1 |
| 05 | [Pre-filter](05-prefilter.md) | `nazar.prefilter` | M1 |
| 06 | [Enricher](06-enrich.md) | `nazar.enrich` | M1/M2 |
| 07 | [Analyst](07-analyst.md) | `nazar.analyst` | M1 |
| 08 | [Policy engine](08-policy.md) | `nazar.policy` | M2 |
| 09 | [Actuator](09-actuator.md) | `nazar.actuator` | M2 |
| 10 | [Notifier](10-notify.md) | `nazar.notify` | M3 |
| 11 | [Daemon and pipeline](11-daemon.md) | `nazar.daemon`, `nazar.pipeline` | M1 |
| 12 | [CLI](12-cli.md) | `nazar.cli` | M1–M3 |
| 13 | [Deployment and packaging](13-deploy.md) | `deploy/`, `pyproject.toml` | M4 |

## Module map

```
                 ┌──────────── nazar.daemon (asyncio tasks, scheduling) ───────────┐
                 │                                                                 │
                 │   nazar.pipeline.Pipeline  (one incident: enrich→analyse→decide→act)
                 │        │          │            │            │           │       │
  collector ──► prefilter ──► enrich ──► analyst ──► policy ──► actuator ──► notify │
     │              │           │          │           │(pure)      │          │    │
     └──────────────┴───────────┴──────────┴───────────┴────────────┴──────────┘    │
                                     │                                              │
                                nazar.store (SQLite, audit log)                     │
                 └─────────────────────────────────────────────────────────────────┘
        nazar.models and nazar.config are imported by everything and import nothing of Nazar.
```

### Dependency rules (enforced in review, checked by a test that inspects imports)

1. `models` imports only the standard library and `pydantic`.
2. `config` imports only `models` and `core`.
3. `policy` imports only `models`, `config` and `core`. **No I/O, no clock, no randomness**: everything it
   needs is passed in. This keeps it exhaustively unit-testable (DESIGN §3.5).
4. Stage packages (`collector`, `prefilter`, `enrich`, `analyst`, `actuator`, `notify`) may import
   `models`, `config`, `store` and `nazar.core`, but **never each other**. They are wired together only
   in `pipeline` and `daemon`.
5. `cli` talks to the same services as `daemon`; it never reaches into another package's internals.

### Extension points

Every external integration sits behind a small `typing.Protocol`, so new ones are added without
touching the pipeline:

| Protocol | Where | v1 implementations | Later |
|---|---|---|---|
| `AlertSource` | collector | `LapiAlertSource` | other detectors, replay files |
| `EnrichmentProvider` | enrich | alert-source geo, CTI, GeoIP (optional), history | AbuseIPDB, rDNS |
| `LlmBackend` | analyst | `OllamaBackend` | llama.cpp server, OpenAI-compatible |
| `DecisionBackend` | actuator | `LapiDecisionBackend`, `CscliDecisionBackend` | — |
| `Notifier` | notify | `LogNotifier`, `TelegramNotifier` | Slack, email, webhook |

v2 (Nazar Radar) will be a separate package `nazar.radar` that reuses `store`, `analyst` (with its
own prompt and schema), `policy` (new rule set) and `notify`.

## Design decisions log

Short records of choices that affect more than one module. New decisions get the next number.

| # | Decision | Reason |
|---|---|---|
| D1 | Runtime dependencies are only `httpx`, `pydantic`, `PyYAML`. Logging uses stdlib `logging` with a JSON formatter; the CLI uses `argparse`. This deviates from DESIGN §7 (`structlog`, `typer`). | Keeps the install light (~5 packages instead of ~12, no `rich`/`click`), smaller attack surface for a security tool. Both are easy to swap later because they sit behind `nazar.core.log` and `nazar.cli`. |
| D2 | One asyncio process; blocking work (SQLite, `cscli`) runs in `asyncio.to_thread`. | No extra services or threads to reason about; SQLite traffic is tiny. |
| D3 | SQLite through the stdlib `sqlite3` with hand-written SQL and numbered migrations; no ORM. | Zero dependency, the schema is small, SQL stays reviewable. |
| D4 | The policy engine is a pure function over an ordered list of rule functions. | Deterministic, table-testable, and new rules are one function each. |
| D5 | Nazar identifies its own CrowdSec objects by scenario `nazar/ai-triage` and keeps the LAPI alert ID of every decision it creates. | Precise rollback (by ID), feedback-loop protection (by prefix). |
| D6 | Decisions are pushed with origin `cscli` by default (configurable). | Bouncers that filter by origin always accept `cscli`. Nazar ownership is tracked by scenario and alert ID, not by origin. |
| D7 | Time is injected through a `Clock` protocol; IDs through an `IdFactory`. | Deterministic tests for windows, expiry, budgets and retention. |
