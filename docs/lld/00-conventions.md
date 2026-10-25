# 00: Engineering conventions

## Code layout

```
src/nazar/
├── __init__.py          # __version__, NAZAR_SCENARIO constants
├── core/                # small shared utilities, no business logic
│   ├── clock.py         # Clock protocol, SystemClock, FrozenClock (tests)
│   ├── errors.py        # NazarError hierarchy
│   ├── log.py           # JSON logging setup, secret redaction
│   └── sanitize.py      # control-char stripping, truncation (used by collector and analyst)
├── models/              # 01
├── config.py            # 02
├── store/               # 03
├── collector/           # 04
├── prefilter/           # 05
├── enrich/              # 06
├── analyst/             # 07
├── policy/              # 08
├── actuator/            # 09
├── notify/              # 10
├── pipeline.py          # 11: processing of one incident
├── daemon.py            # 11: long-running tasks
├── cli/                 # 12: one module per command group
└── data/                # packaged data: eval incidents for test-model
prompts/triage.md        # packaged into nazar/prompts/ at build time
```

Guidelines: modules stay small (aim for under ~300 lines); one responsibility per module; public
names listed in the package `__init__.py`; everything else is private (`_name`).

## Python and typing

- Python **3.11+**. `from __future__ import annotations` in every module.
- Type hints on every function. `mypy --strict` for `models`, `policy`, `config`, `core`; normal mode
  elsewhere, tightened over time.
- Data crossing a module boundary is a pydantic model or a frozen dataclass, never a loose `dict`.
- Enums are `StrEnum` so they serialize as plain strings in JSON, SQLite and logs.
- No global mutable state. Services are classes built once in `nazar.app.build_app(config)` and
  passed in (constructor injection). Tests build them with fakes.

## Dependencies

Runtime: `httpx`, `pydantic` (v2), `PyYAML` (decision D1). Optional extra `geoip`: `geoip2`.
Dev: `pytest`, `pytest-asyncio`, `respx`, `ruff`, `mypy`, `types-PyYAML`.
Adding a runtime dependency needs a line in the decisions log.

## Errors

```
NazarError
├── ConfigError            # bad or missing config/secrets → CLI exit code 2
├── StoreError
├── UpstreamError          # an external service failed
│   ├── LapiError          (status: int | None)
│   │   └── LapiAuthError
│   ├── LlmError
│   ├── CtiError
│   └── NotifierError
└── PolicyViolation        # actuator asked to do something the policy forbids (bug guard)
```

Rules:
- Catch broad exceptions only at task boundaries (daemon loops, per-incident processing), log them
  with `exc_info`, and continue. One bad incident never stops the daemon.
- Upstream failures degrade gracefully (DESIGN principle 5): enrichment → `null` fields; model →
  `unknown` verdict; LAPI → back off and retry; notifier → log and retry later. CrowdSec is never
  touched on an error path.
- Never retry non-idempotent calls blindly. Pushing a decision is protected by an idempotency key (09).

## Logging

- stdlib `logging`, one JSON object per line on stderr (journald captures it). Fields: `ts`, `level`,
  `logger`, `event` (short snake_case message), plus keyword context (`incident_id`, `ip`, …).
- Helper: `log = get_logger(__name__)`; `log.info("incident_triaged", incident_id=…, verdict=…)`
  (a thin `LoggerAdapter` that puts kwargs into the JSON).
- A redaction filter replaces the values of every configured secret with `***`.
- Untrusted strings (log lines, user agents) are logged only after `sanitize.clean()`.
- `--log-format text` gives human-readable output for the CLI.

## Testing

- `pytest` with `asyncio_mode = auto`. HTTP is mocked with `respx`, using recorded fixtures in
  `tests/fixtures/` (LAPI alerts, Ollama responses, CTI responses).
- Time is a `FrozenClock`; the database is a temporary file per test (`tmp_path`).
- Test file per module: `tests/<package>/test_<module>.py`. Policy uses table-driven tests.
- Security suites: `tests/security/test_prompt_injection.py`, `test_callbacks.py`.
- Coverage target: 90% for `policy`, `prefilter`, `analyst.parser`; 80% overall.
- CI (GitHub Actions): `ruff check`, `ruff format --check`, `mypy`, `pytest` on Python 3.11 and 3.12.

## Git and versioning

- Small PRs, one tracker item each where possible. Commit messages: Conventional Commits
  (`feat(policy): …`, `fix(collector): …`, `docs(lld): …`).
- SemVer; `0.x` until v1.0. The DB schema version is independent and only moves forward.
- Every behaviour change updates the matching LLD file and `TRACKER.md` in the same PR.
