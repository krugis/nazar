# 11: Daemon and pipeline (`nazar.daemon`, `nazar.pipeline`, `nazar.app`)

## Composition (`nazar.app`)

`build_app(cfg: Config, *, clock=SystemClock()) -> App` constructs every service once (one
`httpx.AsyncClient` per upstream, the `Database`, repositories, providers, backends, notifiers) and
returns them in a frozen `App` dataclass. Daemon, CLI and tests all use it; tests pass fakes through
optional arguments. `App.aclose()` closes clients and the DB.

## Pipeline (one incident)

```python
class Pipeline:
    async def process(self, incident_id: str) -> PipelineResult
```

```
load incident + events
│ allow-listed?  ─────────────────► verdict(model=none, skipped=allowlisted) → decision no_action
│ already banned & no new signal? ► verdict(model=none, skipped=…)          → stop
▼
enrichment  = Enricher.enrich(...)            (never raises)
triage      = Analyst.triage(incident+enr.)   (never raises; fallback = unknown)
store verdict (+ audit actor=model)
decision    = policy.evaluate(PolicyInput(..., auto_enforced_last_hour=repo.count…), cfg, mode)
store decision (+ audit actor=policy)
match decision.outcome:
  auto        → enforcing: Actuator.apply → notify auto_action ; notify: send report
  approval    → ApprovalService.request
  report_only → add to cycle report (and notify if severity ≥ high)
  no_action   → nothing
incident.needs_triage = 0, last_triaged_scenarios = scenarios
```

Any exception inside `process` is caught at the task boundary, logged with the incident ID, and the
incident keeps `needs_triage = 1` with a retry counter (`kv`), dropped to a `unknown` verdict after
3 failures. CrowdSec is never touched on an error path.

## Daemon tasks (`nazar.daemon.Daemon.run()`)

One asyncio event loop. Each task runs under a supervisor: an unexpected exception restarts that
task after backoff (5 s doubling to 5 min) and never stops the daemon:

| Task | Period | Work |
|---|---|---|
| `collect` | `collector.interval_seconds` | `poll` → `Grouper.ingest` (one transaction with cursor) → enqueue incidents needing triage |
| `triage` | continuous | `await queue.next()` (rate limited) → `Pipeline.process` |
| `telegram` | long poll | `poll_actions` → `ApprovalService.handle` (only if Telegram enabled) |
| `housekeeping` | 60 s | close stale incidents, expire approvals, daily summary when due, health checks, CrowdSec allow-list refresh (hourly) |
| (in housekeeping) | 24 h | `Store.purge` retention |

### Health

`HealthMonitor` keeps the last state of `lapi`, `ollama`, `model`, `model_output`, `cti`, `telegram`,
`volume` and sends a `health` notification only on state **changes** (down → up is reported too;
a healthy first observation is silent), with a 15-minute repeat while down or warning. The state
is also exposed by `nazar status` through `kv["health"]` (JSON snapshot written every minute).

The daily summary is due once the local time (`notifier.timezone`) passes
`daily_summary_time`; `kv["summary.last_sent"]` holds the local date. On the very first start after
that time the summary waits for the next day instead of firing immediately.

### Startup

1. Load config + secrets, set up logging (redacting secrets).
2. Open DB and migrate.
3. LAPI login (retry with backoff; the daemon starts anyway and reports health down).
4. Ollama health; model missing → health alert, every verdict falls back to `unknown`.
5. Rebuild the triage queue from the store; reconcile half-applied decisions (09).
6. Start tasks. Log `nazar_started` with version, mode, model, prompt version.

### Shutdown

`SIGTERM`/`SIGINT` → stop accepting new work, let the current incident finish (≤ analyst timeout),
cancel tasks, close clients and DB, exit 0. systemd `TimeoutStopSec=90`.

## Dry-run reports

In `dry_run` mode the collect task prints (and logs) a report after each cycle that had incidents:
one line per incident — ID, IP, scenarios, verdict, severity, confidence, **intended** outcome and
action. `nazar run --dry-run --once` runs a single collect + triage-until-queue-empty cycle and exits
(useful for evaluation and the M1 acceptance check).

## Tests

End-to-end with fakes: LAPI fixtures → incidents → fake LLM → policy → fake backend; dry-run never
calls the decision backend; exceptions in one incident do not stop the next; shutdown is clean.
