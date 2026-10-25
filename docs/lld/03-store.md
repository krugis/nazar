# 03: Store (`nazar.store`)

SQLite at `store.path` through stdlib `sqlite3` (decision D3).

## Files

| File | Contents |
|---|---|
| `db.py` | `Database`: open, pragmas, migrate, transaction helper |
| `migrations.py` | `MIGRATIONS: list[tuple[int, str]]` |
| `incidents.py` | `IncidentRepo`, `EventRepo` |
| `triage.py` | `VerdictRepo`, `DecisionRepo`, `ApprovalRepo` |
| `state.py` | `KvRepo`, `CtiCacheRepo`, `AuditLog` |
| `__init__.py` | `Store` facade (all repositories + `purge`) |

## Connection

- `PRAGMA journal_mode=WAL; foreign_keys=ON; busy_timeout=5000; synchronous=NORMAL`.
- One connection per process, autocommit mode with explicit `BEGIN IMMEDIATE` transactions
  (`with db.transaction():`, re-entrant). Calls are synchronous (D2). The CLI opens its own
  connection; WAL makes the daemon and CLI safe to run together.
- Timestamps: ISO-8601 UTC text (`2026-10-25T17:02:11Z`). JSON columns: `TEXT` holding JSON.
- Directory created with mode `0750`, file `0640`.

## Migrations

`PRAGMA user_version` holds the schema version. On open, every migration with a higher number runs
inside one transaction, in order. Migrations are append-only: never edit a released one.

## Schema (migration 1)

```sql
CREATE TABLE incidents (
  id            TEXT PRIMARY KEY,          -- inc_2026_10_25_0001
  source_ip     TEXT NOT NULL,
  status        TEXT NOT NULL,             -- open | closed
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  event_count   INTEGER NOT NULL,
  scenarios     TEXT NOT NULL,             -- JSON array
  needs_triage  INTEGER NOT NULL DEFAULT 1,
  last_triaged_scenarios TEXT,             -- JSON array, for "no new signal" (05)
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX ix_incidents_ip_last ON incidents(source_ip, last_seen);
CREATE INDEX ix_incidents_triage ON incidents(needs_triage) WHERE needs_triage = 1;

CREATE TABLE events (
  id            INTEGER PRIMARY KEY,
  incident_id   TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  alert_id      INTEGER NOT NULL UNIQUE,   -- first LAPI alert merged into this row
  scenario      TEXT NOT NULL,
  first_ts      TEXT NOT NULL,
  last_ts       TEXT NOT NULL,
  event_count   INTEGER NOT NULL,
  merged_alerts INTEGER NOT NULL DEFAULT 1,
  sample_lines  TEXT NOT NULL,             -- JSON array
  labels        TEXT NOT NULL,             -- JSON array
  crowdsec_decisions TEXT NOT NULL         -- JSON array
);
CREATE INDEX ix_events_incident ON events(incident_id);

CREATE TABLE seen_alerts (                 -- every LAPI alert id consumed, incl. merged ones
  alert_id INTEGER PRIMARY KEY,
  seen_at  TEXT NOT NULL
);

CREATE TABLE verdicts (
  id             INTEGER PRIMARY KEY,
  incident_id    TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  created_at     TEXT NOT NULL,
  model          TEXT NOT NULL,            -- e.g. hf.co/Nguuma/security-slm-unsloth-1.5b, or "none"
  prompt_version TEXT NOT NULL,
  verdict        TEXT NOT NULL,
  severity       TEXT NOT NULL,
  confidence     REAL NOT NULL,
  proposed_action TEXT NOT NULL,
  body           TEXT NOT NULL,            -- full Verdict JSON
  input          TEXT NOT NULL,            -- Incident JSON that was sent (explain)
  valid_output   INTEGER NOT NULL,         -- 0 when the fallback was used
  attempts       INTEGER NOT NULL,         -- 1 or 2
  latency_ms     INTEGER,
  skipped_reason TEXT                      -- set when the model was not called (05)
);

CREATE TABLE decisions (
  id               INTEGER PRIMARY KEY,
  incident_id      TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  verdict_id       INTEGER NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
  created_at       TEXT NOT NULL,
  action           TEXT NOT NULL,
  outcome          TEXT NOT NULL,
  intended_outcome TEXT NOT NULL,
  duration         TEXT,
  reasons          TEXT NOT NULL,          -- JSON array
  warnings         TEXT NOT NULL,          -- JSON array
  idempotency_key  TEXT UNIQUE,            -- sha256(incident|action|ip), enforcing actions only
  applied_at       TEXT,
  crowdsec_alert_id TEXT,
  rolled_back_at   TEXT,
  rolled_back_by   TEXT
);
CREATE INDEX ix_decisions_applied ON decisions(applied_at) WHERE applied_at IS NOT NULL;

CREATE TABLE approvals (
  id           TEXT PRIMARY KEY,           -- random token
  decision_id  INTEGER NOT NULL UNIQUE REFERENCES decisions(id) ON DELETE CASCADE,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  status       TEXT NOT NULL,              -- pending | approved | rejected | expired
  resolved_at  TEXT,
  resolved_by  TEXT,
  message_ref  TEXT                        -- notifier message id, to edit the message later
);
CREATE INDEX ix_approvals_pending ON approvals(expires_at) WHERE status = 'pending';

CREATE TABLE kv (                          -- cursors and small state
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
);                                         -- keys: lapi.cursor, lapi.last_poll, tg.offset, summary.last_sent

CREATE TABLE cti_cache (
  ip TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, body TEXT NOT NULL   -- normalized JSON
);

CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY,
  ts          TEXT NOT NULL,
  actor       TEXT NOT NULL,               -- model | policy | system | user:<id>
  kind        TEXT NOT NULL,               -- verdict | decision | applied | approval | rollback | health
  incident_id TEXT,
  ref_id      TEXT,                        -- verdict/decision/approval id
  detail      TEXT NOT NULL                -- JSON
);
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
```

Note: `audit_log` has no foreign keys on purpose, so it outlives deleted incidents until its own
retention. Deletes are allowed only by the retention job.

## Repositories (public API)

| Class | Key methods |
|---|---|
| `IncidentRepo` | `find_open(ip, since) -> IncidentRow \| None`, `create(...)`, `update(...)`, `next_id(day)`, `pending_triage(limit)`, `list(since, ip=None)`, `get(id)`, `close_stale(before)` |
| `EventRepo` | `add(...)`, `merge_into(event_id, alert, ...)`, `for_incident(id)`, `mark_seen(alert_id)`, `is_seen(alert_id)` |
| `VerdictRepo` | `add(...) -> id`, `latest(incident_id)` |
| `DecisionRepo` | `add(...) -> id`, `get(id)`, `by_idempotency_key(k)`, `mark_applied(id, alert_id)`, `mark_rolled_back(id, by)`, `applied(since=None, incident_id=None, active_only=True)`, `count_auto_enforced(since)` |
| `ApprovalRepo` | `create(decision_id, ttl) -> Approval`, `get(id)`, `resolve(id, status, by)` (only from `pending`, atomic `UPDATE … WHERE status='pending'`), `expire_due(now) -> list[Approval]` |
| `KvRepo` | `get(key)`, `set(key, value)` |
| `CtiCacheRepo` | `get(ip, max_age)`, `put(ip, body)` |
| `AuditLog` | `append(actor, kind, detail, incident_id=None, ref_id=None)` |

Incident IDs: `next_id(day)` runs inside the same transaction as `create`:
`SELECT COUNT(*)+1 FROM incidents WHERE id LIKE 'inc_YYYY_MM_DD_%'`, formatted with four digits
(five or more when the day exceeds 9999).

## Retention

`Store.purge(older_than)` once a day (11): deletes closed incidents (cascade to events, verdicts,
decisions, approvals) with `last_seen` older than `retention_days`, never ones that have an applied
decision not yet expired; also old `seen_alerts`, `cti_cache` rows past their max age, and
`audit_log` rows past retention. Then `PRAGMA optimize`.

## Tests

Migrate a fresh DB; re-open is a no-op; audit update raises; approval `resolve` is single-shot;
`next_id` sequence; purge keeps rows that must stay.
