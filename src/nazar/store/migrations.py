"""Numbered, append-only schema migrations (LLD 03). Never edit a released migration."""

from __future__ import annotations

_V1 = """
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
  crowdsec_decisions TEXT NOT NULL,        -- JSON array
  country       TEXT,
  asn           TEXT
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
"""

MIGRATIONS: list[tuple[int, str]] = [
    (1, _V1),
]
