# 04: Collector (`nazar.collector`)

Reads new alerts from the CrowdSec Local API and turns them into `Event`s.
Endpoints verified against `pkg/models/localapi_swagger.yaml` (CrowdSec master, Oct 2026).

## Files

| File | Contents |
|---|---|
| `lapi.py` | `LapiClient`: auth + raw HTTP calls (also used by the actuator, 09) |
| `normalize.py` | `alert_to_event(alert: dict, cfg) -> Event \| None` |
| `source.py` | `AlertSource` protocol, `LapiAlertSource` (polling + cursor) |

## LapiClient

```python
class LapiClient:
    def __init__(self, base_url: str, machine_id: str, password: str,
                 http: httpx.AsyncClient, clock: Clock) -> None
    async def login(self) -> None
    async def get_alerts(self, *, since: str, limit: int) -> list[dict]
    async def get_alert(self, alert_id: str) -> dict
    async def push_alerts(self, alerts: list[dict]) -> list[str]
    async def delete_decision(self, decision_id: int) -> int
    async def delete_decisions(self, *, ip: str, scenario: str) -> int
    async def health(self) -> bool
```

| Call | Request | Response |
|---|---|---|
| login | `POST /v1/watchers/login` `{"machine_id", "password", "scenarios": []}` | `200 {"code", "expire", "token"}` |
| get_alerts | `GET /v1/alerts?since=<dur>&limit=<n>` (+ `Authorization: Bearer`) | `200 [Alert]` |
| get_alert | `GET /v1/alerts/{id}` | `200 Alert` (with `decisions[].id`) |
| push_alerts | `POST /v1/alerts` `[Alert]` | `201 ["<alert_id>"]` |
| delete_decision | `DELETE /v1/decisions/{id}` | `200 {"nbDeleted": "1"}` |
| delete_decisions | `DELETE /v1/decisions?ip=…&scenario=…` | `200 {"nbDeleted": "n"}` |

Auth handling:
- Token kept in memory with its `expire` time. Refresh proactively when less than 60 s remain.
- On `401`, re-login once and retry the request once. A second `401` raises `LapiAuthError`.
- `403` on login → `LapiAuthError("machine not validated or wrong password")`.
- Timeouts from `crowdsec.timeout_seconds`. Network errors → `LapiError(status=None)`.
- The password is never logged; the token never leaves the client.

To verify against a live LAPI during M1 acceptance (tracked in TRACKER): whether `include_capi`
must be passed to exclude community-blocklist alerts, the default `limit`, and the sort order.

## Polling and cursor (`LapiAlertSource.poll()`)

```
last_poll  = kv["lapi.last_poll"]  or now - collector.lookback
window     = now - last_poll + 2 × interval      # overlap so nothing falls between polls
since      = format_duration(min(window, lookback × 24))
alerts     = get_alerts(since=since, limit=batch_limit)
new        = [a for a in alerts if a.id > kv["lapi.cursor"] and not seen(a.id)]
events     = [alert_to_event(a) for a in sorted(new, key=id)] minus None
kv["lapi.cursor"] = max id ; kv["lapi.last_poll"] = now     # after the events are stored (11)
```

- The cursor (max alert ID) prevents reprocessing; `seen_alerts` is a second guard for IDs below
  the cursor that arrive late. Both are committed in the same transaction as the events (11), so a
  crash cannot lose or double-process alerts.
- If `len(alerts) == batch_limit`, the response may be truncated: log `lapi_batch_truncated`,
  raise a health warning and poll again immediately (newest-first means older ones may be missed;
  documented limitation, revisit with DESIGN open question 2).
- On `LapiError`: exponential backoff 5 s → 5 min, health alert after 3 consecutive failures.

## Normalization rules (`alert_to_event`)

Return `None` (and log at debug) when:
- `scenario` starts with `nazar/` (feedback loop, DESIGN §3.1)
- `source.scope` is not `ip` (case-insensitive). v1 handles single IPs only.
- `source.ip`/`value` is not a valid IP address
- `simulated` is true (decisions in simulation mode are not real signals)

Field mapping is listed in 01 (Event). Details:
- `crowdsec_decisions`: `type` of each `decisions[]` entry still in force: `until` in the future
  when present; otherwise `duration` not negative. Verified live with CrowdSec 1.8.1: alerts omit
  `until` and report `duration` as the remaining time, negative once the decision expired or was
  deleted (`-24s`). Without this, every past CrowdSec ban looked active forever and R5 blocked Nazar.
- `asn`: `"AS{as_number} {as_name}"` when both exist.
- `sample_lines`: CrowdSec does not ship raw log lines in alerts. Build one line per entry in
  `events[]` from its `meta` list: `key=value` pairs joined with `" "`, keys sorted, only the keys in
  `SAMPLE_META_KEYS` (`log_type`, `service`, `http_verb`, `http_path`, `http_status`,
  `http_user_agent`, `target_fqdn`, `user`, `target_user`, `rule_name`, `matched_zones`). Then
  `sanitize.clean()` and `truncate(max_line_length)` each, keep at most `max_sample_lines`.
- Everything taken from the alert is untrusted. Sanitizing happens here, once, at the boundary.

## Tests

respx fixtures in `tests/fixtures/lapi/`: login ok/403, alerts list (ssh-bf, http-probing, a
`nazar/ai-triage` alert, a range-scoped alert, a simulated one), 401-then-ok, truncated batch.
Assert: token refresh, single retry, cursor monotonic, filtered alerts, sanitized lines.
