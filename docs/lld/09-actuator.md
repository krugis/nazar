# 09: Actuator (`nazar.actuator`)

Applies enforcing decisions **only through CrowdSec** and rolls them back (DESIGN §3.6).

## Files

| File | Contents |
|---|---|
| `backend.py` | `DecisionBackend` protocol |
| `lapi_backend.py` | push/delete through `LapiClient` (04) |
| `cscli_backend.py` | fallback through `cscli` (only if `use_cscli_fallback`) |
| `actuator.py` | `Actuator.apply(...)`, `Actuator.rollback(...)` |

## Interface

```python
class DecisionBackend(Protocol):
    async def add(self, req: BanRequest) -> str                   # returns CrowdSec alert id
    async def remove(self, crowdsec_alert_id: str, ip: str) -> int  # number of decisions removed
    async def find(self, req: BanRequest) -> str | None           # crash reconcile (by message)

@dataclass(frozen=True)
class BanRequest:
    ip: str                 # validated single IP
    type: Action            # ban | captcha
    duration: str           # validated, ≤ max_ban_duration
    incident_id: str
    decision_id: int

class Actuator:
    async def apply(self, decision_id: int) -> ApplyResult        # applied | already_applied | refused
    async def rollback(self, *, decision_id: int | None = None,
                       incident_id: str | None = None,
                       since: timedelta | None = None, by: str) -> list[RollbackResult]
```

`apply` loads the decision from the store and refuses (`PolicyViolation`, logged as an error) unless
`outcome == auto`, `action.enforces`, mode is `active`, and the IP is not allow-listed (re-checked
here as a last guard). The model's text never reaches this module; only validated fields do.

`LapiDecisionBackend` talks to CrowdSec through the `LapiDecisionApi` protocol (the five LAPI calls it
needs). `app.py` passes the collector's `LapiClient`, so the actuator never imports the collector
(dependency rule 4).

## Idempotency

`idempotency_key = sha256(f"{incident_id}|{action}|{ip}")`, unique in `decisions`. Before pushing:
if a decision with that key is already applied and not rolled back → `already_applied`, no call. If
that earlier decision was **rolled back**, a new decision for the same incident is `refused`: a human
removed it, so Nazar must not silently ban again.
The key is written before the push and `applied_at`/`crowdsec_alert_id` right after, in one
transaction per step. If the process dies between push and record, the next start finds the
unapplied row and reconciles: `GET /v1/alerts?scenario=nazar/ai-triage&ip=<ip>` and match the
incident ID in the alert message before pushing again.

## LAPI payload (`POST /v1/alerts`, verified against the swagger)

```json
[{
  "scenario": "nazar/ai-triage",
  "scenario_hash": "",
  "scenario_version": "",
  "message": "nazar inc_2026_10_25_0001 decision 42: ban 203.0.113.45 for 4h",
  "events_count": 1,
  "start_at": "<now RFC3339>",
  "stop_at": "<now RFC3339>",
  "capacity": 0,
  "leakspeed": "0",
  "simulated": false,
  "remediation": true,
  "events": [],
  "labels": ["nazar", "incident:inc_2026_10_25_0001"],
  "source": {"scope": "Ip", "value": "203.0.113.45", "ip": "203.0.113.45"},
  "decisions": [{
    "type": "ban",
    "scope": "Ip",
    "value": "203.0.113.45",
    "duration": "4h",
    "origin": "<crowdsec.decision_origin>",
    "scenario": "nazar/ai-triage"
  }]
}]
```

Response `201 ["<alert_id>"]` → store `crowdsec_alert_id`. The decision then shows in
`cscli decisions list` with reason `nazar/ai-triage` (M2 acceptance).

To verify on a live LAPI (TRACKER): accepted values for `events: []` and `labels`, and that a custom
`decision_origin` works.

## cscli fallback

Only when `crowdsec.use_cscli_fallback` is true and the LAPI push failed with a non-auth error:
`["cscli", "decisions", "add", "--ip", ip, "--type", type, "--duration", duration,
"--reason", "nazar/ai-triage"]` via `asyncio.create_subprocess_exec` (no shell), 15 s timeout.
No alert ID comes back, so `crowdsec_alert_id = "cscli"` and rollback uses the filter path.

## Rollback

For each selected applied decision not yet rolled back:
1. `GET /v1/alerts/{crowdsec_alert_id}` → `DELETE /v1/decisions/{id}` for each decision in it.
2. If the alert is gone or the ID is `cscli`: `DELETE /v1/decisions?ip=<ip>&scenario=nazar/ai-triage`
   (removes only Nazar decisions on that IP).
3. `mark_rolled_back(decision_id, by)` and an audit entry, also when CrowdSec reports 0 deleted
   (already expired).

Selection: `--incident <id>` → its decisions; `--since 1h` → applied within the window; one decision
ID (Telegram button). Nazar never deletes decisions it did not create.

## Tests

respx: payload snapshot; idempotent second apply makes no HTTP call; refuse in dry-run and for
allow-listed IPs; rollback by alert ID and by filter; reconcile after crash; cscli argv built from
validated values only.
