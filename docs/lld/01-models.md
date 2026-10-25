# 01: Models (`nazar.models`)

Pure data contracts shared by every stage. No I/O. Pydantic v2.

## Files

| File | Contents |
|---|---|
| `enums.py` | `VerdictLabel`, `Severity`, `Action`, `Outcome`, `IncidentStatus`, `ApprovalStatus`, `Actor` |
| `durations.py` | `parse_duration`, `format_duration`, `VERDICT_DURATION_RE` |
| `event.py` | `Event` |
| `incident.py` | `Incident`, `Enrichment`, `History` |
| `verdict.py` | `Verdict`, `VERDICT_JSON_SCHEMA` |
| `decision.py` | `Decision`, `AppliedDecision`, `Approval` |

## Enums (`StrEnum`)

| Enum | Values | Notes |
|---|---|---|
| `VerdictLabel` | `malicious`, `suspicious`, `benign`, `unknown` | |
| `Severity` | `low`, `medium`, `high`, `critical` | `.rank` → 0..3 for comparisons |
| `Action` | `none`, `notify`, `ban`, `captcha` | `.enforces` is true for `ban`, `captcha`. **This enum is the action whitelist** (DESIGN §4.3). |
| `Outcome` | `auto`, `approval`, `report_only`, `no_action` | result of the policy engine |
| `IncidentStatus` | `open`, `closed` | `closed` once its window has passed |
| `ApprovalStatus` | `pending`, `approved`, `rejected`, `expired` | |
| `Actor` | `model`, `policy`, `system`, `user:<id>` | audit log actor; `user:` carries the Telegram ID or `cli:<unix user>` |

## Durations

- `parse_duration("30m") -> timedelta`; accepts `^\d+(s|m|h|d)$` (config, CLI).
- Verdicts accept only `^\d+(m|h)$` (DESIGN §4.2).
- `format_duration(timedelta) -> str` produces Go `time.ParseDuration` strings (`4h`, `90m`, `30s`)
  for CrowdSec.

## Event

One normalized CrowdSec alert (built by the collector, 04). Frozen.

| Field | Type | Source in LAPI `Alert` |
|---|---|---|
| `alert_id` | `int` | `id` |
| `source_ip` | `str` | `source.ip` or `source.value` (scope `Ip`) |
| `scenario` | `str` | `scenario` |
| `started_at`, `stopped_at` | `datetime` (UTC) | `start_at`, `stop_at` |
| `event_count` | `int` | `events_count` |
| `message` | `str` | `message` (sanitized, ≤ 300 chars) |
| `sample_lines` | `list[str]` | built from `events[].meta` (see 04) |
| `labels` | `list[str]` | `labels` |
| `country`, `asn` | `str \| None` | `source.cn`, `source.as_number` + `source.as_name` |
| `crowdsec_decisions` | `list[str]` | types of `decisions[]` still active, e.g. `["ban"]` |

## Incident (model input, DESIGN §4.1)

| Field | Type | Notes |
|---|---|---|
| `incident_id` | `str` | `inc_YYYY_MM_DD_NNNN`, UTC date, per-day counter (03) |
| `source_ip` | `str` | |
| `first_seen`, `last_seen` | `datetime` | |
| `scenarios` | `list[str]` | distinct, in first-seen order |
| `event_count` | `int` | sum over events |
| `sample_lines` | `list[str]` | already sanitized and capped (05) |
| `enrichment` | `Enrichment` | filled by 06 |
| `host_context` | `dict[str, list[str]]` | from config `host_context` |
| `crowdsec_already_banned` | `bool` | any event has an active CrowdSec decision |

`Enrichment`: `cti_reputation`, `cti_behaviors`, `cti_classifications`, `country`, `asn`,
`history: History(previous_incidents, previous_bans)`. Every field is optional/empty by default;
missing data is `null`, never a guess.

`Incident.model_input()` returns the JSON-ready dict the analyst embeds in the prompt (07).

## Verdict (model output, DESIGN §4.2)

```python
class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid")      # unknown fields are rejected
    verdict: VerdictLabel
    severity: Severity
    confidence: float          # 0.0 ≤ x ≤ 1.0
    attack_tactics: list[str]  # ≤ 10 items, each ≤ 80 chars
    summary: str               # ≤ 400 chars
    reasoning_points: list[str]  # ≤ 5 items, each ≤ 200 chars
    proposed_action: Action
    proposed_duration: str | None   # ^\d+(m|h)$, "" normalized to None
```

- `Verdict.unknown(reason)` builds the fallback: `unknown`, `low`, `0.0`, action `none`.
- `VERDICT_JSON_SCHEMA` is a **hand-written, flat** JSON schema (no `$ref`) passed to Ollama's
  `format` field. A unit test checks it stays equivalent to the pydantic model (same fields, enums,
  required list), so the two cannot drift.

## Decision and approvals

```python
class Decision(BaseModel):          # output of the policy engine (08)
    action: Action
    outcome: Outcome
    intended_outcome: Outcome       # what active mode would do; equals outcome in active mode
    duration: str | None            # clamped, CrowdSec format; only for enforcing actions
    reasons: list[str]              # one short line per rule that changed the result
    warnings: list[str]
    unusual_volume: bool = False

class AppliedDecision(BaseModel):   # a CrowdSec decision Nazar created (09)
    decision_id: int                # Nazar store row id
    crowdsec_alert_id: str
    ip: str
    type: Action                    # ban | captcha
    duration: str
    applied_at: datetime
    rolled_back_at: datetime | None

class Approval(BaseModel):          # pending human decision (10, 12)
    approval_id: str                # 11 random letters/digits (never starts with '-')
    decision_id: int
    incident_id: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    resolved_by: str | None
```

## Tests (`tests/models/`)

- Verdict: valid fixture parses; each rule from §4.2 rejects (confidence 1.2, summary 401 chars,
  6 reasoning points, extra field, `proposed_duration="2d"`, unknown action `"shell"`).
- Schema/model equivalence test.
- Duration round-trips and rejects (`"4 h"`, `"-1h"`, `"0h"` for format).
