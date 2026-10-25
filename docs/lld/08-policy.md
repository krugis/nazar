# 08: Policy engine (`nazar.policy`)

Turns a `Verdict` for an `Incident` into a `Decision` (DESIGN §3.5). **Pure**: no I/O, no clock, no
randomness, no imports outside `nazar.models` and `nazar.config` (decision D4). `mypy --strict`.

## Files

| File | Contents |
|---|---|
| `engine.py` | `evaluate(inp, cfg, mode) -> Decision` |
| `rules.py` | one function per rule, `RULES` ordered list |
| `types.py` | `PolicyInput`, `Draft` |

## Interface

```python
@dataclass(frozen=True)
class PolicyInput:
    incident: Incident
    verdict: Verdict
    allowlist_match: str | None      # from AllowList.match(); re-checked here, see R1
    auto_enforced_last_hour: int     # applied auto ban/captcha decisions in the last 60 min
    approved_by: str | None = None   # set when re-evaluating a human approval (10, 12)

def evaluate(inp: PolicyInput, cfg: PolicyConfig, mode: Mode,
             allowlist: IpMatcher | None = None) -> Decision
```

`allowlist` is any object with `match(ip) -> str | None` (the `IpMatcher` protocol in
`policy/types.py`; `prefilter.AllowList` satisfies it, so policy never imports prefilter). It lets the
engine re-check the IP itself; a match from either source denies.

## Algorithm

`Draft` is a small mutable working copy (`action`, `outcome`, `duration`, `reasons`, `warnings`,
`unusual_volume`, `final`). Rules run in order; a rule may mark the draft `final`, which skips the
remaining rules except the mode gate. Every rule that changes the draft appends one short reason.

| # | Rule | Applies when | Effect |
|---|---|---|---|
| R1 | Hard deny | IP allow-listed or protected, or not a valid single IP | `no_action`, final |
| R2 | Action whitelist | action not in `Action`, or `captcha` while `captcha_available` is false | `no_action` + warning, final |
| R3 | Nothing to do | action `none` | `no_action`, final |
| R4 | Verdict consistency | enforcing action with verdict `benign` or `unknown` | `report_only` + warning, final |
| R5 | Already enforced | enforcing action and `crowdsec_already_banned` | `report_only` ("CrowdSec already bans this IP"), final |
| R6 | Bounds | enforcing action | duration = proposed or `default_ban_duration`, clamped to `max_ban_duration` (warning when clamped); scope is always a single IP, ranges never produced |
| R7 | Thresholds | always | enforcing: `auto` if confidence ≥ `auto_min_confidence` **and** severity ≥ `high` **and** action ∈ `auto_actions`; else `approval` if confidence ≥ `approval_min_confidence`; else `report_only`. `notify`: `auto` if confidence ≥ `approval_min_confidence` and `notify` ∈ `auto_actions`, else `report_only` (a message never needs approval) |
| R8 | Corroboration | outcome `auto` and enforcing | needs ≥ 1 of: `cti_reputation == "malicious"`, ≥ 2 distinct scenarios, `history.previous_incidents ≥ 1`, `history.previous_bans ≥ 1`. Otherwise → `approval` |
| R9 | Budget | outcome `auto` and enforcing | `auto_enforced_last_hour ≥ max_auto_actions_per_hour` → `approval`, `unusual_volume = True` |
| R10 | Human approval | `approved_by` set | `approval` → `auto` (reason "approved by …"). Any other outcome stays as is, so a click can never raise `report_only`/`no_action`, and R1–R6 are always re-checked |
| R11 | Mode gate | `mode == dry_run` | `intended_outcome = outcome`; outcome → `report_only` unless it is `no_action` |

`intended_outcome` equals `outcome` in active mode. Applying the mode gate last gives the same final
outcome as DESIGN's order (mode gate second) while still telling dry-run reports what *would* have
happened.

Adding a rule = one function in `rules.py`, one entry in `RULES`, rows in the test table, one row in
this document.

## Guarantees (each has a test)

1. An allow-listed/protected IP always yields `no_action`, for any verdict, mode, approval or budget.
2. Dry-run never yields `auto` or `approval`.
3. Output action ∈ `Action`; every enforcing decision that can be applied (intended `auto` or
   `approval`) carries a duration, and any duration is ≤ `max_ban_duration`.
4. A single scenario with no CTI/history never becomes `auto` enforcing.
5. Budget exhaustion never yields `auto` enforcing without `approved_by`.
6. `evaluate` is deterministic: same input, same output.

## Tests

`tests/policy/test_rules.py`: a table of ~40 cases (input sketch → expected action, outcome,
intended, duration, reasons subset). `test_properties.py`: guarantees 1–6 over a generated grid of
verdict × severity × confidence (0, 0.59, 0.6, 0.84, 0.85, 1.0) × mode × allow-listed × budget.
