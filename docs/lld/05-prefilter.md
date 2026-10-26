# 05: Pre-filter (`nazar.prefilter`)

Cheap, deterministic steps before any model call (DESIGN §3.2).

## Files

| File | Contents |
|---|---|
| `allowlist.py` | `AllowList` (pure) and `build_allowlist(cfg, lapi=None)` |
| `grouper.py` | `Grouper.ingest(events) -> IngestResult` (dedupe + incidents, uses store) |
| `triage_queue.py` | `TriageQueue`: priority queue + rate limiter in front of the analyst |

## AllowList

```python
class AllowList:
    def __init__(self, networks: Iterable[IPNetwork], labels: Mapping[IPNetwork, str]) -> None
    def match(self, ip: str) -> str | None      # label of the first matching network, e.g. "rfc1918"
```

Always-protected networks (cannot be removed by config):

| Label | Networks |
|---|---|
| `loopback` | `127.0.0.0/8`, `::1/128` |
| `rfc1918` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| `link_local` | `169.254.0.0/16`, `fe80::/10` |
| `cgnat` | `100.64.0.0/10` |
| `ula` | `fc00::/7` |
| `unspecified` | `0.0.0.0/8`, `::/128` |
| `host` | this host's addresses: `policy.host_addresses` + addresses from `socket.getaddrinfo(gethostname())` + interface addresses read from `/proc/net/fib_trie` (IPv4, `/32 host LOCAL` entries) and `/proc/net/if_inet6` (IPv6). No subprocesses. |

Then `config` label for `policy.allowlist_cidrs`, and `crowdsec` label for CrowdSec allow-lists
when `crowdsec.import_allowlists` is on: LAPI `GET /v1/allowlists?with_content=true` (watcher JWT,
per the swagger); lists returned without `items` are fetched by name. Expired and invalid items are
skipped (CrowdSec sends `0001-01-01T00:00:00Z`, Go's zero time, for "never expires"; verified live
with 1.8.1). The daemon refreshes at startup and hourly, swapping the entries of a
`RefreshableAllowList` (an `IpMatcher` shared by grouper, pipeline, policy and actuator), so no
service needs rebuilding.
IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped before matching.

`AllowList` is immutable and has no I/O; `build_allowlist` gathers the inputs. The policy engine
receives the match result, and re-checks it itself (08), so an allow-listed IP is protected even if
a caller skips the pre-filter.

## Grouper

Input: events from one poll, sorted by `alert_id`. All writes for one poll happen in one transaction
together with the cursor update (04).

For each event:
1. `seen_alerts` already has the alert → skip.
2. **Allow-listed** → still stored (audit and reports), but its incident gets
   `needs_triage = 0` and a `skipped_reason = "allowlisted:<label>"` verdict row with model `none`.
3. **Find incident**: open incident for the IP with `last_seen ≥ event.started_at − incident_window`.
   None → create one (`next_id`).
4. **Dedupe**: an event row in that incident with the same scenario and
   `last_ts ≥ event.started_at − dedupe_window` → merge: add `event_count`, extend `last_ts`,
   append sample lines up to the cap, `merged_alerts += 1`. Otherwise insert a new event row.
5. Update incident: `last_seen`, `event_count`, `scenarios`, `crowdsec_already_banned`.
6. **Needs triage** is set when the incident is new, or gains a scenario not in
   `last_triaged_scenarios`, or (not banned by CrowdSec and a non-merged event was added).
   A merged duplicate alone never triggers a new model call.

Separately, `close_stale(now − incident_window)` marks old open incidents `closed`.

### Skip trivial cases

When an incident is picked for triage and `crowdsec_already_banned` is true and its scenarios equal
`last_triaged_scenarios` (no new signal), the pipeline records a verdict row with
`skipped_reason="already_banned_no_new_signal"` and does not call the model.

## TriageQueue

- Holds incident IDs needing triage. Priority (higher first):
  `distinct_scenarios × 10 + log2(event_count + 1) + (5 if not crowdsec_already_banned)`, ties by
  oldest `first_seen`.
- Token bucket: `max_calls_per_minute` tokens, refilled continuously. `await queue.next()` waits for
  a token.
- Overflow: when the queue holds more than `analyst.max_queue`, the lowest-priority oldest entries
  are removed and recorded as one bulk entry: a verdict row per incident with model `none`,
  `skipped_reason="rate_limited_bulk"`, verdict `unknown`, and a single summary line in the next
  report/health message ("N low-priority incidents summarized without model triage").
- The queue is rebuilt from `IncidentRepo.pending_triage()` on startup, so it survives restarts.

## Tests

Table-driven: allow-list labels (each protected range, mapped IPv6, config CIDR); grouping across
the window edge; dedupe inside/outside window; needs-triage rules; skip-trivial; queue ordering,
rate limit with a fake clock, overflow bulk-summarize.
