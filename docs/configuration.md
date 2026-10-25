# Configuration reference

File: `/etc/nazar/config.yaml` (override with `--config` or `NAZAR_CONFIG`). Unknown keys are
errors, so typos are caught by `nazar config check`. Every key is optional; the values below are
the defaults.

Secrets never go in this file. It only names environment variables, which are read from the
process environment or `/etc/nazar/secrets.env` (`KEY=value` lines, mode 0600).

```yaml
mode: dry_run              # dry_run: triage and report only. active: may change CrowdSec.

crowdsec:
  lapi_url: http://127.0.0.1:8080
  machine_id: nazar                     # created by `nazar init`
  password_env: NAZAR_LAPI_PASSWORD     # secret: machine password
  cti_api_key_env: null                 # e.g. NAZAR_CTI_KEY to enable CTI enrichment
  cti_url: https://cti.api.crowdsec.net/v2
  cti_cache_hours: 24
  timeout_seconds: 10
  decision_origin: cscli                # origin of decisions Nazar creates
  use_cscli_fallback: false             # apply decisions with `cscli` if LAPI fails
  import_allowlists: false              # also honour CrowdSec allow-lists (refreshed hourly)

collector:
  interval_seconds: 30                  # LAPI polling interval
  lookback: 1h                          # first poll window when there is no cursor yet
  batch_limit: 500                      # alerts per poll

prefilter:
  dedupe_window_seconds: 300            # merge repeated alerts (same IP and scenario)
  incident_window_minutes: 30           # events of one IP within this window = one incident
  max_sample_lines: 20                  # log lines shown to the model per incident
  max_line_length: 300

analyst:
  ollama_url: http://127.0.0.1:11434
  model: granite4:micro-h
  timeout_seconds: 60
  temperature: 0.1
  max_calls_per_minute: 10              # excess incidents queue; overflow is summarized
  max_queue: 200
  prompt_version: triage-v1             # must match prompts/triage.md
  num_ctx: 4096
  num_predict: 2048                     # tokens for reasoning + answer (reasoning models think first)
  think: null                           # auto: false for reasoning models, omitted otherwise
  keep_alive: 30m

policy:
  auto_actions: [ban, notify]           # actions allowed without a human
  auto_min_confidence: 0.85             # and severity high or critical, and corroboration
  approval_min_confidence: 0.6          # below this: report only
  default_ban_duration: 4h              # when the model proposes none
  max_ban_duration: 24h                 # hard upper bound
  max_auto_actions_per_hour: 20         # above this, everything needs approval
  allowlist_cidrs: []                   # your offices, VPN, monitoring, CI
  host_addresses: []                    # extra addresses of this host (local ones are found automatically)
  captcha_available: false              # true only with a captcha-capable bouncer

enrich:
  timeout_seconds: 5                    # per provider
  geoip_country_db: null                # path to GeoLite2-Country.mmdb (needs the geoip extra)
  geoip_asn_db: null                    # path to GeoLite2-ASN.mmdb

notifier:
  telegram:
    enabled: false
    bot_token_env: NAZAR_TG_TOKEN       # secret: bot token
    chat_id: ""                         # required when enabled
    allowed_user_ids: []                # recommended for group chats
  approval_ttl_minutes: 60              # an unanswered approval expires: no action
  daily_summary_time: "09:00"
  timezone: UTC                         # IANA name, e.g. Europe/Istanbul

host_context:
  exposed_services: []                  # e.g. [ssh, nginx, php-fpm]; helps judge relevance

store:
  path: /var/lib/nazar/nazar.db
  retention_days: 90
```

## Secrets (`/etc/nazar/secrets.env`)

| Variable | Needed for | Created by |
|---|---|---|
| `NAZAR_LAPI_PASSWORD` | always | `nazar init` |
| `NAZAR_HMAC_KEY` | Telegram buttons (hex, at least 16 bytes) | `nazar init` |
| `NAZAR_TG_TOKEN` | Telegram | you |
| `NAZAR_CTI_KEY` | CTI enrichment | you |

Variable names can be changed with the `*_env` keys above. Secrets are redacted from logs.

## How the policy decides

For each verdict the rules run in this order (details: [LLD 08](lld/08-policy.md)):

1. allow-listed or protected IP (loopback, private ranges, this host, your CIDRs) → no action
2. action not allowed (e.g. captcha without a captcha bouncer) → no action
3. model proposes nothing → no action
4. ban proposed for a benign/unknown verdict → report only
5. CrowdSec already bans the IP → report only
6. duration clamped to `max_ban_duration`
7. `auto` needs confidence ≥ `auto_min_confidence`, severity ≥ high and the action in
   `auto_actions`; otherwise `approval` above `approval_min_confidence`; otherwise report only
8. `auto` bans also need an independent signal (CTI malicious, two or more scenarios, or history);
   otherwise approval
9. more than `max_auto_actions_per_hour` → approval and a health warning
10. a human approval turns `approval` into `auto` (rules 1–6 are still checked)
11. in `dry_run`, everything becomes report only (reports show what active mode would do)
