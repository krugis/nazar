# 02: Config (`nazar.config`)

## Files and precedence

| What | Default path | Override | Mode |
|---|---|---|---|
| Config | `/etc/nazar/config.yaml` | `--config`, `NAZAR_CONFIG` | `0640 root:nazar` |
| Secrets | `/etc/nazar/secrets.env` | `NAZAR_SECRETS` | `0600 nazar:nazar` |

Precedence for secrets: process environment > `secrets.env` (`load_secrets` never overrides an
existing variable, so systemd `EnvironmentFile=` and manual exports both work).

`secrets.env` format: `KEY=value` lines, optional `export `, optional matching quotes, `#` comments.

| Secret variable | Used by | Created by |
|---|---|---|
| `NAZAR_LAPI_PASSWORD` | collector, actuator | `nazar init` (from `cscli machines add`) |
| `NAZAR_CTI_KEY` | enrich (optional) | user |
| `NAZAR_TG_TOKEN` | notify (optional) | user |
| `NAZAR_HMAC_KEY` | Telegram callback signing | `nazar init` (32 random bytes, hex) |

The config file only names the variables (`password_env`, `cti_api_key_env`, `bot_token_env`).

## Schema

Pydantic models, `extra="forbid"` on every section, so typos fail `nazar config check`.
Defaults equal DESIGN §6. Only additions beyond DESIGN are listed with a ★.

| Section | Keys |
|---|---|
| root | `mode: dry_run \| active` |
| `crowdsec` | `lapi_url`, `machine_id`, `password_env`★, `cti_api_key_env`, `cti_url`★, `cti_cache_hours`★ (24), `timeout_seconds`★ (10), `decision_origin`★ (`cscli`, D6), `use_cscli_fallback`★ (false), `import_allowlists`★ (false) |
| `collector` | `interval_seconds` (30, ≥5), `lookback`★ (`1h`, first poll window), `batch_limit`★ (500) |
| `prefilter` | `dedupe_window_seconds` (300), `incident_window_minutes` (30), `max_sample_lines`★ (20), `max_line_length`★ (300) |
| `analyst` | `ollama_url`, `model`, `timeout_seconds`, `temperature`, `max_calls_per_minute`, `prompt_version`, `num_ctx`★ (4096), `num_predict`★ (512), `max_queue`★ (200), `think`★ (`null` = omit option), `keep_alive`★ (`30m`) |
| `policy` | `auto_actions`, `auto_min_confidence`, `approval_min_confidence`, `max_ban_duration`, `max_auto_actions_per_hour`, `allowlist_cidrs`, `default_ban_duration`★ (`4h`), `host_addresses`★, `captcha_available`★ (false) |
| `notifier` | `telegram.{enabled, bot_token_env, chat_id, allowed_user_ids★}`, `approval_ttl_minutes`, `daily_summary_time`, `timezone` |
| `host_context` | `exposed_services` |
| `store` | `path`, `retention_days` |

Cross-field validation:
- `approval_min_confidence ≤ auto_min_confidence`
- `default_ban_duration ≤ max_ban_duration`
- `auto_actions ⊆ Action` (enum validation does this)
- `allowlist_cidrs`, `host_addresses` parse as networks
- `daily_summary_time` is `HH:MM`, `timezone` is a valid IANA zone
- `telegram.enabled` ⇒ `chat_id` non-empty

## API

```python
def load_config(path: Path | None = None) -> Config      # raises ConfigError
def load_secrets(path: Path | None = None) -> None
def secret(env_name: str | None) -> str | None
def check_config(cfg: Config) -> list[Issue]             # semantic checks for `nazar config check`
```

`check_config` returns warnings that are not schema errors, e.g. required secret missing, store
directory not writable, `mode: active` with an empty allow-list, captcha in `auto_actions` without a
captcha bouncer. The CLI adds the prompt-version check (prompt file version differs from
`analyst.prompt_version`), since config must not import the analyst.

`--dry-run` on the CLI produces a copy with `mode=dry_run` (`cfg.model_copy(update=…)`); config
objects are never mutated.

## Tests

Example config loads; every default matches DESIGN §6; each cross-field rule rejects; unknown key
rejects; secrets parsing (quotes, comments, `export`, no override).
