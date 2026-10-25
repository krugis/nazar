# 12: CLI (`nazar.cli`)

`argparse` (decision D1). Entry point `nazar = nazar.cli:main`.

## Structure

```
cli/
├── __init__.py      # main(): build parser, global options, dispatch, exit codes
├── _context.py      # load secrets + config, set up logging and redaction
├── _output.py       # table / JSON printing
├── run.py           # run
├── setup.py         # init, config check, status, test-model
├── incidents.py     # incidents, explain, report
└── actions.py       # approve, reject, rollback
```

Each module exposes `register(subparsers)` and handler functions `def cmd_x(args) -> int`; a
handler loads config through `_context.load(args)` and builds the `App` only if it needs one.
Adding a command = one function + one `register` line.

Global options: `--config PATH`, `--secrets PATH`, `--log-level`, `--log-format json|text`
(default `text` on a TTY, `json` otherwise), `--json` (machine-readable output where supported).

Exit codes: `0` ok, `1` runtime error / check failed, `2` config error, `3` refused by policy.

## Commands

| Command | Behaviour |
|---|---|
| `nazar init [--non-interactive] [--machine-id nazar]` | Root only. Create `/etc/nazar/` (0750), write `config.yaml` from the packaged example if absent (never overwrite), create `/var/lib/nazar` owned by `nazar`. Register the machine: `cscli machines add <id> --auto -f -` (stdout parsed as YAML for `password`; **never** the default credentials file, which belongs to the CrowdSec agent). Generate `NAZAR_HMAC_KEY`. Write `secrets.env` (0600) merging existing keys. Detect captcha-capable bouncers via `cscli bouncers list -o json` (name contains `nginx`, `openresty`, `traefik`, `cloudflare`) and suggest `captcha_available`. Check Ollama + model, then run `config check` and a one-incident self-test. Idempotent: re-running keeps existing values. |
| `nazar run [--dry-run] [--once]` | Start the daemon (11). `--dry-run` forces dry-run whatever the config says. |
| `nazar status` | LAPI reachable + auth, Ollama + model present, mode, queue size, last cursor and poll time, pending approvals, last health snapshot. Exit 1 if a required component is down. |
| `nazar incidents [--since 24h] [--ip IP] [--limit 50]` | Table: ID, IP, last seen, scenarios, verdict, severity, confidence, outcome, applied. |
| `nazar explain <incident_id>` | Full trail: events with sample lines, enrichment, model input, verdict (+ model, prompt version, attempts, latency), every policy reason and warning, actions, approvals, rollbacks, audit entries. |
| `nazar approve <approval_id>` / `nazar reject <approval_id>` | Through `ApprovalService` with actor `user:cli:<login user>`. Approve re-runs the policy; refused → exit 3 with reasons. |
| `nazar rollback (--incident ID \| --since DUR \| --decision ID) [--yes]` | Lists what will be removed, asks for confirmation unless `--yes`, then `Actuator.rollback`. |
| `nazar report [--daily] [--send]` | Print the summary for the last 24 h; `--send` also sends it through the notifiers. |
| `nazar test-model [--file PATH] [--limit N]` | Run eval incidents through the analyst (no policy, no actions) and print metrics (07). |
| `nazar config check` | Schema validation + `check_config` warnings. Exit 2 on errors, 1 on warnings with `--strict`. |

Commands that only read (status, incidents, explain, report, config check) work while the daemon is
running (WAL, 03). `approve`, `reject`, `rollback` are safe concurrently because state changes are
atomic and idempotent.

## Tests

Parser wiring for every command; `config check` exit codes; `explain` output on a seeded DB;
`rollback` confirmation; `init` with a fake `cscli` on `PATH` (writes into a temp root via
`NAZAR_ROOT` override used only by tests).
