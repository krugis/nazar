# Installing Nazar

Nazar runs next to CrowdSec on the same Linux server. It needs no GPU and no cloud service.

## Requirements

| What | Notes |
|---|---|
| Linux, x86_64 or arm64 | Debian/Ubuntu or RHEL family; systemd for the service |
| [CrowdSec](https://docs.crowdsec.net/) Security Engine | with at least one bouncer (firewall, nginx, …) |
| [Ollama](https://ollama.com) | listening on `127.0.0.1:11434` |
| Python 3.11+ with `venv` | e.g. `apt install python3 python3-venv` on Ubuntu 24.04 |
| 4 GB RAM or more | the default model uses about 1.2 GB |

## 1. Install CrowdSec and a bouncer

Follow the CrowdSec documentation. Check that it works:

```bash
sudo cscli metrics
sudo cscli bouncers list
```

## 2. Install Ollama and pull the model

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull hf.co/Nguuma/security-slm-unsloth-1.5b
```

## 3. Install Nazar

From a checkout of this repository:

```bash
sudo sh deploy/install.sh --from .
```

The script is idempotent. It:

1. checks Python, `cscli` and Ollama,
2. creates the unprivileged system user `nazar`,
3. installs Nazar into `/opt/nazar/venv` and links `/usr/local/bin/nazar`,
4. runs `nazar init`, which
   - writes `/etc/nazar/config.yaml` (only if missing; your edits are never overwritten),
   - registers a CrowdSec machine `nazar` and stores its password in `/etc/nazar/secrets.env`
     (mode 0600; the CrowdSec agent's own credentials file is not touched),
   - generates the key that signs Telegram buttons,
   - creates the database in `/var/lib/nazar`,
   - checks LAPI, Ollama and the model, and runs one test incident through the model,
5. installs and enables `nazar.service`, but does **not** start it.

`--from` also accepts a wheel, a PyPI name or a git URL. Without `--from` it installs `nazar-sec`
from PyPI.

## 4. Configure

Edit `/etc/nazar/config.yaml` (reference: [configuration.md](configuration.md)). At least:

- add your own addresses (office, VPN, monitoring, CI) to `policy.allowlist_cidrs`,
- list the services the server exposes in `host_context.exposed_services`.

Then validate:

```bash
sudo nazar config check
sudo nazar status
```

## 5. Dry run first

Nazar starts in `mode: dry_run`. It triages and reports, but never changes CrowdSec.

```bash
sudo -u nazar nazar run --dry-run --once
sudo systemctl start nazar
journalctl -u nazar -f
```

Each report line shows the verdict and what active mode **would** do (`would=auto`,
`would=approval`, …). Review a few days of incidents:

```bash
sudo nazar incidents --since 3d
sudo nazar explain inc_2026_10_25_0001
sudo nazar report --since 3d
```

## 6. Go active

When the dry-run results look right, set `mode: active` and restart:

```bash
sudo systemctl restart nazar
```

Every ban Nazar creates is visible in `sudo cscli decisions list` with the reason
`nazar/ai-triage`, and can be removed at any time:

```bash
sudo nazar rollback --since 1h
```

## Optional: Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather) and add it to a private chat or group.
2. Put the token in `/etc/nazar/secrets.env` as `NAZAR_TG_TOKEN=...`.
3. In `config.yaml`, set `notifier.telegram.enabled: true`, the `chat_id` and, for groups,
   `allowed_user_ids`.
4. `sudo nazar config check && sudo systemctl restart nazar`.

## Optional: CrowdSec CTI and GeoIP

- CTI: get a key from the CrowdSec console, add `NAZAR_CTI_KEY=...` to `secrets.env` and set
  `crowdsec.cti_api_key_env: NAZAR_CTI_KEY`.
- GeoIP: `sudo /opt/nazar/venv/bin/pip install 'nazar-sec[geoip]'`, download the GeoLite2 Country
  and ASN databases from MaxMind (free account) and set `enrich.geoip_country_db` and
  `enrich.geoip_asn_db`.

## Uninstall

```bash
sudo systemctl disable --now nazar
sudo nazar rollback --since 30d --yes      # remove Nazar's decisions first, if any
sudo cscli machines delete nazar
sudo rm -rf /opt/nazar /usr/local/bin/nazar /etc/nazar /var/lib/nazar \
  /etc/systemd/system/nazar.service
sudo userdel nazar
```
