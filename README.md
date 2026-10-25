# Nazar

**AI-assisted protection for Linux servers, built on CrowdSec.**

> *Nazar* is the Turkish name for the blue evil-eye charm that has watched over doorways for centuries. This project is a modern nazar for your servers: it watches, recognizes the evil eye, and wards it off.

> **Status: pre-alpha.** v1 features (triage, policy, CrowdSec decisions, Telegram approvals) are
> implemented and tested against recorded API responses; validation on live CrowdSec installs is in
> progress. Run it in dry-run mode first. See [DESIGN.md](DESIGN.md) and [TRACKER.md](TRACKER.md).

---

## What is Nazar?

Nazar adds a small, local AI analyst to [CrowdSec](https://www.crowdsec.net/).

- **CrowdSec is the enforcer.** It parses logs, detects attacks with scenarios and WAF rules, and blocks attackers through bouncers (nftables, nginx, Cloudflare, …).
- **Nazar is the analyst.** It reviews CrowdSec alerts, adds context, correlates weak signals, explains what is happening in plain language, and proposes or applies **bounded, reversible** actions through CrowdSec.

The model runs **entirely on your server**. Nazar needs no GPU and no cloud LLM, and your logs never leave the machine.

```
 logs ──► CrowdSec (detect) ──► Nazar (triage + decide) ──► CrowdSec decisions ──► bouncers (block)
                                    │
                                    └──► you (alerts, approvals, daily report)
```

## Why?

| Problem | What Nazar does |
|---|---|
| Hundreds of alerts, little context | Groups, enriches and ranks them, so you read incidents instead of noise |
| Rules can't see the bigger picture | Correlates events over time (e.g. scan → login attempt → odd request) |
| "What does this alert mean?" | Plain-language explanation mapped to MITRE ATT&CK |
| AI tools that act without limits | A strict policy engine: the model proposes, deterministic rules decide |
| Sending logs to a cloud AI | Fully local small language model, works on CPU |

## Features

### v1: AI triage (implemented, in validation)
- Reads alerts from the CrowdSec Local API
- Enrichment: CrowdSec CTI reputation, GeoIP/ASN, local history for the IP
- Local triage with a small, non-reasoning model ([IBM Granite 4.0 Micro-H](https://ollama.com/library/granite4), 3B, Q4_K_M, Apache-2.0) through [Ollama](https://ollama.com): 21/22 on Nazar's labelled incidents, ~50 s per incident on 2 vCPU ([model comparison](docs/models.md))
- Policy engine with allow-lists, a maximum ban duration and approval tiers
- Actions applied as CrowdSec decisions, tagged and auditable
- Telegram notifications with **Approve / Reject** buttons
- Daily security summary
- Dry-run mode (default) to evaluate Nazar before letting it act

### v2: Nazar Radar, threat news to action (planned)
- Watches trusted sources (CISA KEV, NVD, vendor advisories, CERT feeds)
- Extracts CVEs, affected products and fixed versions
- Matches them against **your installed software**
- Responds in tiers: refreshes CrowdSec virtual-patching rules automatically and raises patching for your approval

## Safety principles

Nazar is a security tool, so it must not become an attack surface.

1. **The model never runs commands.** It can only pick from a fixed, validated list of actions.
2. **Logs and news are untrusted input.** Attackers control user agents, usernames and URLs, so everything the model reads is treated as data, never as instructions.
3. **Allow-lists always win.** Your own IPs, private ranges and monitoring systems are never blocked.
4. **Everything is bounded and reversible.** Bans have a maximum duration and can be rolled back in one command.
5. **Fail safe.** If the model is down or returns invalid output, CrowdSec keeps protecting you as before.

## Requirements

- Linux (Debian/Ubuntu or RHEL family), x86_64 or arm64
- [CrowdSec](https://docs.crowdsec.net/) Security Engine with at least one bouncer
- [Ollama](https://ollama.com)
- Python 3.11+
- 4 GB RAM or more (the model needs about 2.5 GB; see [docs/models.md](docs/models.md) for tight hosts)

## Quick start

```bash
# 1. Install CrowdSec and a bouncer (see the CrowdSec docs), and Ollama
# 2. Pull the model
ollama pull granite4:micro-h
# 3. Install Nazar (creates the nazar user, config, secrets, CrowdSec machine, systemd unit)
git clone https://github.com/krugis/nazar-sec-nazar && cd nazar-sec-nazar
sudo sh deploy/install.sh --from .
# 4. Add your own IPs to policy.allowlist_cidrs, then check
sudo nano /etc/nazar/config.yaml && sudo nazar config check
# 5. Dry run first: triage and report, no changes to CrowdSec
sudo -u nazar nazar run --dry-run --once
sudo systemctl start nazar
```

Day-to-day commands:

| Command | What it does |
|---|---|
| `nazar status` | health of LAPI, Ollama and the model |
| `nazar incidents --since 24h` | incidents with verdicts and outcomes |
| `nazar explain <incident>` | the full trail: events, enrichment, verdict, policy reasons, actions |
| `nazar approve <id>` / `nazar reject <id>` | answer an approval request |
| `nazar rollback --since 1h` | remove decisions Nazar created |
| `nazar report` | the summary of the last 24 hours |
| `nazar test-model` | evaluate the model on labelled incidents |

Documentation: [install](docs/install.md) · [configuration](docs/configuration.md) ·
[safety model](docs/safety.md) · [FAQ](docs/faq.md) · [low-level design](docs/lld/README.md)

## Roadmap

- [x] v0.1: alert ingestion, triage, dry-run reports (live validation pending)
- [x] v0.2: policy engine and CrowdSec decisions (live validation pending)
- [x] v0.3: Telegram approvals and daily summary
- [ ] v0.4: packaging (install script and docs done; PyPI release, .deb, Docker image)
- [ ] v1.0: stable v1
- [ ] v2: Nazar Radar (news-driven response)

## Development

The low-level design is in [docs/lld/](docs/lld/README.md) and progress is tracked in
[TRACKER.md](TRACKER.md).

```bash
uv venv -p 3.12 && uv pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

Try it against a local CrowdSec and Ollama without changing anything:

```bash
nazar --config examples/config.yaml config check
nazar --config examples/config.yaml run --dry-run --once
```

## Contributing

Contributions are welcome once the first release is out. All contributors will be asked to sign a Contributor License Agreement (CLA).

## License

Licensed under the [Apache License 2.0](LICENSE).

"Nazar" and the Nazar logo are trademarks of the project owner. The Apache license does not grant rights to use them.

CrowdSec is a trademark of CrowdSec SAS. Nazar is an independent project and is not affiliated with or endorsed by CrowdSec.
