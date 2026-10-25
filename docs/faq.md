# FAQ

**Does Nazar replace CrowdSec?**
No. CrowdSec detects and enforces. Nazar adds triage on top: it groups alerts into incidents,
explains them, and creates extra, bounded CrowdSec decisions when the evidence is strong. If Nazar
stops, CrowdSec works exactly as before.

**Do my logs leave the server?**
No. The model runs locally in Ollama. The only optional outbound calls are the CrowdSec CTI API
(which receives the attacker's IP, not your logs) and Telegram (which receives the notification
text).

**Do I need a GPU?**
No. The default model is a 1.5B-parameter model quantized to about 1.2 GB and runs on CPU. Triage
of one incident takes seconds to tens of seconds; Nazar groups alerts so it calls the model far
less often than CrowdSec raises alerts, and rate-limits calls (`analyst.max_calls_per_minute`).

**Can I use another model?**
Yes: any Ollama model that can follow a JSON schema. Set `analyst.model` and compare models with
`nazar test-model`, which reports accuracy, invalid-output rate and latency on a labelled set.

**What if the model is wrong?**
The policy engine limits the damage: no action on allow-listed or private addresses, bans need an
independent signal to be automatic, durations are capped, there is an hourly budget, and
everything can be rolled back. Start in dry-run mode and review `nazar incidents` before going
active.

**Could an attacker trick Nazar into banning my own IPs?**
Your allow-listed and private addresses can never be banned. For others, an attacker would need to
make traffic look like it comes from that IP and also pass the corroboration rule. See
[safety.md](safety.md).

**Why did Nazar not ban an IP that looks malicious?**
Run `nazar explain <incident>`. The policy reasons show why: for example it was allow-listed,
CrowdSec already banned it, confidence was below the threshold, or it needed approval because only
one scenario fired and CTI had no data.

**How do I undo everything Nazar did today?**
`sudo nazar rollback --since 24h`.

**Where are the logs?**
`journalctl -u nazar`. They are JSON lines; use `--log-format text` on the command line for
human-readable output.

**Why does the daily summary not arrive on the first day?**
If Nazar starts after `daily_summary_time`, the first summary is sent the next day.

**Is there a web dashboard?**
Not in the open-source core. Use the CLI, Telegram and the daily summary.
