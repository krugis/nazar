# End-to-end test

A disposable stack with CrowdSec, Ollama and Nazar. `run.sh` replays SSH and HTTP attack logs
(including a prompt-injection attempt in a user agent, and the same attack from an allow-listed
range), runs Nazar against the real LAPI and model, and checks properties that must hold whatever
the model answers:

1. a dry run makes no CrowdSec changes,
2. every incident gets a verdict,
3. in active mode the allow-listed IP is never banned by Nazar,
4. `nazar rollback` removes every decision Nazar created.

```bash
cd deploy/e2e
./run.sh                       # tears the stack down afterwards
KEEP=1 ./run.sh                # keep it for inspection (docker compose down -v to remove)
CROWDSEC_IMAGE=crowdsecurity/crowdsec:v1.6.8 OLLAMA_IMAGE=ollama/ollama:0.12.6 ./run.sh
```

Needs Docker with the compose plugin, about 3 GB of disk (images and the model) and a few minutes.
It is not part of the normal CI run because of the model size.
