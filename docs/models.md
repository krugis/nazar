# Models

Nazar works with any Ollama model that follows a JSON schema (`analyst.model`). This page records
which models were tested, how, and why the default was chosen. Re-run the comparison for your own
hardware with `nazar test-model`.

## Default: IBM Granite 4.0 Micro-H

```bash
ollama pull granite4:micro-h
```

| | |
|---|---|
| Size | 3.2B parameters, Q4_K_M, 1.9 GB download, ~2.5 GB RAM at `num_ctx: 4096` |
| Type | general instruction model, **no reasoning step**, hybrid Mamba/transformer |
| Licence | Apache-2.0 |
| Accuracy | **21/22** verdict and action on Nazar's labelled incidents; 0% invalid output |
| Speed | ~50 s median, ~71 s p95 per incident on 2 vCPU (no GPU) |

The one miss: a multi-scenario attack rated `suspicious → notify` instead of `malicious → ban`,
the cautious direction.

## How the models were tested

- Host: Debian 11, 2 vCPU, no GPU, Ollama 0.40.11, Ollama capped at 2.4 GB RAM (shared server).
- `nazar test-model` on the 22 labelled incidents in `nazar/data/eval_incidents.jsonl`, including
  two prompt-injection cases; plus single-incident probes. October 2026.

| Model | Size | Result | Verdict |
|---|---|---|---|
| `granite4:micro-h` (IBM Granite 4.0 Micro-H, 3B) | 1.9 GB | 21/22 correct, 0% invalid, ~50 s | **default** |
| `hf.co/Nguuma/security-slm-unsloth-1.5b` (security fine-tune of a 1.5B reasoning model) | 1.2 GB | Always reasons first and ignores `think: false`; reasoning length varied from ~300 to >2000 tokens, so 2 of 3 runs hit the 2048-token limit with no answer (up to 193 s). When it answered, verdicts were plausible. | rejected: unreliable on CPU |
| `hf.co/ferhatcil/Cybersecurity-LLM-Qwen2.5-3B-GGUF:Q4_K_M` (security fine-tune of Qwen2.5-3B) | 1.9 GB | Valid JSON, 26–56 s, but rated every probe incident `malicious` at confidence 1.0, including Googlebot. | rejected: uncalibrated |

Larger security models (Cisco Foundation-Sec-8B, Seneca 8B, Dolphin3-Cyber 8B) need ~5 GB RAM
and were not tested yet. On a host with 8 GB RAM, Foundation-Sec-8B-Instruct, Qwen3-4B-Instruct-2507
(`qwen3:4b-instruct`), Phi-4-mini and Gemma 3 4B are the next candidates (TRACKER V-3).

## Lessons for choosing a model

- **Prefer non-reasoning models.** Ollama's `num_predict` budget covers reasoning *and* answer, and
  reasoning length is unpredictable on CPU. Nazar sends `think: false` to models with the thinking
  capability, but some models reason anyway.
- **Judge calibration, not only JSON validity.** Schema-constrained output makes almost any model
  produce valid JSON; the difference is whether the verdict and confidence are sensible.
- **Small hosts:** if Ollama is memory-limited, lower `analyst.num_ctx` (2048 is enough for Nazar's
  prompts of ~850 tokens plus the answer). A model that exceeds its memory limit is killed and
  restarted by systemd; triage falls back to `unknown` (no action) meanwhile.
- **Licences matter** if you build on Nazar commercially: Granite and Qwen 2.5 1.5B are Apache-2.0,
  Qwen 2.5 3B is under a non-commercial research licence, Llama has a community licence.
