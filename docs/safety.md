# Safety model

Nazar is a security tool, so it must not become an attack surface or a way to hurt the server it
protects. This page explains how the design keeps that promise. The full threat model is in
[DESIGN.md §5](../DESIGN.md#5-security-design).

## The model proposes, the policy decides, CrowdSec enforces

- The model can only fill in a fixed JSON form (verdict, severity, confidence, summary, one of
  `none`, `notify`, `ban`, `captcha`, and a duration). Anything else fails validation and becomes
  `unknown`, which means no action.
- The model never chooses **what** to ban. The target is always the source IP of the incident,
  taken from CrowdSec, and never from model text.
- A deterministic policy engine turns the verdict into a decision. It has no network, file or
  clock access and is tested with every combination of inputs.
- The only thing Nazar can do to the system is create or remove its own CrowdSec decisions,
  through the CrowdSec API. There is no shell, file or network action. The optional `cscli`
  fallback builds its arguments only from validated values and never runs a shell.

## Logs are untrusted

Attackers control user agents, usernames, URLs and paths. Nazar:

- strips control characters, ANSI escapes and Unicode direction/zero-width characters at the
  point alerts come in, and truncates lines,
- puts incident data inside a single `<data>` block as JSON in which `<`, `>` and `&` are escaped,
  so attacker text can never close the block or open a `<think>` section,
- tells the model that everything in the block is data, never instructions,
- discards the model's reasoning text and validates the answer against a strict schema,
- renders notifications with fixed plain-text templates (no Markdown/HTML), so model text cannot
  add links, buttons or fake headers.

A test suite feeds a corpus of injection payloads through the whole path
(`tests/security/test_prompt_injection.py`).

## Allow-lists always win

Loopback, private ranges (RFC 1918), link-local, CGNAT, unique-local IPv6 and the host's own
addresses are always protected and cannot be removed. Your `policy.allowlist_cidrs` and,
optionally, CrowdSec's allow-lists are added. The allow-list is checked by the pre-filter, again by
the policy engine, again by the actuator right before calling CrowdSec, and again when a human
approves.

## Bounded and reversible

- Bans last at most `policy.max_ban_duration` (default 24h). Range bans are never produced.
- One alert plus the model's opinion is never enough for an automatic ban: it needs an independent
  signal (CTI reputation, several scenarios, or history), otherwise a human approves.
- At most `max_auto_actions_per_hour` automatic actions; above that, everything needs approval
  and you get a warning.
- Each decision is created at most once per incident, and never again after you roll it back.
- `nazar rollback` removes Nazar's decisions by incident, by time window or one by one. Nazar
  never removes decisions it did not create.
- Everything is recorded in an append-only audit log (`nazar explain <incident>`).

## Human approvals

- Telegram buttons carry HMAC-signed data with an expiry. Only the configured chat (and, if set,
  the allowed users) can use them. Forged, expired, replayed or foreign clicks are rejected and
  audited.
- At click time the policy engine runs again on the current state. If the IP was allow-listed in
  the meantime, or CrowdSec already bans it, the approval is refused.
- An approval that nobody answers expires and nothing happens.

## Fail safe

If Ollama is down, the model answers garbage, CTI fails or Nazar crashes, CrowdSec keeps
protecting the server exactly as before. Nazar never touches CrowdSec on an error path. It starts in
dry-run mode and only acts after you switch it to active.

## Least privilege

Nazar runs as the unprivileged `nazar` user under a hardened systemd unit (no new privileges,
read-only system, private /tmp, no capabilities, restricted system calls, write access to
`/var/lib/nazar` only). Its only CrowdSec access is its own machine account. Secrets live in a
0600 file and are redacted from logs.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting on the repository
(Security tab → "Report a vulnerability") or contact the maintainer privately, with details and,
if possible, a reproduction.
