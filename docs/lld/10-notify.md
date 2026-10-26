# 10: Notifier (`nazar.notify`)

Tells the operator what happened and collects approvals (DESIGN §3.7).

## Files

| File | Contents |
|---|---|
| `messages.py` | notification types (`Note`), plain-text `render`, `buttons` |
| `base.py` | `Notifier` and `InteractiveNotifier` protocols, `UserAction`, `FanoutNotifier` |
| `log_notifier.py` | writes notifications to the log (always on) |
| `telegram.py` | `TelegramNotifier` (Bot API over `httpx`, long polling) |
| `callbacks.py` | signing and verification of button data |
| `health.py` | `HealthMonitor`: notify on state changes, repeat every 15 min while down |
| `summary.py` | daily summary builder (from store queries) and renderer |
| `nazar/approvals.py` | `ApprovalService` (top level, next to `pipeline.py`: it wires policy, actuator and notifier, which stage packages may not import) |

## Interfaces

```python
class Notifier(Protocol):
    async def send(self, n: Notification) -> str | None     # message ref, if any

class InteractiveNotifier(Notifier, Protocol):
    async def poll_actions(self) -> list[UserAction]        # verified button clicks
    async def mark_resolved(self, message_ref: str, text: str) -> None
```

`Note` is a union of pydantic models, each with a `kind`:

| Model (`kind`) | Sent when | Buttons |
|---|---|---|
| `AutoActionNote` (`auto_action`) | an automatic ban/captcha was applied | Rollback (valid for `max_ban_duration`) |
| `ApprovalNote` (`approval`) | the policy asks for approval | Approve, Reject (valid until the approval expires) |
| `IncidentNote` (`incident`) | an auto `notify` action, or a `report_only` incident with severity ≥ high | — |
| `TextNote` (`daily_summary`, `report`) | daily summary, `nazar report --send` | — |
| `HealthNote` (`health`) | component (`lapi`, `ollama`, `model`, `model_output`, `cti`, `telegram`, `volume`) changes state | — |

Rendering is plain text with fixed templates (no Markdown/HTML parse mode), so untrusted text
(summaries come from the model, which read attacker data) cannot inject formatting or links.
Model text is capped (summary 400, reasons 3 × 200).

`FanoutNotifier` sends to every enabled notifier; a failure in one is logged and does not affect the
others. Failed sends retry with backoff (3 tries) then are dropped with an error log.

## Telegram

- `sendMessage` to `chat_id` with `reply_markup.inline_keyboard`; `editMessageReplyMarkup` +
  `editMessageText` once resolved or expired; `answerCallbackQuery` on every click.
- `getUpdates` long polling (`timeout=30`, `allowed_updates=["callback_query"]`), offset stored in
  `kv["tg.offset"]`. No inbound port.
- Token from `bot_token_env`; the URL contains the token, so HTTP errors are logged without URLs.

### Callback security

`callback_data` (≤ 64 bytes): `n1|<op>|<ref>|<exp>|<sig>`
- `op`: `a` approve, `r` reject, `b` rollback; `ref`: approval ID or decision ID; `exp`: unix time.
- `sig = base64url(HMAC-SHA256(NAZAR_HMAC_KEY, "n1|op|ref|exp"))[:16]` (96 bits).

A click is accepted only if **all** hold, otherwise it is rejected, answered with "not allowed" and
audit-logged (`callback_rejected`, reason):
1. `callback_query.message.chat.id == chat_id`, and, when `telegram.allowed_user_ids` is set
   (recommended for group chats), `callback_query.from.id` is in it.
2. Signature valid (`hmac.compare_digest`), version `n1`.
3. Not expired (`exp` and, for approvals, `approvals.expires_at`).
4. For approve: `ApprovalService.approve` re-runs the policy engine (`approved_by="user:<tg id>"`,
   R10) on current state (allow-list, mode, CrowdSec status) and the actuator applies only an `auto`
   result. For rollback: the decision must be Nazar's and applied.

## ApprovalService

```python
async def request(self, incident, verdict, decision, decision_id) -> str  # row + message
async def approve(self, approval_id: str, by: str) -> ApprovalResult
async def reject(self, approval_id: str, by: str) -> ApprovalResult
async def expire_due(self) -> int                                         # every minute (11)
async def handle(self, action: UserAction) -> None                        # verified clicks
```

`approve` re-runs the policy engine with `approved_by` (R10) on the incident snapshot stored with
the verdict, refreshed with the current CrowdSec ban state, the current allow-list and mode.
Only an `auto` enforcing result is applied, as a **new decision row** (its reasons include the R10
line) through the actuator. Any other result resolves the approval as rejected by
`policy:<user>` and returns `refused` with the policy's reasons (CLI exit code 3).
Outcomes: `approved`, `rejected`, `refused`, `expired`, `not_pending` (replay or race),
`not_found`. `resolve` is atomic and single-shot (03). Expired means no action; the message is
edited to say so.

## Daily summary

At `daily_summary_time` in `timezone` (the daemon checks once a minute, `kv["summary.last_sent"]`
prevents doubles): incidents, verdict counts, decisions by outcome, applied/rolled back, approvals
pending/expired, top 5 incidents by severity, model invalid-output rate (bad answers) and,
separately, incidents not triaged because the model was unavailable, health events. Same text as
`nazar report --daily`.

## Tests

Signed data round-trip; forged signature, wrong chat, expired, replayed (already resolved) all
rejected; approve re-runs policy (allow-listed after the request → refused); message rendering keeps
untrusted text plain; respx Telegram fixtures.
