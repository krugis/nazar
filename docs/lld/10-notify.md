# 10: Notifier (`nazar.notify`)

Tells the operator what happened and collects approvals (DESIGN §3.7).

## Files

| File | Contents |
|---|---|
| `messages.py` | `Notification` types and plain-text rendering |
| `base.py` | `Notifier` and `InteractiveNotifier` protocols, `FanoutNotifier` |
| `log_notifier.py` | writes notifications to the log (always on) |
| `telegram.py` | `TelegramNotifier` (Bot API over `httpx`, long polling) |
| `callbacks.py` | signing and verification of button data |
| `approvals.py` | `ApprovalService`: create, resolve, expire (shared by Telegram and CLI) |
| `summary.py` | daily summary builder (pure, from store queries) |

## Interfaces

```python
class Notifier(Protocol):
    async def send(self, n: Notification) -> str | None     # message ref, if any

class InteractiveNotifier(Notifier, Protocol):
    async def poll_actions(self) -> list[UserAction]        # verified button clicks
    async def mark_resolved(self, message_ref: str, text: str) -> None
```

`Notification` is a tagged union (pydantic, `kind` field):

| kind | Fields | Buttons |
|---|---|---|
| `auto_action` | incident, decision, verdict summary, decision_id | Rollback |
| `approval` | incident, decision, verdict summary, approval_id, expires_at | Approve, Reject |
| `report` | dry-run cycle report or bulk-summary line | — |
| `daily_summary` | counts and top incidents | — |
| `health` | component (`lapi`, `ollama`, `model_output`, `cti`, `volume`), state, detail | — |

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
async def request(self, decision_id: int) -> Approval           # creates row + sends message
async def approve(self, approval_id: str, by: str) -> ApprovalResult
async def reject(self, approval_id: str, by: str) -> ApprovalResult
async def expire_due(self) -> int                               # called every minute (11)
```

`resolve` is atomic and single-shot (03). Expired means no action; the message is edited to say so.

## Daily summary

At `daily_summary_time` in `timezone` (the daemon checks once a minute, `kv["summary.last_sent"]`
prevents doubles): incidents, verdict counts, decisions by outcome, applied/rolled back, approvals
pending/expired, top 5 incidents by severity, model invalid-output rate, health events. Same text as
`nazar report --daily`.

## Tests

Signed data round-trip; forged signature, wrong chat, expired, replayed (already resolved) all
rejected; approve re-runs policy (allow-listed after the request → refused); message rendering keeps
untrusted text plain; respx Telegram fixtures.
