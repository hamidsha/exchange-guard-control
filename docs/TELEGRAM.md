# Telegram and proxy setup

Telegram integration can send critical outbound alerts, show current top senders and provide expiring action buttons. It is optional and disabled by default.

## 1. Create a bot

1. Open a conversation with Telegram BotFather.
2. Create a bot and copy the token.
3. Add the bot to the intended private chat or administrator group.
4. Send `/start` or another message in that chat.

Treat the token as a password. Never put it in Git, command output, screenshots or issue reports.

## 2. Discover numeric IDs

Run the included interactive helper on the Linux control-plane host:

```bash
chmod +x scripts/discover-telegram-ids.sh
./scripts/discover-telegram-ids.sh
```

It prompts without echoing the token or proxy. If it reports no update, send another message to the bot and rerun it.

The output contains:

- `USER_ID`: the administrator permitted to press action buttons.
- `CHAT_ID`: the private or group chat receiving alerts.

Group chat IDs are often negative. User IDs are positive.

## 3. Configure direct or proxy access

Use the interactive configuration helper:

```bash
chmod +x scripts/configure-telegram.sh
./scripts/configure-telegram.sh
```

Supported explicit proxy URL forms:

```text
http://proxy.example.internal:3128
http://username:password@proxy.example.internal:3128
socks5://proxy.example.internal:1080
socks5h://username:password@proxy.example.internal:1080
```

`socks5h` asks the proxy to resolve DNS. Restrict the `.env` file to root because credentials embedded in a proxy URL are secrets.

The resulting settings look like:

```dotenv
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=replace-with-bot-token
TELEGRAM_CHAT_ID=-1000000000000
TELEGRAM_ALLOWED_USER_IDS=100000001,100000002
TELEGRAM_PROXY_URL=http://proxy.example.internal:3128
TELEGRAM_LONG_POLL_SECONDS=25
TELEGRAM_ACTION_TTL_MINUTES=60
```

Apply without rebuilding:

```bash
docker compose up -d --no-deps --force-recreate web
docker compose logs --tail=100 web
```

## 4. Test

Use the Telegram test action on the Outbound page. Confirm the message appears in the configured chat.

Useful bot requests include the command/menu action for current top outbound senders. Only the exact configured chat and allowed numeric user IDs may invoke response actions.

## 5. Action-button behavior

- Alert action tokens are random, single-use and expire after `TELEGRAM_ACTION_TTL_MINUTES`.
- Telegram callback data does not contain an email address or PowerShell command.
- Pressing quarantine queues the same controlled incident workflow used by the web UI.
- Repeated or expired presses receive an explicit status instead of replaying an action.
- Bulk/expected sender profiles are excluded from critical alert noise but remain visible in the web data.
- Every accepted or rejected operator action is represented in the application audit/command history where applicable.

## 6. Security recommendations

- Use a private chat or tightly controlled administrator group.
- Set `TELEGRAM_ALLOWED_USER_IDS`; never authorize by display name or username.
- Do not expose the bot token in shell history. Prefer the included prompts.
- Restrict outbound firewall access to Telegram and the explicit proxy.
- Rotate the bot token immediately if `.env` or a backup is exposed.
- Telegram is a response convenience, not a replacement for the web audit trail or incident procedure.

## 7. Troubleshooting

Check effective container settings without printing secrets:

```bash
docker compose exec -T web python - <<'PY'
from app.config import settings

print({
    'enabled': settings.telegram_enabled,
    'token_configured': bool(settings.telegram_bot_token),
    'chat_configured': bool(settings.telegram_chat_id),
    'allowed_user_ids_configured': bool(settings.telegram_allowed_user_ids),
    'proxy_configured': bool(settings.telegram_proxy_url),
    'long_poll_seconds': settings.telegram_long_poll_seconds,
    'action_ttl_minutes': settings.telegram_action_ttl_minutes,
})
PY
```

Then inspect recent logs:

```bash
docker compose logs --since=30m web
```

If the host has no direct Internet access, test the proxy separately without printing credentials and verify that DNS resolution works for `api.telegram.org` through the chosen proxy mode.

