#!/usr/bin/env bash
set -euo pipefail
umask 077

cd "$(dirname "$0")/.."
if [[ ! -f .env ]]; then
  echo ".env was not found in $(pwd)" >&2
  exit 1
fi

get_env_value() {
  local key="$1"
  local line
  line="$(grep -m1 "^${key}=" .env || true)"
  printf '%s' "${line#*=}"
}

current_enabled="$(get_env_value TELEGRAM_ENABLED)"
current_token="$(get_env_value TELEGRAM_BOT_TOKEN)"
current_chat_id="$(get_env_value TELEGRAM_CHAT_ID)"
current_allowed_ids="$(get_env_value TELEGRAM_ALLOWED_USER_IDS)"
current_proxy_url="$(get_env_value TELEGRAM_PROXY_URL)"
current_poll="$(get_env_value TELEGRAM_LONG_POLL_SECONDS)"
current_ttl="$(get_env_value TELEGRAM_ACTION_TTL_MINUTES)"

current_enabled="${current_enabled:-false}"
current_poll="${current_poll:-25}"
current_ttl="${current_ttl:-60}"

echo "Current Telegram configuration:"
echo "  Enabled: $current_enabled"
echo "  Bot token: $([[ -n "$current_token" ]] && echo configured || echo missing)"
echo "  Chat ID: ${current_chat_id:-missing}"
echo "  Allowed user IDs: ${current_allowed_ids:-missing}"
echo "  Connection: $([[ -n "$current_proxy_url" ]] && echo proxy || echo direct)"
echo "  Long poll: ${current_poll}s"
echo "  Action TTL: ${current_ttl}m"
echo

read -r -p "Enable Telegram [true/false, blank keeps $current_enabled]: " enabled
read -r -s -p "Bot token [blank keeps current]: " bot_token
printf '\n'
read -r -p "Chat ID [blank keeps ${current_chat_id:-current}]: " chat_id
read -r -p "Allowed user IDs, comma-separated [blank keeps current]: " allowed_ids
read -r -s -p "Proxy URL [blank keeps current, DIRECT clears it]: " proxy_url
printf '\n'
read -r -p "Long poll seconds [blank keeps $current_poll]: " poll_seconds
read -r -p "Quarantine button TTL minutes [blank keeps $current_ttl]: " ttl_minutes

enabled="${enabled:-$current_enabled}"
bot_token="${bot_token:-$current_token}"
chat_id="${chat_id:-$current_chat_id}"
allowed_ids="${allowed_ids:-$current_allowed_ids}"
poll_seconds="${poll_seconds:-$current_poll}"
ttl_minutes="${ttl_minutes:-$current_ttl}"

if [[ "${proxy_url^^}" == "DIRECT" ]]; then
  proxy_url=""
elif [[ -z "$proxy_url" ]]; then
  proxy_url="$current_proxy_url"
fi

if [[ ! "$enabled" =~ ^(true|false)$ ]]; then
  echo "Enabled must be true or false." >&2
  exit 1
fi
if [[ "$enabled" == "true" && ! "$bot_token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
  echo "A valid Telegram bot token is required when Telegram is enabled." >&2
  exit 1
fi
if [[ "$enabled" == "true" && ! "$chat_id" =~ ^-?[0-9]+$ ]]; then
  echo "CHAT_ID must be numeric (group chat IDs can be negative)." >&2
  exit 1
fi
if [[ "$enabled" == "true" && ! "$allowed_ids" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  echo "Allowed user IDs must be comma-separated positive integers." >&2
  exit 1
fi
if [[ -n "$proxy_url" && ! "$proxy_url" =~ ^(http|https|socks5|socks5h):// ]]; then
  echo "Proxy URL must start with http://, https://, socks5:// or socks5h://." >&2
  exit 1
fi
if [[ ! "$poll_seconds" =~ ^[0-9]+$ || "$poll_seconds" -lt 5 || "$poll_seconds" -gt 50 ]]; then
  echo "Long poll seconds must be between 5 and 50." >&2
  exit 1
fi
if [[ ! "$ttl_minutes" =~ ^[0-9]+$ || "$ttl_minutes" -lt 5 || "$ttl_minutes" -gt 1440 ]]; then
  echo "Action TTL must be between 5 and 1440 minutes." >&2
  exit 1
fi

backup=".env.before-telegram-$(date +%Y%m%d-%H%M%S)"
cp .env "$backup"
chmod 600 "$backup"

upsert_env() {
  local key="$1"
  local value="$2"
  local temporary
  temporary="$(mktemp)"
  local found=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "${key}="* ]]; then
      printf '%s=%s\n' "$key" "$value" >> "$temporary"
      found=1
    else
      printf '%s\n' "$line" >> "$temporary"
    fi
  done < .env
  if [[ "$found" -eq 0 ]]; then
    printf '%s=%s\n' "$key" "$value" >> "$temporary"
  fi
  chmod 600 "$temporary"
  mv "$temporary" .env
}

upsert_env TELEGRAM_ENABLED "$enabled"
upsert_env TELEGRAM_BOT_TOKEN "$bot_token"
upsert_env TELEGRAM_CHAT_ID "$chat_id"
upsert_env TELEGRAM_ALLOWED_USER_IDS "$allowed_ids"
upsert_env TELEGRAM_PROXY_URL "$proxy_url"
upsert_env TELEGRAM_LONG_POLL_SECONDS "$poll_seconds"
upsert_env TELEGRAM_ACTION_TTL_MINUTES "$ttl_minutes"

unset bot_token proxy_url current_token current_proxy_url
chmod 600 .env
echo "Telegram settings saved. Backup: $backup"
echo "Apply without rebuilding: docker compose up -d --force-recreate web"
