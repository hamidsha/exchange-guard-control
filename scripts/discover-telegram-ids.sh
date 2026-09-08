#!/usr/bin/env bash
set -euo pipefail
umask 077

read -r -s -p "Telegram bot token: " bot_token
printf '\n'
read -r -s -p "Proxy URL (blank for direct connection): " proxy_url
printf '\n'

if [[ ! "$bot_token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
  echo "Invalid Telegram bot token format." >&2
  exit 1
fi
if [[ -n "$proxy_url" && ! "$proxy_url" =~ ^(http|https|socks5|socks5h):// ]]; then
  echo "Proxy URL must start with http://, https://, socks5:// or socks5h://." >&2
  exit 1
fi

response_file="$(mktemp)"
curl_config="$(mktemp)"
trap 'rm -f "$response_file" "$curl_config"' EXIT

escaped_proxy="${proxy_url//\\/\\\\}"
escaped_proxy="${escaped_proxy//\"/\\\"}"

{
  printf 'url = "https://api.telegram.org/bot%s/getUpdates?timeout=0"\n' "$bot_token"
  printf 'request = "GET"\n'
  printf 'connect-timeout = 10\n'
  printf 'max-time = 20\n'
  if [[ -n "$escaped_proxy" ]]; then
    printf 'proxy = "%s"\n' "$escaped_proxy"
  fi
} > "$curl_config"
chmod 600 "$curl_config"

curl --silent --show-error --fail --config "$curl_config" > "$response_file"
unset bot_token proxy_url escaped_proxy

python3 - "$response_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    body = json.load(handle)

updates = body.get("result") or []
rows = []
for update in updates:
    message = update.get("message") or update.get("channel_post") or {}
    sender = message.get("from") or {}
    chat = message.get("chat") or {}
    if sender.get("id") is not None and chat.get("id") is not None:
        rows.append((sender.get("id"), chat.get("id"), sender.get("username") or "-", chat.get("type") or "-"))

if not rows:
    print("No message update found. Open the bot, send /start, then run this script again.")
    raise SystemExit(2)

print("\nLatest Telegram identity:")
print("USER_ID={}".format(rows[-1][0]))
print("CHAT_ID={}".format(rows[-1][1]))
print("USERNAME={}".format(rows[-1][2]))
print("CHAT_TYPE={}".format(rows[-1][3]))
PY
