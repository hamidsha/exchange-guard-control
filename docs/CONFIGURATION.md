# Configuration reference

Runtime settings are read from `.env` when the web container starts. After changing `.env`, apply the change with:

```bash
docker compose up -d --no-deps --force-recreate web
```

Never commit `.env`.

## Core settings

| Variable | Purpose | Safe starting value |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy connection to the internal PostgreSQL service | Generated automatically |
| `SESSION_SECRET` | Signs browser sessions | Random value from `generate-env.sh` |
| `ADMIN_USERNAME` | Initial administrator name | `admin` |
| `ADMIN_PASSWORD` | Initial administrator password | Generated automatically |
| `BOOTSTRAP_NODE_ID` | Edge agent identity | `edge-01` |
| `BOOTSTRAP_NODE_SECRET` | Edge HMAC secret | Generated automatically |
| `MAILBOX_NODE_ID` | Mailbox agent identity | `mailbox-01` |
| `MAILBOX_NODE_SECRET` | Mailbox HMAC secret | Generated automatically |
| `BLOCKED_OUTBOUND_GROUP` | Existing mail-enabled security-group SMTP address | Organization-specific |
| `BIND_ADDRESS` | Host address publishing the container port | `127.0.0.1` |
| `WEB_PORT` | Host port | `8787` |
| `TRUSTED_HOSTS` | Comma-separated accepted HTTP Host names | Explicit internal names only |
| `SECURE_COOKIES` | Marks session cookies Secure | `true` behind HTTPS |
| `COMMAND_TTL_MINUTES` | Pending agent-command lifetime | `60` |

`ADMIN_PASSWORD` does not overwrite an existing database user. It is used only during first initialization.

## Organization and outbound settings

| Variable | Meaning |
|---|---|
| `ORGANIZATION_DOMAINS` | Comma-separated Accepted Domains owned by the organization |
| `OUTBOUND_MONITOR_ENABLED` | Starts scheduled outbound aggregation |
| `OUTBOUND_SCAN_INTERVAL_MINUTES` | Background scan interval; 15 minutes is a conservative default |
| `OUTBOUND_LOOKBACK_HOURS` | Rolling analysis window |
| `OUTBOUND_MAX_ROWS` | Maximum tracking rows loaded per scan |
| `OUTBOUND_EVENT_IDS` | Final-delivery event IDs; normally `SENDEXTERNAL` on Edge |
| `OUTBOUND_DIRECTIONALITY` | Normally `Originating` |
| `OUTBOUND_INITIAL_BULK_SENDERS` | Known high-volume service senders to classify as bulk |
| `OUTBOUND_ALERT_RECIPIENTS_5M` | Five-minute warning threshold |
| `OUTBOUND_CRITICAL_RECIPIENTS_10M` | Ten-minute critical threshold |
| `OUTBOUND_DAILY_WARNING` | 24-hour warning threshold |
| `OUTBOUND_DAILY_CRITICAL` | 24-hour critical threshold |

The outbound monitor counts external delivery events, not merely mailbox submissions. Its strict default requires all of the following:

1. `EventId` is in `OUTBOUND_EVENT_IDS`.
2. `Directionality` matches `OUTBOUND_DIRECTIONALITY`.
3. The sender domain belongs to `ORGANIZATION_DOMAINS`.
4. At least one recipient is outside `ORGANIZATION_DOMAINS`.

Use the final Edge event to avoid counting a single message repeatedly across DAG transport events.

## Inbound own-domain spoofing and GeoIP

| Variable | Meaning |
|---|---|
| `INBOUND_SPOOF_MONITOR_ENABLED` | Starts scheduled spoof-source aggregation |
| `INBOUND_SPOOF_SCAN_INTERVAL_MINUTES` | Background scan interval |
| `INBOUND_SPOOF_LOOKBACK_DAYS` | Initial historical lookback |
| `INBOUND_SPOOF_LOOKBACK_HOURS` | Normal rolling window |
| `INBOUND_SPOOF_MAX_ROWS` | Row cap per scan |
| `INBOUND_SPOOF_CRITICAL_ACCEPTED` | Accepted-message threshold for critical display |
| `INBOUND_SPOOF_INITIAL_TRUSTED_IPS` | Comma-separated legitimate public relays to seed into trust |
| `INBOUND_GEOIP_ENABLED` | Enables public-IP country enrichment |
| `INBOUND_GEOIP_API_URL` | HTTPS endpoint template containing `{ip}` |
| `INBOUND_GEOIP_PROXY_URL` | Explicit HTTP(S) or SOCKS proxy |
| `INBOUND_GEOIP_CACHE_DAYS` | Country-result cache duration |
| `INBOUND_GEOIP_MAX_LOOKUPS_PER_SCAN` | Per-scan API cap |
| `INBOUND_GEOIP_MAX_LOOKUPS_PER_DAY` | Daily API cap |

Country enforcement is deliberately disabled by default:

```dotenv
INBOUND_AUTO_BLOCK_OUTSIDE_ALLOWED_COUNTRIES=false
INBOUND_AUTO_BLOCK_ALLOWED_COUNTRIES=
```

To enable it after review, supply ISO 3166-1 alpha-2 country codes:

```dotenv
INBOUND_AUTO_BLOCK_ALLOWED_COUNTRIES=US,CA,GB
INBOUND_AUTO_BLOCK_OUTSIDE_ALLOWED_COUNTRIES=true
INBOUND_AUTO_BLOCK_HOURS=24
INBOUND_AUTO_BLOCK_MAX_PER_SCAN=5
INBOUND_AUTO_BLOCK_MIN_ACCEPTED=1
```

An empty allowed-country list is a fail-safe no-op even if the enable flag is accidentally set to `true`. Unknown GeoIP results, private/reserved addresses, trusted IPs and rejected-only sources are never auto-blocked.

## Message-tracking MySQL

| Variable | Meaning |
|---|---|
| `EXCHANGE_MYSQL_HOST` | TCP host reachable from the web container |
| `EXCHANGE_MYSQL_PORT` | TCP port, normally `3306` |
| `EXCHANGE_MYSQL_SOCKET` | Unix socket path; blank selects TCP |
| `EXCHANGE_MYSQL_DATABASE` | Database containing `GetMessageTrackingLog` |
| `EXCHANGE_MYSQL_USER` | Least-privilege account |
| `EXCHANGE_MYSQL_PASSWORD` | Account password |
| `TRACKING_MYSQL_ROOT_PASSWORD` | Used only by the optional bundled MySQL service |

`127.0.0.1` inside the web container refers to that container, not the Linux host. Use the bundled compose override, a reachable DNS/IP address, or the socket override.

## Telegram and proxy

| Variable | Meaning |
|---|---|
| `TELEGRAM_ENABLED` | Enables alerts and long-poll command handling |
| `TELEGRAM_BOT_TOKEN` | Bot token from BotFather |
| `TELEGRAM_CHAT_ID` | Only chat that receives and controls alerts |
| `TELEGRAM_ALLOWED_USER_IDS` | Comma-separated numeric Telegram user IDs permitted to act |
| `TELEGRAM_PROXY_URL` | Explicit `http://`, `https://`, `socks5://` or `socks5h://` proxy |
| `TELEGRAM_LONG_POLL_SECONDS` | Telegram polling timeout |
| `TELEGRAM_ACTION_TTL_MINUTES` | Expiry of alert action tokens |

The application deliberately ignores ambient proxy variables for Telegram and GeoIP. Configure the explicit proxy values so behavior is predictable.

## Reputation providers

Reputation scanning is optional and disabled initially. Configure only providers you are authorized to use:

```dotenv
REPUTATION_ENABLED=false
SPAMHAUS_DQS_KEY=
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
```

API keys remain in `.env`; do not include them in screenshots, diagnostics or Git history.

## Recommended enablement sequence

1. Start web plus PostgreSQL only.
2. Install Edge and mailbox agents and confirm successful signed heartbeats.
3. Add legitimate IP/domain allowlist entries.
4. Populate message-tracking MySQL and confirm freshness.
5. Enable outbound monitoring and review results.
6. Enable spoof monitoring and review accepted versus rejected attempts.
7. Configure GeoIP and review country assignments.
8. Configure Telegram and send a test.
9. Only then consider automatic block policies.

