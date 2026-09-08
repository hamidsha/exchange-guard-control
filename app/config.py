from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Exchange Guard Control"
    database_url: str = Field(alias="DATABASE_URL")
    session_secret: str = Field(alias="SESSION_SECRET")
    admin_username: str = Field(default="admin", alias="ADMIN_USERNAME")
    admin_password: str = Field(alias="ADMIN_PASSWORD")
    bootstrap_node_id: str = Field(default="edge-01", alias="BOOTSTRAP_NODE_ID")
    bootstrap_node_secret: str = Field(alias="BOOTSTRAP_NODE_SECRET")
    mailbox_node_id: str = Field(default="mailbox-01", alias="MAILBOX_NODE_ID")
    mailbox_node_secret: str = Field(default="", alias="MAILBOX_NODE_SECRET")
    blocked_outbound_group: str = Field(default="", alias="BLOCKED_OUTBOUND_GROUP")
    secure_cookies: bool = Field(default=False, alias="SECURE_COOKIES")
    trusted_hosts: str = Field(default="localhost,127.0.0.1", alias="TRUSTED_HOSTS")
    command_ttl_minutes: int = Field(default=60, alias="COMMAND_TTL_MINUTES")

    reputation_enabled: bool = Field(default=False, alias="REPUTATION_ENABLED")
    reputation_scan_interval_minutes: int = Field(default=30, alias="REPUTATION_SCAN_INTERVAL_MINUTES")
    reputation_lookback_days: int = Field(default=7, alias="REPUTATION_LOOKBACK_DAYS")
    reputation_cache_hours: int = Field(default=24, alias="REPUTATION_CACHE_HOURS")
    reputation_max_domains: int = Field(default=300, alias="REPUTATION_MAX_DOMAINS")
    reputation_max_checks_per_run: int = Field(default=50, alias="REPUTATION_MAX_CHECKS_PER_RUN")
    reputation_max_outbound_rows: int = Field(default=20000, alias="REPUTATION_MAX_OUTBOUND_ROWS")
    reputation_max_source_ips: int = Field(default=3, alias="REPUTATION_MAX_SOURCE_IPS")
    reputation_rdap_enabled: bool = Field(default=True, alias="REPUTATION_RDAP_ENABLED")
    outbound_monitor_enabled: bool = Field(default=False, alias="OUTBOUND_MONITOR_ENABLED")
    outbound_scan_interval_minutes: int = Field(default=15, alias="OUTBOUND_SCAN_INTERVAL_MINUTES")
    outbound_lookback_hours: int = Field(default=24, alias="OUTBOUND_LOOKBACK_HOURS")
    outbound_max_rows: int = Field(default=20000, alias="OUTBOUND_MAX_ROWS")
    outbound_event_ids: str = Field(default="SENDEXTERNAL", alias="OUTBOUND_EVENT_IDS")
    outbound_directionality: str = Field(default="Originating", alias="OUTBOUND_DIRECTIONALITY")
    outbound_initial_bulk_senders: str = Field(default="", alias="OUTBOUND_INITIAL_BULK_SENDERS")
    outbound_alert_recipients_5m: int = Field(default=30, alias="OUTBOUND_ALERT_RECIPIENTS_5M")
    outbound_critical_recipients_10m: int = Field(default=75, alias="OUTBOUND_CRITICAL_RECIPIENTS_10M")
    outbound_daily_warning: int = Field(default=350, alias="OUTBOUND_DAILY_WARNING")
    outbound_daily_critical: int = Field(default=450, alias="OUTBOUND_DAILY_CRITICAL")
    organization_domains: str = Field(default="", alias="ORGANIZATION_DOMAINS")

    inbound_spoof_monitor_enabled: bool = Field(default=False, alias="INBOUND_SPOOF_MONITOR_ENABLED")
    inbound_spoof_scan_interval_minutes: int = Field(default=15, alias="INBOUND_SPOOF_SCAN_INTERVAL_MINUTES")
    inbound_spoof_lookback_days: int = Field(default=7, alias="INBOUND_SPOOF_LOOKBACK_DAYS")
    inbound_spoof_lookback_hours: int = Field(default=24, alias="INBOUND_SPOOF_LOOKBACK_HOURS")
    inbound_spoof_max_rows: int = Field(default=20000, alias="INBOUND_SPOOF_MAX_ROWS")
    inbound_spoof_critical_accepted: int = Field(default=10, alias="INBOUND_SPOOF_CRITICAL_ACCEPTED")
    inbound_spoof_initial_trusted_ips: str = Field(
        default="",
        alias="INBOUND_SPOOF_INITIAL_TRUSTED_IPS",
    )
    inbound_geoip_enabled: bool = Field(default=True, alias="INBOUND_GEOIP_ENABLED")
    inbound_geoip_api_url: str = Field(default="https://ipwho.is/{ip}", alias="INBOUND_GEOIP_API_URL")
    inbound_geoip_proxy_url: str = Field(default="", alias="INBOUND_GEOIP_PROXY_URL")
    inbound_geoip_cache_days: int = Field(default=30, alias="INBOUND_GEOIP_CACHE_DAYS")
    inbound_geoip_max_lookups_per_scan: int = Field(default=8, alias="INBOUND_GEOIP_MAX_LOOKUPS_PER_SCAN")
    inbound_geoip_max_lookups_per_day: int = Field(default=900, alias="INBOUND_GEOIP_MAX_LOOKUPS_PER_DAY")
    inbound_auto_block_outside_allowed_countries: bool = Field(
        default=False,
        alias="INBOUND_AUTO_BLOCK_OUTSIDE_ALLOWED_COUNTRIES",
    )
    inbound_auto_block_allowed_countries: str = Field(
        default="",
        alias="INBOUND_AUTO_BLOCK_ALLOWED_COUNTRIES",
    )
    inbound_auto_block_hours: int = Field(default=24, alias="INBOUND_AUTO_BLOCK_HOURS")
    inbound_auto_block_max_per_scan: int = Field(default=5, alias="INBOUND_AUTO_BLOCK_MAX_PER_SCAN")
    inbound_auto_block_min_accepted: int = Field(default=1, alias="INBOUND_AUTO_BLOCK_MIN_ACCEPTED")

    telegram_enabled: bool = Field(default=False, alias="TELEGRAM_ENABLED")
    telegram_bot_token: str = Field(default="", alias="TELEGRAM_BOT_TOKEN")
    telegram_chat_id: str = Field(default="", alias="TELEGRAM_CHAT_ID")
    telegram_allowed_user_ids: str = Field(default="", alias="TELEGRAM_ALLOWED_USER_IDS")
    telegram_proxy_url: str = Field(default="", alias="TELEGRAM_PROXY_URL")
    telegram_long_poll_seconds: int = Field(default=25, alias="TELEGRAM_LONG_POLL_SECONDS")
    telegram_action_ttl_minutes: int = Field(default=60, alias="TELEGRAM_ACTION_TTL_MINUTES")

    exchange_mysql_host: str = Field(default="127.0.0.1", alias="EXCHANGE_MYSQL_HOST")
    exchange_mysql_port: int = Field(default=3306, alias="EXCHANGE_MYSQL_PORT")
    exchange_mysql_socket: str = Field(default="", alias="EXCHANGE_MYSQL_SOCKET")
    exchange_mysql_database: str = Field(default="exchange_monitoring", alias="EXCHANGE_MYSQL_DATABASE")
    exchange_mysql_user: str = Field(default="", alias="EXCHANGE_MYSQL_USER")
    exchange_mysql_password: str = Field(default="", alias="EXCHANGE_MYSQL_PASSWORD")

    spamhaus_dqs_key: str = Field(default="", alias="SPAMHAUS_DQS_KEY")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")


settings = Settings()
