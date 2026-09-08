from __future__ import annotations

import ipaddress
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from .config import settings
from .db import SessionLocal
from .mail_direction import (
    organization_domains,
    selected_recipient_count,
    split_recipients,
)
from .models import (
    AllowlistEntry,
    AppSetting,
    AuditLog,
    Command,
    CommandStatus,
    InboundSpoofScanRun,
    InboundSpoofSource,
    IpGeoRecord,
    Node,
    Snapshot,
    utcnow,
)
from .reputation import _mysql_connection

_SCAN_LOCK = threading.Lock()
_WORKER_STARTED = False


def _organization_domains() -> tuple[str, ...]:
    return tuple(sorted(organization_domains(settings.organization_domains)))


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _public_ip(value: Any) -> str | None:
    raw = str(value or "").strip().strip("[]")
    if not raw:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if not address.is_global:
        return None
    return str(address)


def _risk(accepted_messages: int, accepted_recipients: int, unique_senders: int, failed_messages: int) -> str:
    critical_threshold = max(1, settings.inbound_spoof_critical_accepted)
    if (
        accepted_messages >= critical_threshold
        or accepted_recipients >= critical_threshold * 2
        or unique_senders >= 3
    ):
        return "critical"
    if accepted_messages > 0:
        return "high"
    if failed_messages >= 10:
        return "medium"
    return "low"


def _new_metrics() -> dict[str, Any]:
    return {
        "accepted_message_keys": set(),
        "accepted_event_keys": set(),
        "accepted_recipients": 0,
        "failed_message_keys": set(),
        "senders": set(),
        "recipients": set(),
        "subjects": [],
        "first_seen_at": None,
        "last_seen_at": None,
        "last_accepted_at": None,
        "last_failed_at": None,
    }


def _allowed_country_codes() -> set[str]:
    return {
        value.strip().upper()
        for value in settings.inbound_auto_block_allowed_countries.split(",")
        if len(value.strip()) == 2 and value.strip().isalpha()
    }


def _geo_proxy() -> str | None:
    return (
        settings.inbound_geoip_proxy_url.strip()
        or settings.telegram_proxy_url.strip()
        or None
    )


def _lookup_geoip(source_ip: str) -> dict[str, Any]:
    template = settings.inbound_geoip_api_url.strip()
    if "{ip}" not in template:
        raise RuntimeError("INBOUND_GEOIP_API_URL must contain {ip}")
    url = template.format(ip=source_ip)
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("INBOUND_GEOIP_API_URL must be an HTTPS URL")
    with httpx.Client(
        proxy=_geo_proxy(),
        trust_env=False,
        timeout=httpx.Timeout(10, connect=8),
        follow_redirects=False,
        headers={"User-Agent": "ExchangeGuardControl/0.8"},
    ) as client:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()
    if data.get("success") is False:
        raise RuntimeError(str(data.get("message") or "GeoIP provider rejected lookup")[:300])
    returned_ip = _public_ip(data.get("ip"))
    if returned_ip != source_ip:
        raise RuntimeError("GeoIP provider returned a different IP address")
    country_code = str(data.get("country_code") or "").strip().upper()
    if len(country_code) != 2 or not country_code.isalpha():
        raise RuntimeError("GeoIP provider did not return a valid country code")
    connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
    return {
        "country_code": country_code,
        "country_name": str(data.get("country") or country_code).strip()[:128],
        "city": str(data.get("city") or "").strip()[:256] or None,
        "isp": str(connection.get("isp") or connection.get("org") or "").strip()[:512] or None,
        "provider": parsed.hostname[:64],
    }


def _reserve_geo_lookup_slots(requested: int) -> int:
    requested = max(0, requested)
    daily_limit = max(0, min(settings.inbound_geoip_max_lookups_per_day, 10000))
    if requested == 0 or daily_limit == 0:
        return 0
    today = utcnow().date().isoformat()
    key = "inbound_geoip_daily_usage_v1"
    with SessionLocal() as db:
        record = db.get(AppSetting, key, with_for_update=True)
        current = record.value if record and isinstance(record.value, dict) else {}
        try:
            used = max(0, int(current.get("count") or 0)) if current.get("date") == today else 0
        except (TypeError, ValueError):
            used = 0
        granted = min(requested, max(0, daily_limit - used))
        new_value = {"date": today, "count": used + granted, "limit": daily_limit}
        if record:
            record.value = new_value
            record.updated_by = "system:inbound-geo-policy"
        else:
            db.add(
                AppSetting(
                    key=key,
                    value=new_value,
                    updated_by="system:inbound-geo-policy",
                )
            )
        db.commit()
    return granted


def _refresh_geo_cache(source_ips: set[str]) -> dict[str, int]:
    if not settings.inbound_geoip_enabled or not source_ips:
        return {"lookups": 0, "failures": 0}
    now = utcnow()
    with SessionLocal() as db:
        existing = {
            row.source_ip: row
            for row in db.scalars(
                select(IpGeoRecord).where(IpGeoRecord.source_ip.in_(source_ips))
            ).all()
        }
    candidates = [
        source_ip
        for source_ip in sorted(source_ips)
        if source_ip not in existing or existing[source_ip].expires_at <= now
    ][: max(0, min(settings.inbound_geoip_max_lookups_per_scan, 50))]
    lookup_ips = candidates[:_reserve_geo_lookup_slots(len(candidates))]
    failures = 0
    for source_ip in lookup_ips:
        checked_at = utcnow()
        try:
            result = _lookup_geoip(source_ip)
            status = "success"
            error = None
            expires_at = checked_at + timedelta(days=max(1, min(settings.inbound_geoip_cache_days, 365)))
        except Exception as exc:
            result = {}
            status = "failed"
            error = str(exc)[:1000]
            expires_at = checked_at + timedelta(hours=1)
            failures += 1
        with SessionLocal() as db:
            record = db.get(IpGeoRecord, source_ip)
            if not record:
                record = IpGeoRecord(
                    source_ip=source_ip,
                    expires_at=expires_at,
                )
                db.add(record)
            record.country_code = result.get("country_code")
            record.country_name = result.get("country_name")
            record.city = result.get("city")
            record.isp = result.get("isp")
            record.lookup_status = status
            record.provider = result.get("provider") or "ipwho.is"
            record.checked_at = checked_at
            record.expires_at = expires_at
            record.error = error
            db.commit()
    return {"lookups": len(lookup_ips), "failures": failures}


def _snapshot_active_blocked_ips(db, node_id: str) -> set[str]:
    snapshot = db.scalar(
        select(Snapshot)
        .where(Snapshot.node_id == node_id)
        .order_by(Snapshot.captured_at.desc())
        .limit(1)
    )
    blocked: set[str] = set()
    if not snapshot:
        return blocked
    for entry in snapshot.active_ip_blocks or []:
        if not isinstance(entry, dict) or entry.get("has_expired") is True:
            continue
        source_ip = _public_ip(entry.get("address"))
        if source_ip:
            blocked.add(source_ip)
    return blocked


def _latest_ip_commands(db, node_id: str) -> dict[str, Command]:
    commands = db.scalars(
        select(Command)
        .where(
            Command.node_id == node_id,
            Command.command_type.in_(["BlockIp", "UnblockIp"]),
        )
        .order_by(Command.created_at.desc())
        .limit(2000)
    ).all()
    latest: dict[str, Command] = {}
    for command in commands:
        source_ip = _public_ip((command.payload or {}).get("ip"))
        if source_ip:
            latest.setdefault(source_ip, command)
    return latest


def _recent_block_still_applies(command: Command, now: datetime) -> bool:
    if command.command_type != "BlockIp":
        return False
    if command.status in {CommandStatus.pending, CommandStatus.claimed}:
        return True
    if command.status != CommandStatus.succeeded:
        return (
            command.status == CommandStatus.failed
            and command.created_at + timedelta(hours=1) > now
        )
    try:
        duration_hours = max(1, int((command.payload or {}).get("duration_hours") or 24))
    except (TypeError, ValueError):
        duration_hours = 24
    return command.created_at + timedelta(hours=duration_hours) > now


def _queue_country_policy_blocks() -> int:
    if (
        not settings.inbound_geoip_enabled
        or not settings.inbound_auto_block_outside_allowed_countries
    ):
        return 0
    now = utcnow()
    allowed_countries = _allowed_country_codes()
    max_blocks = max(0, min(settings.inbound_auto_block_max_per_scan, 50))
    minimum_accepted = max(1, settings.inbound_auto_block_min_accepted)
    # An empty allow-country list must never become an implicit block-all policy.
    if max_blocks == 0 or not allowed_countries:
        return 0
    with SessionLocal() as db:
        node = db.get(Node, settings.bootstrap_node_id)
        if not node or not node.enabled:
            return 0
        trusted_ips = set(
            db.scalars(
                select(AllowlistEntry.value).where(AllowlistEntry.entry_type == "ip")
            ).all()
        )
        blocked_ips = _snapshot_active_blocked_ips(db, node.id)
        latest_commands = _latest_ip_commands(db, node.id)
        geo_by_ip = {
            row.source_ip: row
            for row in db.scalars(
                select(IpGeoRecord).where(
                    IpGeoRecord.lookup_status == "success",
                    IpGeoRecord.expires_at > now,
                )
            ).all()
        }
        sources = db.scalars(
            select(InboundSpoofSource)
            .where(
                InboundSpoofSource.active.is_(True),
                InboundSpoofSource.accepted_messages >= minimum_accepted,
            )
            .order_by(
                InboundSpoofSource.accepted_messages.desc(),
                InboundSpoofSource.last_seen_at.desc(),
            )
        ).all()
        queued = 0
        for source in sources:
            if queued >= max_blocks:
                break
            geo = geo_by_ip.get(source.source_ip)
            country_code = geo.country_code.upper() if geo and geo.country_code else ""
            if (
                not geo
                or not country_code
                or country_code in allowed_countries
                or source.source_ip in trusted_ips
                or source.source_ip in blocked_ips
            ):
                continue
            latest = latest_commands.get(source.source_ip)
            if latest and latest.status in {CommandStatus.pending, CommandStatus.claimed}:
                continue
            if latest and _recent_block_still_applies(latest, now):
                continue
            duration_hours = max(1, min(settings.inbound_auto_block_hours, 24 * 365))
            command = Command(
                node_id=node.id,
                command_type="BlockIp",
                payload={
                    "ip": source.source_ip,
                    "duration_hours": duration_hours,
                    "reason": (
                        "Automatic inbound spoof country policy: "
                        f"{country_code} / {geo.country_name}"
                    ),
                    "source_spoof_ip": source.source_ip,
                    "country_code": country_code,
                    "country_name": geo.country_name,
                    "automatic": True,
                },
                created_by="system:inbound-geo-policy",
                expires_at=now + timedelta(minutes=settings.command_ttl_minutes),
            )
            db.add(command)
            db.flush()
            db.add(
                AuditLog(
                    actor="system:inbound-geo-policy",
                    action="inbound_spoof_country_block_queued",
                    target=source.source_ip,
                    details={
                        "command_id": command.id,
                        "country_code": country_code,
                        "country_name": geo.country_name,
                        "accepted_messages": source.accepted_messages,
                        "hours": duration_hours,
                    },
                    remote_ip=None,
                )
            )
            latest_commands[source.source_ip] = command
            queued += 1
        db.commit()
        return queued


def run_inbound_spoof_scan() -> dict[str, Any]:
    """Refresh the cached list of public sources impersonating an organization domain."""
    if not _SCAN_LOCK.acquire(blocking=False):
        return {"ok": False, "skipped": "scan_already_running"}

    run_id: int | None = None
    try:
        domains = _organization_domains()
        if not domains:
            raise RuntimeError("ORGANIZATION_DOMAINS is empty")

        with SessionLocal() as db:
            has_successful_scan = db.scalar(
                select(InboundSpoofScanRun.id)
                .where(InboundSpoofScanRun.status == "succeeded")
                .limit(1)
            ) is not None
            lookback_hours = (
                max(1, min(settings.inbound_spoof_lookback_hours, 24 * 7))
                if has_successful_scan
                else max(1, min(settings.inbound_spoof_lookback_days, 31)) * 24
            )
            run = InboundSpoofScanRun(lookback_hours=lookback_hours)
            db.add(run)
            db.commit()
            run_id = run.id

        with _mysql_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT MAX(Timestamp) AS max_timestamp FROM GetMessageTrackingLog")
                anchor_raw = (cur.fetchone() or {}).get("max_timestamp") or datetime.now(timezone.utc)
                anchor = _as_utc(anchor_raw) or datetime.now(timezone.utc)
                start = anchor - timedelta(hours=lookback_hours)
                domain_placeholders = ",".join(["%s"] * len(domains))
                cur.execute(
                    f"""
                    SELECT
                        Timestamp,
                        UPPER(TRIM(EventId)) AS EventId,
                        Sender,
                        Recipients,
                        RecipientCount,
                        MessageSubject,
                        MessageId,
                        NetworkMessageId,
                        COALESCE(
                            NULLIF(TRIM(OriginalClientIp), ''),
                            NULLIF(TRIM(ClientIp), '')
                        ) AS SourceIp
                    FROM GetMessageTrackingLog
                    WHERE Timestamp >= %s
                      AND Directionality = 'Incoming'
                      AND UPPER(TRIM(EventId)) IN ('RECEIVE', 'FAIL')
                      AND Sender LIKE '%%@%%'
                      AND LOWER(SUBSTRING_INDEX(TRIM(Sender), '@', -1)) IN ({domain_placeholders})
                    ORDER BY Timestamp DESC
                    LIMIT %s
                    """,
                    (
                        start.replace(tzinfo=None),
                        *domains,
                        max(1000, min(settings.inbound_spoof_max_rows, 100000)),
                    ),
                )
                rows = cur.fetchall()

        organization_domain_set = set(domains)
        metrics_by_ip: dict[str, dict[str, Any]] = defaultdict(_new_metrics)
        external_only_rows_ignored = 0
        rows_without_addresses_ignored = 0
        for row in rows:
            source_ip = _public_ip(row.get("SourceIp"))
            if not source_ip:
                continue
            event_id = str(row.get("EventId") or "").strip().upper()
            if event_id not in {"RECEIVE", "FAIL"}:
                continue
            sender = str(row.get("Sender") or "").strip().lower()
            if "@" not in sender:
                continue
            ts = _as_utc(row.get("Timestamp"))
            if ts is None:
                continue
            raw_recipients = str(row.get("Recipients") or "").strip()
            parsed_recipients, internal_recipient_list, _ = split_recipients(
                raw_recipients,
                organization_domain_set,
            )
            if not parsed_recipients:
                rows_without_addresses_ignored += 1
                continue
            if not internal_recipient_list:
                external_only_rows_ignored += 1
                continue
            recipients = set(internal_recipient_list)
            subject = " ".join(str(row.get("MessageSubject") or "").split())[:500]
            message_id = str(row.get("NetworkMessageId") or row.get("MessageId") or "").strip().lower()
            message_key = message_id or f"{ts.isoformat()}|{sender}|{subject}"
            recipient_signature = " ".join(raw_recipients.lower().split())
            event_key = f"{message_key}|{recipient_signature}"
            recipient_count = selected_recipient_count(
                parsed_recipients,
                internal_recipient_list,
                row.get("RecipientCount"),
            )

            item = metrics_by_ip[source_ip]
            item["senders"].add(sender)
            item["recipients"].update(recipients)
            if subject and subject not in item["subjects"] and len(item["subjects"]) < 8:
                item["subjects"].append(subject)
            item["first_seen_at"] = min(item["first_seen_at"] or ts, ts)
            item["last_seen_at"] = max(item["last_seen_at"] or ts, ts)
            if event_id == "RECEIVE":
                item["accepted_message_keys"].add(message_key)
                if event_key not in item["accepted_event_keys"]:
                    item["accepted_event_keys"].add(event_key)
                    item["accepted_recipients"] += recipient_count
                item["last_accepted_at"] = max(item["last_accepted_at"] or ts, ts)
            else:
                item["failed_message_keys"].add(message_key)
                item["last_failed_at"] = max(item["last_failed_at"] or ts, ts)

        now = utcnow()
        with SessionLocal() as db:
            existing = {row.source_ip: row for row in db.scalars(select(InboundSpoofSource)).all()}
            for record in existing.values():
                record.active = False
                record.accepted_messages = 0
                record.accepted_recipients = 0
                record.failed_messages = 0
                record.unique_senders = 0
                record.unique_recipients = 0
                record.risk_level = "low"
                record.scanned_at = now

            for source_ip, values in metrics_by_ip.items():
                record = existing.get(source_ip)
                if not record:
                    record = InboundSpoofSource(source_ip=source_ip)
                    db.add(record)
                accepted_messages = len(values["accepted_message_keys"])
                failed_messages = len(values["failed_message_keys"])
                record.accepted_messages = accepted_messages
                record.accepted_recipients = values["accepted_recipients"]
                record.failed_messages = failed_messages
                record.unique_senders = len(values["senders"])
                record.unique_recipients = len(values["recipients"])
                record.sample_senders = sorted(values["senders"])[:12]
                record.sample_recipients = sorted(values["recipients"])[:12]
                record.sample_subjects = values["subjects"]
                record.first_seen_at = min(
                    [value for value in (record.first_seen_at, values["first_seen_at"]) if value],
                    default=values["first_seen_at"],
                )
                record.last_seen_at = values["last_seen_at"]
                record.last_accepted_at = values["last_accepted_at"]
                record.last_failed_at = values["last_failed_at"]
                record.risk_level = _risk(
                    accepted_messages,
                    values["accepted_recipients"],
                    len(values["senders"]),
                    failed_messages,
                )
                record.active = True
                record.scanned_at = now

            run = db.get(InboundSpoofScanRun, run_id)
            if run:
                run.finished_at = now
                run.status = "succeeded"
                run.rows_read = len(rows)
                run.sources_seen = len(metrics_by_ip)
                run.rows_capped = len(rows) >= max(1000, min(settings.inbound_spoof_max_rows, 100000))
            db.commit()

        geo_stats = {"lookups": 0, "failures": 0}
        auto_blocks_queued = 0
        try:
            geo_stats = _refresh_geo_cache(set(metrics_by_ip))
            auto_blocks_queued = _queue_country_policy_blocks()
        except Exception as geo_exc:
            with SessionLocal() as db:
                db.add(
                    AuditLog(
                        actor="system:inbound-geo-policy",
                        action="inbound_geo_enrichment_failed",
                        details={"error": str(geo_exc)[:1000]},
                        remote_ip=None,
                    )
                )
                db.commit()
        return {
            "ok": True,
            "rows_read": len(rows),
            "sources_seen": len(metrics_by_ip),
            "rows_capped": len(rows) >= max(1000, min(settings.inbound_spoof_max_rows, 100000)),
            "external_only_rows_ignored": external_only_rows_ignored,
            "rows_without_addresses_ignored": rows_without_addresses_ignored,
            "geo_lookups": geo_stats["lookups"],
            "geo_failures": geo_stats["failures"],
            "auto_blocks_queued": auto_blocks_queued,
        }
    except Exception as exc:
        if run_id is not None:
            with SessionLocal() as db:
                run = db.get(InboundSpoofScanRun, run_id)
                if run:
                    run.finished_at = utcnow()
                    run.status = "failed"
                    run.error = str(exc)[:4000]
                db.add(
                    AuditLog(
                        actor="system:inbound-spoof-monitor",
                        action="inbound_spoof_scan_failed",
                        details={"error": str(exc)[:1000]},
                        remote_ip=None,
                    )
                )
                db.commit()
        return {"ok": False, "error": str(exc)[:1000]}
    finally:
        _SCAN_LOCK.release()


def _worker() -> None:
    time.sleep(45)
    while True:
        if settings.inbound_spoof_monitor_enabled:
            run_inbound_spoof_scan()
        time.sleep(max(5, settings.inbound_spoof_scan_interval_minutes) * 60)


def start_inbound_spoof_worker() -> None:
    global _WORKER_STARTED
    if _WORKER_STARTED or not settings.inbound_spoof_monitor_enabled:
        return
    _WORKER_STARTED = True
    threading.Thread(target=_worker, name="inbound-spoof-monitor", daemon=True).start()
