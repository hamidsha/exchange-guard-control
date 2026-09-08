from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select

from .config import settings
from .db import SessionLocal
from .mail_direction import (
    is_internal_address,
    organization_domains,
    selected_recipient_count,
    split_recipients,
)
from .models import (
    AuditLog,
    OutboundEvidenceRecord,
    OutboundHourlyRecord,
    OutboundScanRun,
    OutboundSenderProfile,
    OutboundUsageRecord,
    utcnow,
)
from .reputation import _mysql_connection
from .telegram_bot import sync_critical_alerts

_SCAN_LOCK = threading.Lock()
_WORKER_STARTED = False
_EXCHANGE_SYSTEM_SENDER_RE = re.compile(
    r"^(?:microsoftexchange[0-9a-f]+|healthmailbox[0-9a-z]+|"
    r"systemmailbox\{[^}]+\}|discoverysearchmailbox\{[^}]+\}|"
    r"federatedemail\.[^@]+|migration\.[^@]+)@",
    re.I,
)


def _organization_domains() -> set[str]:
    return organization_domains(settings.organization_domains)


def _outbound_event_ids() -> tuple[str, ...]:
    values = tuple(
        value.strip().upper()
        for value in settings.outbound_event_ids.split(",")
        if value.strip()
    )
    return values or ("SENDEXTERNAL",)


def _is_internal(address: str) -> bool:
    return is_internal_address(address, _organization_domains())


def _is_exchange_system_sender(address: str) -> bool:
    return bool(_EXCHANGE_SYSTEM_SENDER_RE.match(address.strip()))


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _risk(metrics: dict[str, Any], profile_type: str | None = None) -> str:
    if profile_type == "bulk":
        return "bulk"
    if profile_type == "expected":
        return "expected"
    if (
        metrics["recipients_10m"] >= settings.outbound_critical_recipients_10m
        or metrics["recipients_24h"] >= settings.outbound_daily_critical
    ):
        return "critical"
    if (
        metrics["recipients_5m"] >= settings.outbound_alert_recipients_5m
        or metrics["recipients_24h"] >= settings.outbound_daily_warning
    ):
        return "high"
    if metrics["recipients_1h"] >= 50 or metrics["recipients_24h"] >= 200:
        return "medium"
    return "low"


def run_outbound_scan() -> dict[str, Any]:
    if not _SCAN_LOCK.acquire(blocking=False):
        return {"ok": False, "skipped": "scan_already_running"}
    run_id: int | None = None
    try:
        with SessionLocal() as db:
            run = OutboundScanRun()
            db.add(run)
            db.commit()
            run_id = run.id
            sender_profiles = {
                profile.sender.lower(): profile.profile_type
                for profile in db.scalars(
                    select(OutboundSenderProfile).where(OutboundSenderProfile.enabled.is_(True))
                ).all()
            }
        with _mysql_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT MAX(Timestamp) AS max_timestamp FROM GetMessageTrackingLog")
                anchor_raw = (cur.fetchone() or {}).get("max_timestamp") or datetime.now(timezone.utc)
                anchor = _as_utc(anchor_raw) or datetime.now(timezone.utc)
                start = anchor - timedelta(hours=max(1, min(settings.outbound_lookback_hours, 48)))
                event_ids = _outbound_event_ids()
                event_placeholders = ",".join(["%s"] * len(event_ids))
                cur.execute(
                    f"""
                    SELECT
                        Sender,
                        Recipients,
                        RecipientCount,
                        MessageId,
                        NetworkMessageId,
                        Timestamp,
                        MessageSubject,
                        TotalBytes,
                        OriginalClientIp,
                        ClientIp
                    FROM GetMessageTrackingLog
                    WHERE Timestamp >= %s
                      AND Directionality = %s
                      AND UPPER(TRIM(EventId)) IN ({event_placeholders})
                      AND Sender LIKE '%%@%%'
                      AND Recipients IS NOT NULL
                    ORDER BY Timestamp DESC
                    LIMIT %s
                    """,
                    (
                        start.replace(tzinfo=None),
                        settings.outbound_directionality,
                        *event_ids,
                        settings.outbound_max_rows,
                    ),
                )
                rows = cur.fetchall()
        organization_domain_set = _organization_domains()
        metrics_by_sender: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "messages_5m": 0,
                "recipients_5m": 0,
                "messages_10m": 0,
                "recipients_10m": 0,
                "messages_1h": 0,
                "recipients_1h": 0,
                "messages_24h": 0,
                "recipients_24h": 0,
                "message_ids_5m": set(),
                "message_ids_10m": set(),
                "message_ids_1h": set(),
                "message_ids_24h": set(),
                "unique_recipients": set(),
                "unique_domains": set(),
                "first_seen_at": None,
                "last_seen_at": None,
            }
        )
        seen_delivery_events: set[tuple[str, str, str]] = set()
        internal_only_rows_ignored = 0
        rows_without_addresses_ignored = 0
        hourly_by_sender: dict[tuple[str, datetime], dict[str, Any]] = defaultdict(
            lambda: {"message_ids": set(), "recipients": 0}
        )
        evidence_rows: dict[str, dict[str, Any]] = {}
        for row in rows:
            sender = str(row.get("Sender") or "").strip().lower()
            if "@" not in sender or not _is_internal(sender):
                continue
            if _is_exchange_system_sender(sender):
                continue
            raw_recipients = str(row.get("Recipients") or "").strip()
            parsed_recipients, _, external_recipient_list = split_recipients(
                raw_recipients,
                organization_domain_set,
            )
            if not parsed_recipients:
                rows_without_addresses_ignored += 1
                continue
            if not external_recipient_list:
                internal_only_rows_ignored += 1
                continue
            recipients = set(external_recipient_list)
            recipient_count = selected_recipient_count(
                parsed_recipients,
                external_recipient_list,
                row.get("RecipientCount"),
            )
            ts = _as_utc(row.get("Timestamp"))
            if ts is None:
                continue
            message_id = str(row.get("MessageId") or "").strip().lower()
            recipient_signature = " ".join(raw_recipients.lower().split())
            delivery_message_key = message_id or ts.isoformat()
            delivery_key = (sender, delivery_message_key, recipient_signature)
            if delivery_key in seen_delivery_events:
                continue
            seen_delivery_events.add(delivery_key)
            message_key = message_id or f"{ts.isoformat()}|{recipient_signature}"
            age = anchor - ts
            item = metrics_by_sender[sender]
            item["message_ids_24h"].add(message_key)
            item["messages_24h"] = len(item["message_ids_24h"])
            item["recipients_24h"] += recipient_count
            item["unique_recipients"].update(recipients)
            item["unique_domains"].update(address.rsplit("@", 1)[-1] for address in recipients)
            item["first_seen_at"] = min(item["first_seen_at"] or ts, ts)
            item["last_seen_at"] = max(item["last_seen_at"] or ts, ts)
            if age <= timedelta(hours=1):
                item["message_ids_1h"].add(message_key)
                item["messages_1h"] = len(item["message_ids_1h"])
                item["recipients_1h"] += recipient_count
            if age <= timedelta(minutes=10):
                item["message_ids_10m"].add(message_key)
                item["messages_10m"] = len(item["message_ids_10m"])
                item["recipients_10m"] += recipient_count
            if age <= timedelta(minutes=5):
                item["message_ids_5m"].add(message_key)
                item["messages_5m"] = len(item["message_ids_5m"])
                item["recipients_5m"] += recipient_count
            hour_start = ts.replace(minute=0, second=0, microsecond=0)
            hourly = hourly_by_sender[(sender, hour_start)]
            hourly["message_ids"].add(message_key)
            hourly["recipients"] += recipient_count
            network_message_id = str(row.get("NetworkMessageId") or "").strip() or None
            event_key_source = "|".join(
                (sender, message_id or "", network_message_id or "", ts.isoformat(), recipient_signature)
            )
            event_key = hashlib.sha256(event_key_source.encode("utf-8", errors="ignore")).hexdigest()
            if event_key not in evidence_rows:
                source_ip = str(row.get("OriginalClientIp") or row.get("ClientIp") or "").strip() or None
                try:
                    total_bytes = max(0, int(row.get("TotalBytes") or 0))
                except (TypeError, ValueError):
                    total_bytes = 0
                evidence_rows[event_key] = {
                    "sender": sender,
                    "event_timestamp": ts,
                    "message_id": message_id or None,
                    "network_message_id": network_message_id,
                    "subject": str(row.get("MessageSubject") or "").strip()[:2000] or None,
                    "recipients": sorted(recipients)[:200],
                    "recipient_count": recipient_count,
                    "total_bytes": total_bytes,
                    "transport_source_ip": source_ip,
                }
        now = utcnow()
        with SessionLocal() as db:
            existing = {row.sender: row for row in db.scalars(select(OutboundUsageRecord)).all()}
            rows_capped = len(rows) >= settings.outbound_max_rows
            for row in existing.values():
                if _is_exchange_system_sender(row.sender):
                    db.delete(row)
                    continue
                if row.sender not in metrics_by_sender and not rows_capped:
                    db.delete(row)
                    continue
                row.messages_5m = row.recipients_5m = 0
                row.messages_10m = row.recipients_10m = 0
                row.messages_1h = row.recipients_1h = 0
                row.messages_24h = row.recipients_24h = 0
                row.unique_recipients_24h = row.unique_domains_24h = 0
                row.risk_level = sender_profiles.get(row.sender, "low")
                row.scanned_at = now
            for sender, values in metrics_by_sender.items():
                record = existing.get(sender)
                if not record:
                    record = OutboundUsageRecord(sender=sender)
                    db.add(record)
                for key in (
                    "messages_5m", "recipients_5m", "messages_10m", "recipients_10m",
                    "messages_1h", "recipients_1h", "messages_24h", "recipients_24h",
                    "first_seen_at", "last_seen_at",
                ):
                    setattr(record, key, values[key])
                record.unique_recipients_24h = len(values["unique_recipients"])
                record.unique_domains_24h = len(values["unique_domains"])
                record.risk_level = _risk(values, sender_profiles.get(sender))
                record.scanned_at = now
            db.execute(delete(OutboundHourlyRecord).where(OutboundHourlyRecord.hour_start < start))
            current_hourly = {
                (row.sender, _as_utc(row.hour_start)): row
                for row in db.scalars(
                    select(OutboundHourlyRecord).where(OutboundHourlyRecord.hour_start >= start)
                ).all()
            }
            seen_hourly: set[tuple[str, datetime]] = set()
            for (sender, hour_start), values in hourly_by_sender.items():
                key = (sender, hour_start)
                seen_hourly.add(key)
                hourly_record = current_hourly.get(key)
                if hourly_record is None:
                    hourly_record = OutboundHourlyRecord(sender=sender, hour_start=hour_start)
                    db.add(hourly_record)
                hourly_record.messages = len(values["message_ids"])
                hourly_record.recipients = values["recipients"]
                hourly_record.scanned_at = now
            for key, hourly_record in current_hourly.items():
                if key not in seen_hourly and not rows_capped:
                    db.delete(hourly_record)
            db.execute(
                delete(OutboundEvidenceRecord).where(OutboundEvidenceRecord.event_timestamp < start)
            )
            if not rows_capped:
                stale_evidence = delete(OutboundEvidenceRecord).where(
                    OutboundEvidenceRecord.event_timestamp >= start
                )
                if evidence_rows:
                    stale_evidence = stale_evidence.where(
                        OutboundEvidenceRecord.event_key.not_in(list(evidence_rows))
                    )
                db.execute(stale_evidence)
            existing_evidence = {
                row.event_key: row
                for row in db.scalars(
                    select(OutboundEvidenceRecord).where(
                        OutboundEvidenceRecord.event_key.in_(list(evidence_rows))
                    )
                ).all()
            } if evidence_rows else {}
            for event_key, values in evidence_rows.items():
                evidence = existing_evidence.get(event_key)
                if evidence is None:
                    evidence = OutboundEvidenceRecord(event_key=event_key)
                    db.add(evidence)
                for field, value in values.items():
                    setattr(evidence, field, value)
                evidence.scanned_at = now
            run = db.get(OutboundScanRun, run_id)
            if run:
                run.finished_at = now
                run.status = "succeeded"
                run.rows_read = len(rows)
                run.senders_seen = len(metrics_by_sender)
                run.rows_capped = rows_capped
            db.commit()
        telegram = {"created": 0, "recovered": 0}
        try:
            telegram = sync_critical_alerts()
        except Exception as telegram_exc:
            with SessionLocal() as db:
                db.add(
                    AuditLog(
                        actor="system:outbound-monitor",
                        action="telegram_alert_sync_failed",
                        details={"error": str(telegram_exc)[:1000]},
                        remote_ip=None,
                    )
                )
                db.commit()
        return {
            "ok": True,
            "rows_read": len(rows),
            "senders_seen": len(metrics_by_sender),
            "rows_capped": len(rows) >= settings.outbound_max_rows,
            "internal_only_rows_ignored": internal_only_rows_ignored,
            "rows_without_addresses_ignored": rows_without_addresses_ignored,
            "telegram_alerts_created": telegram["created"],
            "telegram_alerts_recovered": telegram["recovered"],
        }
    except Exception as exc:
        if run_id is not None:
            with SessionLocal() as db:
                run = db.get(OutboundScanRun, run_id)
                if run:
                    run.finished_at = utcnow()
                    run.status = "failed"
                    run.error = str(exc)[:4000]
                    db.commit()
        return {"ok": False, "error": str(exc)[:1000]}
    finally:
        _SCAN_LOCK.release()


def _worker() -> None:
    time.sleep(30)
    while True:
        if settings.outbound_monitor_enabled:
            run_outbound_scan()
        time.sleep(max(5, settings.outbound_scan_interval_minutes) * 60)


def start_outbound_worker() -> None:
    global _WORKER_STARTED
    if _WORKER_STARTED or not settings.outbound_monitor_enabled:
        return
    _WORKER_STARTED = True
    threading.Thread(target=_worker, name="outbound-monitor", daemon=True).start()
