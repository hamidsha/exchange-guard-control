from __future__ import annotations

import html
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import desc, func, select

from .config import settings
from .db import SessionLocal
from .incidents import IncidentQueueError, queue_mailbox_quarantine
from .models import (
    AppSetting,
    AuditLog,
    IncidentStatus,
    MailboxIncident,
    OutboundSenderProfile,
    OutboundUsageRecord,
    TelegramAlert,
    utcnow,
)

_WORKER_STARTED = False
_HTTP_CLIENT = httpx.Client(
    proxy=settings.telegram_proxy_url.strip() or None,
    trust_env=False,
)


def allowed_user_ids() -> set[int]:
    result: set[int] = set()
    for value in settings.telegram_allowed_user_ids.split(","):
        try:
            result.add(int(value.strip()))
        except (TypeError, ValueError):
            continue
    return result


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def telegram_configuration() -> dict[str, Any]:
    allowed = allowed_user_ids()
    configured = bool(
        settings.telegram_enabled
        and settings.telegram_bot_token.strip()
        and settings.telegram_chat_id.strip()
        and allowed
    )
    return {
        "enabled": settings.telegram_enabled,
        "configured": configured,
        "chat_id": settings.telegram_chat_id.strip(),
        "connection_mode": "proxy" if settings.telegram_proxy_url.strip() else "direct",
        "allowed_user_count": len(allowed),
        "long_poll_seconds": max(5, min(settings.telegram_long_poll_seconds, 50)),
        "action_ttl_minutes": max(5, min(settings.telegram_action_ttl_minutes, 1440)),
    }


def _audit(db, actor: str, action: str, target: str | None = None, details: dict | None = None) -> None:
    db.add(AuditLog(actor=actor[:128], action=action, target=target, details=details, remote_ip=None))


def _api(method: str, payload: dict[str, Any], timeout_seconds: int = 15) -> Any:
    token = settings.telegram_bot_token.strip()
    try:
        response = _HTTP_CLIENT.post(
            f"https://api.telegram.org/bot{token}/{method}",
            json=payload,
            timeout=httpx.Timeout(timeout_seconds + 10, connect=10),
        )
    except httpx.RequestError as exc:
        raise RuntimeError(f"Telegram network error: {type(exc).__name__}") from exc
    try:
        body = response.json()
    except ValueError as exc:
        raise RuntimeError(f"Telegram returned HTTP {response.status_code} with a non-JSON response") from exc
    if response.status_code >= 400:
        raise RuntimeError(
            f"Telegram returned HTTP {response.status_code}: "
            f"{str(body.get('description') or 'request failed')[:300]}"
        )
    if not body.get("ok"):
        raise RuntimeError(str(body.get("description") or "Telegram API rejected the request"))
    return body.get("result")


def _menu_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "📊 ۵ فرستنده اول", "callback_data": "m:top"},
                {"text": "🚨 Criticalها", "callback_data": "m:critical"},
            ],
            [
                {"text": "🛡 Incidentهای فعال", "callback_data": "m:incidents"},
                {"text": "ℹ️ راهنما", "callback_data": "m:help"},
            ],
        ]
    }


def _report_keyboard(include_critical_actions: bool = False) -> dict[str, Any]:
    rows: list[list[dict[str, str]]] = []
    if include_critical_actions:
        now = utcnow()
        with SessionLocal() as db:
            alerts = db.scalars(
                select(TelegramAlert)
                .where(
                    TelegramAlert.risk_active.is_(True),
                    TelegramAlert.status == "sent",
                )
                .order_by(desc(TelegramAlert.created_at))
                .limit(5)
            ).all()
        for alert in alerts:
            if _as_utc(alert.action_expires_at) > now:
                label = alert.sender if len(alert.sender) <= 38 else f"{alert.sender[:35]}…"
                rows.append(
                    [{"text": f"🚫 {label}", "callback_data": f"q:{alert.action_token}"}]
                )
    rows.extend(_menu_keyboard()["inline_keyboard"])
    return {"inline_keyboard": rows}


def _alert_keyboard(alert: TelegramAlert, include_quarantine: bool = True) -> dict[str, Any]:
    rows: list[list[dict[str, str]]] = []
    if include_quarantine:
        rows.append(
            [{"text": f"🚫 Quarantine {alert.sender}", "callback_data": f"q:{alert.action_token}"}]
        )
    rows.extend(_menu_keyboard()["inline_keyboard"])
    return {"inline_keyboard": rows}


def _top_records(limit: int = 5, risk_level: str | None = None) -> list[OutboundUsageRecord]:
    with SessionLocal() as db:
        statement = select(OutboundUsageRecord)
        if risk_level:
            statement = statement.where(OutboundUsageRecord.risk_level == risk_level)
        return list(
            db.scalars(
                statement.order_by(
                    desc(OutboundUsageRecord.recipients_24h),
                    desc(OutboundUsageRecord.recipients_10m),
                    OutboundUsageRecord.sender,
                ).limit(limit)
            ).all()
        )


def _format_usage_rows(records: list[OutboundUsageRecord]) -> str:
    if not records:
        return "موردی در Cache فعلی وجود ندارد."
    lines: list[str] = []
    for index, record in enumerate(records, start=1):
        lines.append(
            f"{index}. <code>{html.escape(record.sender)}</code>\n"
            f"   وضعیت: <b>{html.escape(record.risk_level.upper())}</b> | "
            f"۱۰د: <b>{record.recipients_10m}</b> | "
            f"۱س: <b>{record.recipients_1h}</b> | "
            f"۲۴س: <b>{record.recipients_24h}</b> | "
            f"پیام یکتا: <b>{record.messages_24h}</b>"
        )
    return "\n\n".join(lines)


def _top_report_text() -> str:
    records = _top_records(5)
    scanned_at = max((record.scanned_at for record in records), default=None)
    return (
        "📊 <b>۵ فرستنده با بیشترین تحویل خارجی در ۲۴ ساعت</b>\n\n"
        f"{_format_usage_rows(records)}\n\n"
        f"آخرین اسکن Cache: <code>{html.escape(str(scanned_at or 'نامشخص'))}</code>\n"
        "این درخواست Query جدیدی به Exchange نمی‌زند."
    )


def _critical_report_text() -> str:
    critical = _top_records(20, "critical")
    with SessionLocal() as db:
        total = db.scalar(
            select(func.count())
            .select_from(OutboundUsageRecord)
            .where(OutboundUsageRecord.risk_level == "critical")
        ) or 0
    return (
        f"🚨 <b>فرستنده‌های Critical — {total} مورد</b>\n\n"
        f"{_format_usage_rows(critical)}"
        + ("\n\nنمایش به ۲۰ مورد اول محدود شده است." if total > 20 else "")
    )


def _incident_report_text() -> str:
    active_statuses = [IncidentStatus.pending, IncidentStatus.quarantined, IncidentStatus.partial]
    with SessionLocal() as db:
        incidents = db.scalars(
            select(MailboxIncident)
            .where(MailboxIncident.status.in_(active_statuses))
            .order_by(desc(MailboxIncident.created_at))
            .limit(20)
        ).all()
    if not incidents:
        body = "Incident فعالی وجود ندارد."
    else:
        body = "\n\n".join(
            f"• <code>{html.escape(incident.primary_smtp_address)}</code>\n"
            f"  Incident #{incident.id} | <b>{incident.status.value}</b> | "
            f"By: {html.escape(incident.created_by)}"
            for incident in incidents
        )
    return f"🛡 <b>Incidentهای فعال</b>\n\n{body}"


def _menu_text() -> str:
    with SessionLocal() as db:
        counts = {
            level: db.scalar(
                select(func.count())
                .select_from(OutboundUsageRecord)
                .where(OutboundUsageRecord.risk_level == level)
            ) or 0
            for level in ["critical", "high", "medium", "low", "bulk"]
        }
        active_incidents = db.scalar(
            select(func.count())
            .select_from(MailboxIncident)
            .where(
                MailboxIncident.status.in_(
                    [IncidentStatus.pending, IncidentStatus.quarantined, IncidentStatus.partial]
                )
            )
        ) or 0
    return (
        "🛡 <b>Exchange Guard</b>\n\n"
        f"Critical: <b>{counts['critical']}</b> | High: <b>{counts['high']}</b> | "
        f"Medium: <b>{counts['medium']}</b>\n"
        f"Low: <b>{counts['low']}</b> | Bulk: <b>{counts['bulk']}</b> | "
        f"Incident فعال: <b>{active_incidents}</b>\n\n"
        "دستورهای قابل استفاده:\n"
        "/top — پنج فرستنده اول\n"
        "/critical — فهرست Criticalها\n"
        "/incidents — Incidentهای فعال\n"
        "/menu — نمایش همین منو"
    )


def _send_report(text: str, include_critical_actions: bool = False) -> int:
    result = _api(
        "sendMessage",
        {
            "chat_id": settings.telegram_chat_id.strip(),
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_markup": _report_keyboard(include_critical_actions),
        },
    )
    return int(result["message_id"])


def _register_bot_commands() -> None:
    _api(
        "setMyCommands",
        {
            "commands": [
                {"command": "menu", "description": "منوی Exchange Guard"},
                {"command": "top", "description": "۵ فرستنده با بیشترین ارسال"},
                {"command": "critical", "description": "فرستنده‌های Critical"},
                {"command": "incidents", "description": "Incidentهای فعال"},
                {"command": "help", "description": "راهنما"},
            ]
        },
    )


def send_telegram_test(actor: str) -> int:
    if not telegram_configuration()["configured"]:
        raise RuntimeError("Telegram integration is not fully configured")
    result = _api(
        "sendMessage",
        {
            "chat_id": settings.telegram_chat_id.strip(),
            "text": (
                "✅ <b>Exchange Guard Telegram test</b>\n\n"
                f"اتصال برقرار است. Operator: <code>{html.escape(actor)}</code>\n"
                "هشدارهای جدید CRITICAL با دکمه زمان‌دار Quarantine در همین گفتگو ارسال می‌شوند.\n\n"
                "برای گزارش لحظه‌ای از /top یا دکمه‌های زیر استفاده کنید."
            ),
            "parse_mode": "HTML",
            "reply_markup": _menu_keyboard(),
        },
    )
    return int(result["message_id"])


def sync_critical_alerts() -> dict[str, int]:
    """Create one Telegram alert per non-bulk sender for each critical episode."""
    if not telegram_configuration()["configured"]:
        return {"created": 0, "recovered": 0}

    created = 0
    recovered = 0
    with SessionLocal() as db:
        bulk_senders = {
            str(sender).strip().lower()
            for sender in db.scalars(
                select(OutboundSenderProfile.sender).where(
                    OutboundSenderProfile.enabled.is_(True),
                    OutboundSenderProfile.profile_type == "bulk",
                )
            ).all()
        }
        critical = {
            row.sender: row
            for row in db.scalars(
                select(OutboundUsageRecord).where(OutboundUsageRecord.risk_level == "critical")
            ).all()
            if row.sender.strip().lower() not in bulk_senders
        }
        active_alerts = db.scalars(
            select(TelegramAlert)
            .where(TelegramAlert.risk_active.is_(True))
            .order_by(desc(TelegramAlert.created_at))
        ).all()
        latest_active_by_sender: dict[str, TelegramAlert] = {}
        for alert in active_alerts:
            latest_active_by_sender.setdefault(alert.sender, alert)

        for sender, alert in latest_active_by_sender.items():
            if sender not in critical:
                alert.risk_active = False
                if alert.status in {"pending", "sent"}:
                    alert.status = "recovered"
                recovered += 1
                if sender.strip().lower() in bulk_senders:
                    _audit(
                        db,
                        "system:outbound-monitor",
                        "telegram_alert_suppressed_bulk_profile",
                        sender,
                        {"alert_id": alert.id},
                    )
                else:
                    _audit(
                        db,
                        "system:outbound-monitor",
                        "telegram_alert_recovered",
                        sender,
                        {"alert_id": alert.id},
                    )

        ttl = max(5, min(settings.telegram_action_ttl_minutes, 1440))
        for sender, record in critical.items():
            if sender in latest_active_by_sender:
                continue
            alert = TelegramAlert(
                sender=sender,
                risk_level="critical",
                status="pending",
                risk_active=True,
                action_token=secrets.token_urlsafe(24),
                metrics={
                    "recipients_5m": record.recipients_5m,
                    "recipients_10m": record.recipients_10m,
                    "recipients_1h": record.recipients_1h,
                    "recipients_24h": record.recipients_24h,
                    "messages_24h": record.messages_24h,
                    "unique_recipients_24h": record.unique_recipients_24h,
                    "unique_domains_24h": record.unique_domains_24h,
                    "scanned_at": record.scanned_at.isoformat() if record.scanned_at else None,
                },
                action_expires_at=utcnow() + timedelta(minutes=ttl),
            )
            db.add(alert)
            db.flush()
            created += 1
            _audit(
                db,
                "system:outbound-monitor",
                "telegram_alert_created",
                sender,
                {"alert_id": alert.id, "risk": "critical", "metrics": alert.metrics},
            )
        db.commit()
    return {"created": created, "recovered": recovered}


def _alert_text(alert: TelegramAlert) -> str:
    metrics = alert.metrics or {}
    return (
        "🚨 <b>Exchange Guard — CRITICAL</b>\n\n"
        f"فرستنده: <code>{html.escape(alert.sender)}</code>\n"
        f"تحویل خارجی ۵ دقیقه: <b>{metrics.get('recipients_5m', 0)}</b>\n"
        f"تحویل خارجی ۱۰ دقیقه: <b>{metrics.get('recipients_10m', 0)}</b>\n"
        f"تحویل خارجی ۱ ساعت: <b>{metrics.get('recipients_1h', 0)}</b>\n"
        f"تحویل خارجی ۲۴ ساعت: <b>{metrics.get('recipients_24h', 0)}</b>\n"
        f"پیام یکتای ۲۴ ساعت: <b>{metrics.get('messages_24h', 0)}</b>\n"
        f"گیرنده یکتا: <b>{metrics.get('unique_recipients_24h', 0)}</b>\n\n"
        "📊 <b>۵ فرستنده اول در Cache فعلی</b>\n\n"
        f"{_format_usage_rows(_top_records(5))}\n\n"
        "با دکمه Quarantine، EWS بسته، عضویت گروه Block اعمال و Queue فعلی Edge پاک می‌شود."
    )


def _dispatch_pending_alerts() -> None:
    now = utcnow()
    with SessionLocal() as db:
        alerts = db.scalars(
            select(TelegramAlert)
            .where(TelegramAlert.status == "pending", TelegramAlert.delivery_attempts < 5)
            .order_by(TelegramAlert.created_at)
            .limit(20)
        ).all()
        for alert in alerts:
            if not alert.risk_active or _as_utc(alert.action_expires_at) <= now:
                alert.status = "expired" if alert.risk_active else "recovered"
                continue
            try:
                result = _api(
                    "sendMessage",
                    {
                        "chat_id": settings.telegram_chat_id.strip(),
                        "text": _alert_text(alert),
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True,
                        "reply_markup": _alert_keyboard(alert),
                    },
                )
                alert.status = "sent"
                alert.sent_at = utcnow()
                alert.telegram_chat_id = str(result.get("chat", {}).get("id", settings.telegram_chat_id))
                alert.telegram_message_id = int(result["message_id"])
                alert.last_error = None
                _audit(db, "system:telegram", "telegram_alert_sent", alert.sender, {"alert_id": alert.id})
            except Exception as exc:
                alert.delivery_attempts += 1
                alert.last_error = str(exc)[:2000]
                if alert.delivery_attempts >= 5:
                    alert.status = "send_failed"
                _audit(
                    db,
                    "system:telegram",
                    "telegram_alert_send_failed",
                    alert.sender,
                    {"alert_id": alert.id, "attempt": alert.delivery_attempts, "error": alert.last_error},
                )
            db.commit()


def _answer_callback(callback_id: str, text: str, show_alert: bool = False) -> None:
    try:
        _api(
            "answerCallbackQuery",
            {"callback_query_id": callback_id, "text": text[:180], "show_alert": show_alert},
        )
    except Exception:
        pass


def _replace_keyboard(chat_id: str, message_id: int, keyboard: dict[str, Any]) -> None:
    try:
        _api(
            "editMessageReplyMarkup",
            {"chat_id": chat_id, "message_id": message_id, "reply_markup": keyboard},
        )
    except Exception:
        pass


def _actor_from_user(user: dict[str, Any]) -> str:
    user_id = str(user.get("id") or "unknown")
    username = str(user.get("username") or "").strip()
    return (f"telegram:{user_id}" + (f":{username}" if username else ""))[:128]


def _callback_report(action: str) -> tuple[str, bool]:
    reports = {
        "m:top": _top_report_text,
        "m:critical": _critical_report_text,
        "m:incidents": _incident_report_text,
        "m:help": _menu_text,
        "m:menu": _menu_text,
    }
    factory = reports.get(action)
    if not factory:
        raise ValueError("Unknown Telegram menu action")
    return factory(), action in {"m:top", "m:critical"}


def _process_menu_callback(
    callback_id: str,
    data: str,
    user: dict[str, Any],
    chat_id: str,
) -> None:
    actor = _actor_from_user(user)
    action_name = data.removeprefix("m:")
    _answer_callback(callback_id, "در حال آماده‌سازی گزارش…")
    try:
        report_text, include_actions = _callback_report(data)
        message_id = _send_report(report_text, include_actions)
    except Exception as exc:
        with SessionLocal() as db:
            _audit(
                db,
                actor,
                "telegram_report_failed",
                action_name,
                {"chat_id": chat_id, "error": str(exc)[:1000]},
            )
            db.commit()
        try:
            _send_report("❌ دریافت گزارش ناموفق بود. وضعیت Proxy و Log پنل را بررسی کنید.")
        except Exception:
            pass
        return
    with SessionLocal() as db:
        _audit(
            db,
            actor,
            "telegram_report_sent",
            action_name,
            {"chat_id": chat_id, "message_id": message_id},
        )
        db.commit()


def _already_processed_text(alert: TelegramAlert, incident: MailboxIncident | None) -> str:
    status = incident.status.value if incident else alert.status
    incident_suffix = f" — Incident #{incident.id}" if incident else ""
    messages = {
        "pending": "⏳ درخواست قبلاً ثبت شده و منتظر اجرای Agentهاست",
        "quarantine_requested": "⏳ درخواست قرنطینه قبلاً در صف قرار گرفته است",
        "quarantined": "✅ این Mailbox قبلاً با موفقیت قرنطینه شده است",
        "partial": "⚠️ قرنطینه قبلی ناقص اجرا شده؛ جزئیات را در Incident پنل بررسی کنید",
        "failed": "❌ اجرای قبلی ناموفق بوده؛ جزئیات Incident را بررسی کنید",
        "released": "🔓 Incident قبلی Release شده است",
        "expired": "⌛ اعتبار این دکمه تمام شده است",
        "recovered": "ℹ️ این فرستنده دیگر در وضعیت Critical نیست",
        "action_failed": "❌ درخواست قبلی پذیرفته نشد؛ جزئیات در پنل ثبت شده است",
    }
    return f"{messages.get(status, f'وضعیت فعلی: {status}')}{incident_suffix}"


def _process_callback(callback: dict[str, Any]) -> None:
    callback_id = str(callback.get("id") or "")
    user = callback.get("from") or {}
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    try:
        user_id = int(user.get("id"))
    except (TypeError, ValueError):
        _answer_callback(callback_id, "Unauthorized", True)
        return
    chat_id = str(chat.get("id") or "")
    if user_id not in allowed_user_ids() or chat_id != settings.telegram_chat_id.strip():
        with SessionLocal() as db:
            _audit(
                db,
                f"telegram:{user_id}",
                "telegram_callback_denied",
                details={"chat_id": chat_id},
            )
            db.commit()
        _answer_callback(callback_id, "دسترسی مجاز نیست.", True)
        return

    data = str(callback.get("data") or "")
    if data.startswith("m:"):
        _process_menu_callback(callback_id, data, user, chat_id)
        return
    if not data.startswith("q:"):
        _answer_callback(callback_id, "Unknown action", True)
        return
    token = data[2:]
    actor = _actor_from_user(user)

    with SessionLocal() as db:
        alert = db.scalar(
            select(TelegramAlert)
            .where(TelegramAlert.action_token == token)
            .with_for_update()
        )
        if not alert:
            _audit(db, actor, "telegram_callback_invalid", details={"chat_id": chat_id})
            db.commit()
            _answer_callback(callback_id, "این دکمه معتبر نیست.", True)
            return
        if alert.status != "sent":
            incident = db.get(MailboxIncident, alert.incident_id) if alert.incident_id else None
            if not incident and alert.status == "action_failed":
                incident = db.scalar(
                    select(MailboxIncident)
                    .where(
                        MailboxIncident.primary_smtp_address == alert.sender,
                        MailboxIncident.status.in_(
                            [
                                IncidentStatus.pending,
                                IncidentStatus.quarantined,
                                IncidentStatus.partial,
                            ]
                        ),
                    )
                    .order_by(desc(MailboxIncident.created_at))
                    .limit(1)
                )
                if incident:
                    alert.incident_id = incident.id
                    alert.status = (
                        "quarantine_requested"
                        if incident.status == IncidentStatus.pending
                        else incident.status.value
                    )
                    db.commit()
            if (
                alert.status == "action_failed"
                and alert.risk_active
                and _as_utc(alert.action_expires_at) > utcnow()
                and incident is None
            ):
                alert.status = "sent"
                alert.last_error = None
                db.flush()
            else:
                _answer_callback(callback_id, _already_processed_text(alert, incident), True)
                return
        if _as_utc(alert.action_expires_at) <= utcnow():
            alert.status = "expired"
            _audit(db, actor, "telegram_quarantine_expired", alert.sender, {"alert_id": alert.id})
            db.commit()
            _answer_callback(callback_id, "زمان این دکمه تمام شده؛ از پنل بررسی کنید.", True)
            return
        try:
            incident = queue_mailbox_quarantine(
                db,
                alert.sender,
                f"Telegram critical alert #{alert.id}; operator requested quarantine",
                actor,
            )
        except IncidentQueueError as exc:
            if exc.code == "active_incident_exists" and exc.incident_id:
                existing_incident = db.get(MailboxIncident, exc.incident_id)
                if existing_incident:
                    alert.incident_id = existing_incident.id
                    alert.status = (
                        "quarantine_requested"
                        if existing_incident.status == IncidentStatus.pending
                        else existing_incident.status.value
                    )
                    alert.acted_by = actor[:128]
                    alert.acted_at = utcnow()
                    _audit(
                        db,
                        actor,
                        "telegram_quarantine_already_active",
                        alert.sender,
                        {"alert_id": alert.id, "incident_id": existing_incident.id},
                    )
                    db.commit()
                    message_id = int(message.get("message_id") or alert.telegram_message_id or 0)
                    _answer_callback(
                        callback_id,
                        _already_processed_text(alert, existing_incident),
                        True,
                    )
                    if message_id:
                        _replace_keyboard(chat_id, message_id, _menu_keyboard())
                    return
            alert.status = "action_failed"
            alert.acted_by = actor[:128]
            alert.acted_at = utcnow()
            alert.last_error = str(exc)[:2000]
            _audit(
                db,
                actor,
                "telegram_quarantine_rejected",
                alert.sender,
                {"alert_id": alert.id, "error": str(exc)},
            )
            db.commit()
            _answer_callback(callback_id, f"قرنطینه صف نشد: {exc}", True)
            return

        alert.status = "quarantine_requested"
        alert.incident_id = incident.id
        alert.acted_by = actor[:128]
        alert.acted_at = utcnow()
        _audit(
            db,
            actor,
            "telegram_quarantine_queued",
            alert.sender,
            {
                "alert_id": alert.id,
                "incident_id": incident.id,
                "mailbox_command_id": incident.mailbox_command_id,
                "edge_command_id": incident.edge_command_id,
            },
        )
        db.commit()
        message_id = int(message.get("message_id") or alert.telegram_message_id or 0)

    _answer_callback(
        callback_id,
        f"درخواست قرنطینه ثبت شد — Incident #{incident.id}",
    )
    if message_id:
        _replace_keyboard(chat_id, message_id, _menu_keyboard())
    try:
        _api(
            "sendMessage",
            {
                "chat_id": settings.telegram_chat_id.strip(),
                "text": (
                    f"⏳ قرنطینه <code>{html.escape(alert.sender)}</code> در صف قرار گرفت.\n"
                    f"Incident #{incident.id}\n"
                    "نتیجه Agentها در همین گفتگو و پنل ثبت می‌شود."
                ),
                "parse_mode": "HTML",
                "reply_markup": _menu_keyboard(),
            },
        )
    except Exception:
        pass


def _get_update_offset() -> int:
    with SessionLocal() as db:
        setting = db.get(AppSetting, "telegram_update_offset")
        try:
            return int((setting.value or {}).get("offset", 0)) if setting else 0
        except (TypeError, ValueError):
            return 0


def _process_message(message: dict[str, Any]) -> None:
    user = message.get("from") or {}
    chat = message.get("chat") or {}
    try:
        user_id = int(user.get("id"))
    except (TypeError, ValueError):
        return
    chat_id = str(chat.get("id") or "")
    actor = _actor_from_user(user)
    if user_id not in allowed_user_ids() or chat_id != settings.telegram_chat_id.strip():
        with SessionLocal() as db:
            _audit(
                db,
                actor,
                "telegram_message_denied",
                details={"chat_id": chat_id},
            )
            db.commit()
        return

    text = str(message.get("text") or "").strip()
    command = text.split(maxsplit=1)[0].split("@", 1)[0].lower() if text else ""
    aliases = {
        "/start": "menu",
        "/menu": "menu",
        "/status": "menu",
        "menu": "menu",
        "status": "menu",
        "وضعیت": "menu",
        "/top": "top",
        "/top5": "top",
        "top": "top",
        "top5": "top",
        "/critical": "critical",
        "critical": "critical",
        "/incidents": "incidents",
        "/incident": "incidents",
        "incidents": "incidents",
        "/help": "help",
        "help": "help",
    }
    action = aliases.get(command, "help")
    factories = {
        "menu": _menu_text,
        "top": _top_report_text,
        "critical": _critical_report_text,
        "incidents": _incident_report_text,
        "help": _menu_text,
    }
    try:
        message_id = _send_report(
            factories[action](),
            include_critical_actions=action in {"top", "critical"},
        )
    except Exception as exc:
        with SessionLocal() as db:
            _audit(
                db,
                actor,
                "telegram_command_failed",
                action,
                {"chat_id": chat_id, "error": str(exc)[:1000]},
            )
            db.commit()
        return
    with SessionLocal() as db:
        _audit(
            db,
            actor,
            "telegram_command",
            action,
            {"chat_id": chat_id, "message_id": message_id},
        )
        db.commit()


def _save_update_offset(offset: int) -> None:
    with SessionLocal() as db:
        setting = db.get(AppSetting, "telegram_update_offset")
        if setting:
            setting.value = {"offset": offset}
            setting.updated_by = "system:telegram"
        else:
            db.add(AppSetting(key="telegram_update_offset", value={"offset": offset}, updated_by="system:telegram"))
        db.commit()


def _poll_updates(offset: int) -> int:
    timeout = max(5, min(settings.telegram_long_poll_seconds, 50))
    updates = _api(
        "getUpdates",
        {
            "offset": offset,
            "timeout": timeout,
            "allowed_updates": ["callback_query", "message"],
        },
        timeout_seconds=timeout,
    ) or []
    for update in updates:
        update_id = int(update.get("update_id", 0))
        try:
            callback = update.get("callback_query")
            if callback:
                _process_callback(callback)
            message = update.get("message")
            if message:
                _process_message(message)
        finally:
            offset = max(offset, update_id + 1)
            _save_update_offset(offset)
    return offset


def _reconcile_incidents() -> None:
    terminal_messages = {
        "quarantined": "✅ قرنطینه کامل شد",
        "partial": "⚠️ قرنطینه ناقص اجرا شد؛ Incident را در پنل بررسی کنید",
        "failed": "❌ قرنطینه ناموفق بود؛ Incident را در پنل بررسی کنید",
        "released": "🔓 کاربر از قرنطینه خارج شد",
    }
    with SessionLocal() as db:
        alerts = db.scalars(
            select(TelegramAlert).where(
                TelegramAlert.incident_id.is_not(None),
                (
                    TelegramAlert.status.in_(
                        ["quarantine_requested", "quarantined", "partial", "failed"]
                    )
                )
                | (TelegramAlert.outcome_notified.is_(False)),
            )
        ).all()
        for alert in alerts:
            incident = db.get(MailboxIncident, alert.incident_id)
            if not incident:
                continue
            status = incident.status.value
            expected = "quarantine_requested" if status == "pending" else status
            if alert.status != expected:
                alert.status = expected
                alert.outcome_notified = False
                _audit(
                    db,
                    "system:telegram",
                    "telegram_incident_status",
                    alert.sender,
                    {"alert_id": alert.id, "incident_id": incident.id, "status": expected},
                )
            if status in terminal_messages and not alert.outcome_notified:
                try:
                    _api(
                        "sendMessage",
                        {
                            "chat_id": settings.telegram_chat_id.strip(),
                            "text": f"{terminal_messages[status]}\n<code>{html.escape(alert.sender)}</code>\nIncident #{incident.id}",
                            "parse_mode": "HTML",
                            "reply_markup": _menu_keyboard(),
                        },
                    )
                    alert.outcome_notified = True
                except Exception as exc:
                    alert.last_error = str(exc)[:2000]
            db.commit()


def _worker() -> None:
    time.sleep(5)
    offset = _get_update_offset()
    try:
        _register_bot_commands()
    except Exception as exc:
        with SessionLocal() as db:
            _audit(
                db,
                "system:telegram",
                "telegram_command_menu_failed",
                details={"error": str(exc)[:1000]},
            )
            db.commit()
    while True:
        try:
            _dispatch_pending_alerts()
            _reconcile_incidents()
            offset = _poll_updates(offset)
        except Exception:
            time.sleep(10)


def start_telegram_worker() -> None:
    global _WORKER_STARTED
    if _WORKER_STARTED or not telegram_configuration()["configured"]:
        return
    _WORKER_STARTED = True
    threading.Thread(target=_worker, name="telegram-bot", daemon=True).start()
