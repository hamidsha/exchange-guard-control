from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import dns.resolver
import httpx
import pymysql
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .mail_direction import (
    organization_domains,
    split_recipients,
)
from .models import Candidate, CandidateStatus, ReputationRecord, ReputationScanRun, ReputationStatus, utcnow
from .security import normalize_domain

_SCAN_LOCK = threading.Lock()


def _org_domains() -> set[str]:
    return organization_domains(settings.organization_domains)


def _mysql_connection():
    kwargs: dict[str, Any] = {
        "user": settings.exchange_mysql_user,
        "password": settings.exchange_mysql_password,
        "database": settings.exchange_mysql_database,
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "connect_timeout": 8,
        "read_timeout": 30,
        "write_timeout": 10,
        "autocommit": True,
    }
    if settings.exchange_mysql_socket:
        kwargs["unix_socket"] = settings.exchange_mysql_socket
    else:
        kwargs["host"] = settings.exchange_mysql_host
        kwargs["port"] = settings.exchange_mysql_port
    return pymysql.connect(**kwargs)


def _safe_domain(value: str | None) -> str | None:
    if not value:
        return None
    try:
        d = normalize_domain(value)
    except ValueError:
        return None
    if d in _org_domains() or any(d.endswith('.' + own) for own in _org_domains()):
        return None
    return d


def discover_domains() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "inbound_count": 0,
        "outbound_count": 0,
        "unique_recipients": 0,
        "source_ips": set(),
        "first_seen_at": None,
        "last_seen_at": None,
    })
    org_domains = _org_domains()
    ordered_org_domains = tuple(sorted(org_domains))
    if not ordered_org_domains:
        return {}
    with _mysql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT MAX(Timestamp) AS max_timestamp FROM GetMessageTrackingLog")
            row = cur.fetchone() or {}
            anchor = row.get("max_timestamp") or datetime.now()
            start = anchor - timedelta(days=settings.reputation_lookback_days)
            internal_recipient_predicate = " OR ".join(
                ["LOWER(Recipients) LIKE %s"] * len(ordered_org_domains)
            )
            sender_domain_placeholders = ",".join(["%s"] * len(ordered_org_domains))
            cur.execute(
                f"""
                SELECT
                    Sender,
                    Recipients,
                    Timestamp,
                    ClientIp,
                    MessageId,
                    NetworkMessageId
                FROM GetMessageTrackingLog
                WHERE Timestamp >= %s
                  AND Directionality = 'Incoming'
                  AND UPPER(TRIM(EventId)) = 'RECEIVE'
                  AND Sender LIKE '%%@%%'
                  AND Recipients IS NOT NULL
                  AND ({internal_recipient_predicate})
                  AND LOWER(SUBSTRING_INDEX(TRIM(Sender), '@', -1)) NOT IN ({sender_domain_placeholders})
                ORDER BY Timestamp DESC
                LIMIT %s
                """,
                (
                    start,
                    *(f"%@{domain}%" for domain in ordered_org_domains),
                    *ordered_org_domains,
                    max(
                        settings.reputation_max_outbound_rows,
                        settings.reputation_max_domains * 100,
                    ),
                ),
            )
            inbound_message_keys: dict[str, set[tuple[str, str]]] = defaultdict(set)
            inbound_recipients: dict[str, set[str]] = defaultdict(set)
            for row in cur.fetchall():
                sender = str(row.get("Sender") or "").strip().lower()
                d = _safe_domain(sender.rsplit("@", 1)[-1] if "@" in sender else "")
                if not d:
                    continue
                raw_recipients = str(row.get("Recipients") or "")
                _, internal_recipients, _ = split_recipients(raw_recipients, org_domains)
                if not internal_recipients:
                    continue
                ts = row.get("Timestamp")
                message_key = str(
                    row.get("MessageId") or row.get("NetworkMessageId") or ts or ""
                ).strip().lower()
                recipient_signature = " ".join(raw_recipients.lower().split())
                event_key = (message_key, recipient_signature)
                if event_key in inbound_message_keys[d]:
                    continue
                inbound_message_keys[d].add(event_key)
                inbound_recipients[d].update(internal_recipients)
                item = result[d]
                item["inbound_count"] = len(inbound_message_keys[d])
                item["unique_recipients"] = len(inbound_recipients[d])
                if ts:
                    item["first_seen_at"] = min(item["first_seen_at"] or ts, ts)
                    item["last_seen_at"] = max(item["last_seen_at"] or ts, ts)
                source_ip = str(row.get("ClientIp") or "").strip()
                if source_ip:
                    item["source_ips"].add(source_ip)

            event_ids = tuple(
                value.strip().upper()
                for value in settings.outbound_event_ids.split(",")
                if value.strip()
            ) or ("SENDEXTERNAL",)
            event_placeholders = ",".join(["%s"] * len(event_ids))
            cur.execute(
                f"""
                SELECT Sender, Recipients, RecipientCount, MessageId, NetworkMessageId, Timestamp
                FROM GetMessageTrackingLog
                WHERE Timestamp >= %s
                  AND Directionality = %s
                  AND UPPER(TRIM(EventId)) IN ({event_placeholders})
                  AND LOWER(SUBSTRING_INDEX(TRIM(Sender), '@', -1)) IN ({sender_domain_placeholders})
                  AND Recipients IS NOT NULL
                ORDER BY Timestamp DESC
                LIMIT %s
                """,
                (
                    start,
                    settings.outbound_directionality,
                    *event_ids,
                    *ordered_org_domains,
                    settings.reputation_max_outbound_rows,
                ),
            )
            outbound_counts: Counter[str] = Counter()
            outbound_first: dict[str, datetime] = {}
            outbound_last: dict[str, datetime] = {}
            seen_events: set[tuple[str, str, str]] = set()
            for row in cur.fetchall():
                ts = row.get("Timestamp")
                raw_recipients = str(row.get("Recipients") or "")
                _, _, external_recipients = split_recipients(raw_recipients, org_domains)
                if not external_recipients:
                    continue
                sender = str(row.get("Sender") or "").strip().lower()
                message_key = str(
                    row.get("MessageId") or row.get("NetworkMessageId") or ts or ""
                ).strip().lower()
                recipient_signature = " ".join(raw_recipients.lower().split())
                event_key = (sender, message_key, recipient_signature)
                if event_key in seen_events:
                    continue
                seen_events.add(event_key)
                for address in external_recipients:
                    d = _safe_domain(address.rsplit("@", 1)[-1])
                    if not d:
                        continue
                    outbound_counts[d] += 1
                    outbound_first[d] = min(outbound_first.get(d, ts), ts) if ts else outbound_first.get(d)
                    outbound_last[d] = max(outbound_last.get(d, ts), ts) if ts else outbound_last.get(d)
            for d, count in outbound_counts.most_common(settings.reputation_max_domains):
                item = result[d]
                item["outbound_count"] = count
                if outbound_first.get(d):
                    item["first_seen_at"] = min(x for x in [item.get("first_seen_at"), outbound_first[d]] if x)
                if outbound_last.get(d):
                    item["last_seen_at"] = max(x for x in [item.get("last_seen_at"), outbound_last[d]] if x)
    for item in result.values():
        item["source_ips"] = sorted(item["source_ips"])[:10]
    return dict(result)


def _resolve(name: str, rtype: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    try:
        answer = resolver.resolve(name, rtype)
        return [str(x).strip('"') for x in answer]
    except Exception:
        return []


def _dns_hygiene(domain: str) -> dict[str, Any]:
    mx = _resolve(domain, "MX")
    txt = _resolve(domain, "TXT")
    dmarc = _resolve(f"_dmarc.{domain}", "TXT")
    a = _resolve(domain, "A")
    spf = [x for x in txt if x.lower().startswith("v=spf1")]
    dmarc_records = [x for x in dmarc if x.lower().startswith("v=dmarc1")]
    return {"mx": mx[:10], "a": a[:10], "has_spf": bool(spf), "has_dmarc": bool(dmarc_records), "spf": spf[:3], "dmarc": dmarc_records[:3]}


def _rdap(domain: str) -> dict[str, Any]:
    if not settings.reputation_rdap_enabled:
        return {"enabled": False}
    try:
        with httpx.Client(timeout=8, follow_redirects=True, headers={"User-Agent": "ExchangeGuardControl/0.2"}) as client:
            r = client.get(f"https://rdap.org/domain/{domain}")
            if r.status_code != 200:
                return {"status_code": r.status_code}
            data = r.json()
        registered = None
        for event in data.get("events", []):
            if event.get("eventAction") in {"registration", "registered"}:
                registered = event.get("eventDate")
                break
        age_days = None
        if registered:
            dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).days)
        return {"registered_at": registered, "age_days": age_days, "handle": data.get("handle")}
    except Exception as exc:
        return {"error": str(exc)[:300]}


def _dqs_query(resource: str, zone: str, is_ip: bool = False) -> dict[str, Any]:
    if not settings.spamhaus_dqs_key:
        return {"enabled": False}
    try:
        if is_ip:
            ip = ipaddress.ip_address(resource)
            if ip.version == 4:
                query = ".".join(reversed(resource.split('.')))
            else:
                query = ".".join(reversed(ip.exploded.replace(':', '')))
        else:
            query = resource
        fqdn = f"{query}.{settings.spamhaus_dqs_key}.{zone}.dq.spamhaus.net"
        answers = _resolve(fqdn, "A")
        valid = [x for x in answers if x.startswith("127.")]
        errors = [x for x in valid if x.startswith("127.255.255.")]
        listed = bool(valid and not errors)
        return {"enabled": True, "listed": listed, "answers": valid, "errors": errors}
    except Exception as exc:
        return {"enabled": True, "error": str(exc)[:300]}


def _abuseipdb(ip: str) -> dict[str, Any]:
    if not settings.abuseipdb_api_key:
        return {"enabled": False}
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            r.raise_for_status()
            data = r.json().get("data", {})
        return {
            "enabled": True,
            "abuse_confidence_score": int(data.get("abuseConfidenceScore") or 0),
            "total_reports": int(data.get("totalReports") or 0),
            "distinct_users": int(data.get("numDistinctUsers") or 0),
            "last_reported_at": data.get("lastReportedAt"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "country_code": data.get("countryCode"),
        }
    except Exception as exc:
        return {"enabled": True, "error": str(exc)[:300]}


def _virustotal(domain: str) -> dict[str, Any]:
    if not settings.virustotal_api_key:
        return {"enabled": False}
    try:
        with httpx.Client(timeout=12) as client:
            r = client.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": settings.virustotal_api_key})
            if r.status_code == 404:
                return {"enabled": True, "not_found": True}
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "enabled": True,
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories", {}),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
    except Exception as exc:
        return {"enabled": True, "error": str(exc)[:300]}


def _score(record: ReputationRecord, providers: dict[str, Any], candidate: Candidate | None) -> tuple[int, str, str, list[str]]:
    score = 0
    reasons: list[str] = []
    dbl = providers.get("spamhaus_dbl", {})
    codes = set(dbl.get("answers") or [])
    if dbl.get("listed"):
        if codes & {"127.0.1.4", "127.0.1.5", "127.0.1.6", "127.0.1.104", "127.0.1.105", "127.0.1.106"}:
            score += 80; reasons.append("Spamhaus DBL: phishing/malware/botnet related")
        elif codes & {"127.0.1.2"}:
            score += 60; reasons.append("Spamhaus DBL: low-reputation domain")
        else:
            score += 35; reasons.append("Spamhaus DBL: abused legitimate/redirector domain")
    zrd = providers.get("spamhaus_zrd", {})
    if zrd.get("listed"):
        score += 30; reasons.append("Spamhaus ZRD: very recently observed domain")
    vt = providers.get("virustotal", {})
    mal, susp = int(vt.get("malicious") or 0), int(vt.get("suspicious") or 0)
    if mal >= 5:
        score += 60; reasons.append(f"VirusTotal: {mal} malicious engines")
    elif mal >= 2:
        score += 35; reasons.append(f"VirusTotal: {mal} malicious engines")
    elif mal == 1 or susp >= 2:
        score += 15; reasons.append("VirusTotal: limited malicious/suspicious detections")
    rdap = providers.get("rdap", {})
    age = rdap.get("age_days")
    if isinstance(age, int) and age < 7:
        score += 25; reasons.append(f"Domain age is only {age} days")
    elif isinstance(age, int) and age < 30:
        score += 12; reasons.append(f"Domain age is {age} days")
    dns = providers.get("dns", {})
    if not dns.get("mx"):
        score += 8; reasons.append("No MX record")
    if not dns.get("has_spf"):
        score += 3; reasons.append("No SPF record")
    if not dns.get("has_dmarc"):
        score += 3; reasons.append("No DMARC record")
    ip_results = providers.get("source_ips", {})
    for ip, data in ip_results.items():
        zen = data.get("spamhaus_zen", {})
        abuse = data.get("abuseipdb", {})
        if zen.get("listed"):
            score += 45; reasons.append(f"Source IP {ip} is listed by Spamhaus ZEN")
            break
        acs = int(abuse.get("abuse_confidence_score") or 0)
        users = int(abuse.get("distinct_users") or 0)
        if acs >= 90 and users >= 3:
            score += 45; reasons.append(f"Source IP {ip} AbuseIPDB score {acs}")
            break
        if acs >= 70:
            score += 30; reasons.append(f"Source IP {ip} AbuseIPDB score {acs}")
            break
        if acs >= 40:
            score += 15; reasons.append(f"Source IP {ip} AbuseIPDB score {acs}")
            break
    if candidate and candidate.status in {CandidateStatus.open, CandidateStatus.approved, CandidateStatus.blocked}:
        score += min(40, 10 + candidate.consecutive_hits * 10)
        reasons.append(f"Internal behavioral detector: {candidate.message_count} messages / {candidate.unique_recipient_count} recipients")
    if record.inbound_count >= 20:
        score += 8; reasons.append(f"High inbound volume: {record.inbound_count} messages")
    if record.unique_recipients >= 12:
        score += 8; reasons.append(f"Broad targeting: {record.unique_recipients} recipients")
    score = min(100, score)
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    if record.outbound_count and level in {"critical", "high"}:
        recommendation = "investigate_outbound"
        reasons.append("Outbound traffic to a risky domain may indicate account or endpoint compromise")
    elif record.inbound_count and level in {"critical", "high"}:
        recommendation = "block_suggested"
    elif level == "medium":
        recommendation = "review"
    else:
        recommendation = "monitor"
    return score, level, recommendation, reasons


def check_record(db: Session, record: ReputationRecord) -> None:
    providers: dict[str, Any] = {}
    providers["dns"] = _dns_hygiene(record.domain)
    providers["rdap"] = _rdap(record.domain)
    providers["spamhaus_dbl"] = _dqs_query(record.domain, "dbl")
    providers["spamhaus_zrd"] = _dqs_query(record.domain, "zrd")
    providers["virustotal"] = _virustotal(record.domain)
    ip_results: dict[str, Any] = {}
    for ip in (record.source_ips or [])[: settings.reputation_max_source_ips]:
        try:
            if not ipaddress.ip_address(ip).is_global:
                continue
        except ValueError:
            continue
        ip_results[ip] = {"spamhaus_zen": _dqs_query(ip, "zen", is_ip=True), "abuseipdb": _abuseipdb(ip)}
    providers["source_ips"] = ip_results
    candidate = db.scalar(select(Candidate).where(Candidate.sender_domain == record.domain).order_by(desc(Candidate.last_seen_at)).limit(1))
    score, level, recommendation, reasons = _score(record, providers, candidate)
    record.provider_results = providers
    record.risk_score = score
    record.risk_level = level
    record.recommendation = recommendation
    record.reasons = reasons
    record.checked_at = utcnow()


def run_reputation_scan(force: bool = False) -> dict[str, Any]:
    if not _SCAN_LOCK.acquire(blocking=False):
        return {"status": "already_running"}
    run_id = None
    try:
        with SessionLocal() as db:
            run = ReputationScanRun(status="running")
            db.add(run); db.commit(); db.refresh(run); run_id = run.id
        discovered = discover_domains()
        checked = errors = 0
        checks_remaining = max(1, settings.reputation_max_checks_per_run)
        with SessionLocal() as db:
            run = db.get(ReputationScanRun, run_id)
            run.discovered = len(discovered)
            for domain, data in discovered.items():
                record = db.scalar(select(ReputationRecord).where(ReputationRecord.domain == domain))
                if not record:
                    record = ReputationRecord(domain=domain)
                    db.add(record); db.flush()
                record.inbound_count = data["inbound_count"]
                record.outbound_count = data["outbound_count"]
                record.unique_recipients = data["unique_recipients"]
                record.source_ips = data["source_ips"]
                record.first_seen_at = data["first_seen_at"]
                record.last_seen_at = data["last_seen_at"]
                due = force or not record.checked_at or record.checked_at < utcnow() - timedelta(hours=settings.reputation_cache_hours)
                if due and checks_remaining > 0:
                    try:
                        check_record(db, record); checked += 1; checks_remaining -= 1
                    except Exception as exc:
                        errors += 1
                        record.provider_results = {"error": str(exc)[:500]}
                        record.checked_at = utcnow()
                db.commit()
            run.finished_at = utcnow(); run.status = "completed" if errors == 0 else "completed_with_errors"
            run.checked = checked; run.errors = errors
            run.details = {"providers": provider_status(), "lookback_days": settings.reputation_lookback_days}
            db.commit()
        return {"status": "completed", "discovered": len(discovered), "checked": checked, "errors": errors}
    except Exception as exc:
        if run_id:
            with SessionLocal() as db:
                run = db.get(ReputationScanRun, run_id)
                if run:
                    run.finished_at = utcnow(); run.status = "failed"; run.errors = 1; run.details = {"error": str(exc)[:1000]}; db.commit()
        return {"status": "failed", "error": str(exc)}
    finally:
        _SCAN_LOCK.release()


def provider_status() -> dict[str, bool]:
    return {
        "mysql": bool(settings.exchange_mysql_user and settings.exchange_mysql_password),
        "spamhaus_dqs": bool(settings.spamhaus_dqs_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "virustotal": bool(settings.virustotal_api_key),
        "rdap": settings.reputation_rdap_enabled,
        "dns_hygiene": True,
    }


def _worker() -> None:
    time.sleep(20)
    while True:
        if settings.reputation_enabled:
            run_reputation_scan(force=False)
        time.sleep(max(300, settings.reputation_scan_interval_minutes * 60))


def start_worker() -> None:
    if settings.reputation_enabled:
        threading.Thread(target=_worker, name="reputation-worker", daemon=True).start()
