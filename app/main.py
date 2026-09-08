from __future__ import annotations

import hashlib
import ipaddress
import json
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import settings
from .db import Base, SessionLocal, engine, get_db
from .models import (
    AllowlistEntry,
    AppSetting,
    AuditLog,
    Candidate,
    CandidateStatus,
    Command,
    CommandStatus,
    Event,
    IncidentStatus,
    InboundSpoofScanRun,
    InboundSpoofSource,
    IpGeoRecord,
    MailboxIncident,
    MailboxRecord,
    Node,
    OutboundScanRun,
    OutboundEvidenceRecord,
    OutboundHourlyRecord,
    OutboundSenderProfile,
    OutboundUsageRecord,
    Role,
    Snapshot,
    TelegramAlert,
    ThrottlingPolicyRecord,
    ReputationRecord,
    ReputationScanRun,
    ReputationStatus,
    User,
    utcnow,
)
from .reputation import check_record, provider_status, run_reputation_scan, start_worker
from .outbound import run_outbound_scan, start_outbound_worker
from .inbound_spoof import run_inbound_spoof_scan, start_inbound_spoof_worker
from .incidents import IncidentQueueError, queue_mailbox_quarantine
from .telegram_bot import send_telegram_test, start_telegram_worker, telegram_configuration
from .security import (
    csrf_token,
    hash_password,
    normalize_domain,
    normalize_ip,
    require_admin,
    require_user,
    verify_agent_request,
    verify_csrf,
    verify_password,
)


app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=settings.secure_cookies,
    same_site="lax",
    max_age=8 * 60 * 60,
)
trusted_hosts = [x.strip() for x in settings.trusted_hosts.split(",") if x.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts or ["*"])
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def audit(db: Session, request: Request | None, actor: str, action: str, target: str | None = None, details: dict[str, Any] | None = None) -> None:
    remote_ip = request.client.host if request and request.client else None
    db.add(AuditLog(actor=actor, action=action, target=target, details=details, remote_ip=remote_ip))


def queue_command(db: Session, node_id: str, command_type: str, payload: dict[str, Any], actor: str) -> Command:
    expires_at = utcnow() + timedelta(minutes=settings.command_ttl_minutes)
    cmd = Command(
        node_id=node_id,
        command_type=command_type,
        payload=payload,
        created_by=actor,
        expires_at=expires_at,
    )
    db.add(cmd)
    db.flush()
    return cmd


def base_context(request: Request, db: Session, title: str, user: User | None = None) -> dict[str, Any]:
    now = utcnow()

    def node_summary(node_id: str, label: str) -> dict[str, Any]:
        node = db.get(Node, node_id)
        last_seen = node.last_seen_at if node else None
        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        connected = bool(
            node
            and node.enabled
            and last_seen
            and (now - last_seen).total_seconds() <= 15 * 60
        )
        return {
            "label": label,
            "connected": connected,
            "last_seen_at": last_seen,
        }

    return {
        "request": request,
        "title": title,
        "app_name": settings.app_name,
        "user": user,
        "csrf_token": csrf_token(request),
        "shell_nodes": [
            node_summary(settings.bootstrap_node_id, "Edge agent"),
            node_summary(settings.mailbox_node_id, "Mailbox agent"),
        ] if user else [],
    }


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == settings.admin_username))
        if not user:
            db.add(
                User(
                    username=settings.admin_username,
                    password_hash=hash_password(settings.admin_password),
                    role=Role.admin,
                    enabled=True,
                )
            )
        node = db.get(Node, settings.bootstrap_node_id)
        if not node:
            db.add(
                Node(
                    id=settings.bootstrap_node_id,
                    display_name=settings.bootstrap_node_id,
                    shared_secret=settings.bootstrap_node_secret,
                    enabled=True,
                )
            )
        if settings.mailbox_node_secret:
            mailbox_node = db.get(Node, settings.mailbox_node_id)
            if not mailbox_node:
                db.add(
                    Node(
                        id=settings.mailbox_node_id,
                        display_name="Exchange Mailbox Management",
                        shared_secret=settings.mailbox_node_secret,
                        enabled=True,
                    )
                )
        defaults = {
            "auto_enforce": {"enabled": False},
            "default_ip_block_hours": {"hours": 24},
            "max_blocks_per_run": {"count": 3},
        }
        for key, value in defaults.items():
            if not db.get(AppSetting, key):
                db.add(AppSetting(key=key, value=value, updated_by="bootstrap"))
        seed_key = "outbound_bulk_profiles_seeded_v1"
        if not db.get(AppSetting, seed_key):
            for sender in {
                value.strip().lower()
                for value in settings.outbound_initial_bulk_senders.split(",")
                if value.strip()
            }:
                if "@" in sender and not db.get(OutboundSenderProfile, sender):
                    db.add(
                        OutboundSenderProfile(
                            sender=sender,
                            profile_type="bulk",
                            note="Initial approved bulk sender",
                            created_by="bootstrap",
                        )
                    )
            db.add(AppSetting(key=seed_key, value={"completed": True}, updated_by="bootstrap"))
        spoof_seed_key = "inbound_spoof_trusted_ips_seeded_v1"
        if not db.get(AppSetting, spoof_seed_key):
            trusted_added = []
            for raw_ip in settings.inbound_spoof_initial_trusted_ips.split(","):
                if not raw_ip.strip():
                    continue
                try:
                    trusted_ip = normalize_ip(raw_ip)
                except ValueError:
                    continue
                exists = db.scalar(
                    select(AllowlistEntry).where(
                        AllowlistEntry.entry_type == "ip",
                        AllowlistEntry.value == trusted_ip,
                    )
                )
                if not exists:
                    db.add(
                        AllowlistEntry(
                            entry_type="ip",
                            value=trusted_ip,
                            comment="Trusted public sender seeded for inbound spoof monitoring",
                            created_by="bootstrap",
                        )
                    )
                    trusted_added.append(trusted_ip)
            db.add(
                AppSetting(
                    key=spoof_seed_key,
                    value={"completed": True, "trusted_ips": trusted_added},
                    updated_by="bootstrap",
                )
            )
            db.flush()
            if trusted_added:
                queue_command(db, settings.bootstrap_node_id, "SyncAllowlist", {}, "bootstrap")
                for trusted_ip in trusted_added:
                    queue_command(
                        db,
                        settings.bootstrap_node_id,
                        "UnblockIp",
                        {"ip": trusted_ip, "reason": "Initial trusted inbound sender"},
                        "bootstrap",
                    )
        db.commit()
    start_worker()
    start_outbound_worker()
    start_inbound_spoof_worker()
    start_telegram_worker()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if request.session.get("username"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", base_context(request, db, "Login"))


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = db.scalar(select(User).where(User.username == username, User.enabled.is_(True)))
    if not user or not verify_password(user.password_hash, password):
        audit(db, request, username, "login_failed")
        db.commit()
        context = base_context(request, db, "Login")
        context["error"] = "Invalid username or password"
        return templates.TemplateResponse("login.html", context, status_code=401)
    request.session.clear()
    request.session["username"] = user.username
    csrf_token(request)
    audit(db, request, user.username, "login_succeeded")
    db.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    username = request.session.get("username", "unknown")
    audit(db, request, username, "logout")
    db.commit()
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    open_candidates = db.scalar(select(func.count()).select_from(Candidate).where(Candidate.status == CandidateStatus.open)) or 0
    pending_commands = db.scalar(select(func.count()).select_from(Command).where(Command.status.in_([CommandStatus.pending, CommandStatus.claimed]))) or 0
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    recent_candidates = db.scalars(select(Candidate).order_by(desc(Candidate.last_seen_at)).limit(10)).all()
    latest_snapshot = db.scalar(select(Snapshot).order_by(desc(Snapshot.captured_at)).limit(1))
    recent_events = db.scalars(select(Event).order_by(desc(Event.timestamp_utc)).limit(10)).all()
    high_risk_domains = db.scalar(select(func.count()).select_from(ReputationRecord).where(ReputationRecord.risk_level.in_(["high", "critical"]), ReputationRecord.status == ReputationStatus.open)) or 0
    recent_reputation = db.scalars(select(ReputationRecord).order_by(desc(ReputationRecord.risk_score), desc(ReputationRecord.last_seen_at)).limit(10)).all()
    mailbox_count = db.scalar(select(func.count()).select_from(MailboxRecord).where(MailboxRecord.active.is_(True))) or 0
    assigned_policy_count = db.scalar(
        select(func.count())
        .select_from(MailboxRecord)
        .where(
            MailboxRecord.active.is_(True),
            MailboxRecord.current_policy.is_not(None),
        )
    ) or 0
    outbound_alerts = db.scalar(select(func.count()).select_from(OutboundUsageRecord).where(OutboundUsageRecord.risk_level.in_(["high", "critical"]))) or 0
    active_incidents = db.scalar(select(func.count()).select_from(MailboxIncident).where(MailboxIncident.status.in_([IncidentStatus.pending, IncidentStatus.quarantined, IncidentStatus.partial]))) or 0
    top_outbound = db.scalars(
        select(OutboundUsageRecord)
        .where(OutboundUsageRecord.risk_level != "bulk")
        .order_by(
            desc(OutboundUsageRecord.recipients_10m),
            desc(OutboundUsageRecord.recipients_24h),
        )
        .limit(6)
    ).all()
    dashboard_incidents = db.scalars(
        select(MailboxIncident)
        .where(
            MailboxIncident.status.in_([
                IncidentStatus.pending,
                IncidentStatus.quarantined,
                IncidentStatus.partial,
            ])
        )
        .order_by(desc(MailboxIncident.created_at))
        .limit(4)
    ).all()
    trusted_spoof_ips = set(
        db.scalars(select(AllowlistEntry.value).where(AllowlistEntry.entry_type == "ip")).all()
    )
    suspicious_spoof_sources = sum(
        1
        for row in db.scalars(
            select(InboundSpoofSource).where(
                InboundSpoofSource.active.is_(True),
                InboundSpoofSource.accepted_messages > 0,
            )
        ).all()
        if row.source_ip not in trusted_spoof_ips
    )
    context = base_context(request, db, "Dashboard", user)
    context.update(
        {
            "open_candidates": open_candidates,
            "pending_commands": pending_commands,
            "nodes": nodes,
            "recent_candidates": recent_candidates,
            "latest_snapshot": latest_snapshot,
            "recent_events": recent_events,
            "high_risk_domains": high_risk_domains,
            "recent_reputation": recent_reputation,
            "mailbox_count": mailbox_count,
            "assigned_policy_count": assigned_policy_count,
            "outbound_alerts": outbound_alerts,
            "active_incidents": active_incidents,
            "top_outbound": top_outbound,
            "dashboard_incidents": dashboard_incidents,
            "suspicious_spoof_sources": suspicious_spoof_sources,
        }
    )
    return templates.TemplateResponse("dashboard.html", context)


@app.get("/reputation", response_class=HTMLResponse)
def reputation_page(request: Request, level: str = "", direction: str = "", status: str = "", db: Session = Depends(get_db)):
    user = require_user(request, db)
    stmt = select(ReputationRecord)
    if level in {"critical", "high", "medium", "low"}:
        stmt = stmt.where(ReputationRecord.risk_level == level)
    if status in {x.value for x in ReputationStatus}:
        stmt = stmt.where(ReputationRecord.status == ReputationStatus(status))
    if direction == "inbound":
        stmt = stmt.where(ReputationRecord.inbound_count > 0)
    elif direction == "outbound":
        stmt = stmt.where(ReputationRecord.outbound_count > 0)
    records = db.scalars(stmt.order_by(desc(ReputationRecord.risk_score), desc(ReputationRecord.last_seen_at)).limit(1000)).all()
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    latest_run = db.scalar(select(ReputationScanRun).order_by(desc(ReputationScanRun.started_at)).limit(1))
    counts = {lvl: db.scalar(select(func.count()).select_from(ReputationRecord).where(ReputationRecord.risk_level == lvl, ReputationRecord.status == ReputationStatus.open)) or 0 for lvl in ["critical", "high", "medium", "low"]}
    context = base_context(request, db, "External reputation", user)
    context.update({"records": records, "nodes": nodes, "latest_run": latest_run, "provider_status": provider_status(), "counts": counts, "filters": {"level": level, "direction": direction, "status": status}})
    return templates.TemplateResponse("reputation.html", context)


@app.get("/reputation/{record_id}", response_class=HTMLResponse)
def reputation_detail(record_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    record = db.get(ReputationRecord, record_id)
    if not record:
        raise HTTPException(404, "Reputation record not found")
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    context = base_context(request, db, f"Reputation: {record.domain}", user)
    context.update({"record": record, "nodes": nodes})
    return templates.TemplateResponse("reputation_detail.html", context)


@app.post("/reputation/scan")
def reputation_scan(request: Request, csrf: str = Form(...), force: bool = Form(False), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    result = run_reputation_scan(force=force)
    audit(db, request, user.username, "reputation_scan", details=result)
    db.commit()
    return RedirectResponse("/reputation", status_code=303)


@app.post("/reputation/check")
def reputation_check(request: Request, csrf: str = Form(...), domain: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    domain = normalize_domain(domain)
    record = db.scalar(select(ReputationRecord).where(ReputationRecord.domain == domain))
    if not record:
        record = ReputationRecord(domain=domain)
        db.add(record); db.flush()
    check_record(db, record)
    audit(db, request, user.username, "reputation_manual_check", domain, {"score": record.risk_score, "level": record.risk_level})
    db.commit()
    return RedirectResponse(f"/reputation/{record.id}", status_code=303)


@app.post("/reputation/{record_id}/block")
def reputation_block(record_id: int, request: Request, csrf: str = Form(...), node_id: str = Form(...), scope: str = Form("subdomains"), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    record = db.get(ReputationRecord, record_id)
    if not record:
        raise HTTPException(404, "Reputation record not found")
    allow = db.scalar(select(AllowlistEntry).where(AllowlistEntry.entry_type == "domain", AllowlistEntry.value == record.domain))
    if allow:
        raise HTTPException(409, "Domain is allowlisted")
    command_type = "BlockDomainExact" if scope == "exact" else "BlockDomainAndSubdomains"
    cmd = queue_command(db, node_id, command_type, {"domain": record.domain, "reason": f"External reputation score {record.risk_score}: {record.recommendation}", "source_reputation_id": record.id}, user.username)
    audit(db, request, user.username, "reputation_block_queued", record.domain, {"command_id": cmd.id, "scope": scope, "score": record.risk_score})
    db.commit()
    return RedirectResponse(f"/reputation/{record.id}", status_code=303)


@app.post("/reputation/{record_id}/dismiss")
def reputation_dismiss(record_id: int, request: Request, csrf: str = Form(...), reason: str = Form("Dismissed by administrator"), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    record = db.get(ReputationRecord, record_id)
    if not record:
        raise HTTPException(404, "Reputation record not found")
    record.status = ReputationStatus.dismissed
    record.dismissed_reason = reason[:1000]
    audit(db, request, user.username, "reputation_dismissed", record.domain, {"reason": reason[:1000]})
    db.commit()
    return RedirectResponse(f"/reputation/{record.id}", status_code=303)


@app.post("/reputation/{record_id}/allowlist")
def reputation_allowlist(record_id: int, request: Request, csrf: str = Form(...), comment: str = Form("Added from reputation page"), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    record = db.get(ReputationRecord, record_id)
    if not record:
        raise HTTPException(404, "Reputation record not found")
    existing = db.scalar(select(AllowlistEntry).where(AllowlistEntry.entry_type == "domain", AllowlistEntry.value == record.domain))
    if not existing:
        db.add(AllowlistEntry(entry_type="domain", value=record.domain, comment=comment[:1000], created_by=user.username))
    record.status = ReputationStatus.allowlisted
    audit(db, request, user.username, "reputation_allowlisted", record.domain)
    db.commit()
    return RedirectResponse(f"/reputation/{record.id}", status_code=303)


@app.get("/candidates", response_class=HTMLResponse)
def candidates_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    candidates = db.scalars(select(Candidate).order_by(desc(Candidate.last_seen_at)).limit(500)).all()
    context = base_context(request, db, "Candidates", user)
    context["candidates"] = candidates
    return templates.TemplateResponse("candidates.html", context)




@app.get("/candidates/{candidate_id}", response_class=HTMLResponse)
def candidate_detail(candidate_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    candidate = db.get(Candidate, candidate_id)
    if not candidate:
        raise HTTPException(404, "Candidate not found")
    evidence = db.scalars(
        select(Event)
        .where(
            Event.node_id == candidate.node_id,
            Event.client_ip == candidate.client_ip,
            Event.sender_domain == candidate.sender_domain,
        )
        .order_by(desc(Event.timestamp_utc))
        .limit(100)
    ).all()
    context = base_context(request, db, f"Candidate {candidate.id}", user)
    context.update({"candidate": candidate, "evidence": evidence})
    return templates.TemplateResponse("candidate_detail.html", context)


@app.post("/candidates/{candidate_id}/approve")
def candidate_approve(
    candidate_id: int,
    request: Request,
    csrf: str = Form(...),
    duration_hours: int = Form(24),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    candidate = db.get(Candidate, candidate_id)
    if not candidate:
        raise HTTPException(404, "Candidate not found")
    duration_hours = max(1, min(duration_hours, 24 * 30))
    cmd = queue_command(
        db,
        candidate.node_id,
        "BlockIp",
        {
            "ip": candidate.client_ip,
            "duration_hours": duration_hours,
            "reason": f"Approved candidate {candidate.id}: {candidate.sender_domain}",
            "source_candidate_id": candidate.id,
        },
        user.username,
    )
    candidate.status = CandidateStatus.approved
    audit(db, request, user.username, "candidate_approved", str(candidate.id), {"command_id": cmd.id})
    db.commit()
    return RedirectResponse("/candidates", status_code=303)


@app.post("/candidates/{candidate_id}/dismiss")
def candidate_dismiss(
    candidate_id: int,
    request: Request,
    csrf: str = Form(...),
    reason: str = Form("Dismissed by administrator"),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    candidate = db.get(Candidate, candidate_id)
    if not candidate:
        raise HTTPException(404, "Candidate not found")
    candidate.status = CandidateStatus.dismissed
    candidate.dismissed_reason = reason[:1000]
    audit(db, request, user.username, "candidate_dismissed", str(candidate.id), {"reason": reason[:1000]})
    db.commit()
    return RedirectResponse("/candidates", status_code=303)


@app.get("/blocks", response_class=HTMLResponse)
def blocks_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    snapshot = db.scalar(select(Snapshot).order_by(desc(Snapshot.captured_at)).limit(1))
    commands = db.scalars(
        select(Command)
        .where(Command.command_type.in_(["BlockIp", "UnblockIp", "BlockDomainExact", "BlockDomainAndSubdomains", "UnblockDomainExact", "UnblockDomainAndSubdomains"]))
        .order_by(desc(Command.created_at))
        .limit(100)
    ).all()
    context = base_context(request, db, "Blocks", user)
    context.update({"nodes": nodes, "snapshot": snapshot, "commands": commands})
    return templates.TemplateResponse("blocks.html", context)


@app.post("/blocks/ip")
def manual_block_ip(
    request: Request,
    csrf: str = Form(...),
    node_id: str = Form(...),
    ip: str = Form(...),
    duration_hours: int = Form(24),
    reason: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    ip = normalize_ip(ip)
    duration_hours = max(1, min(duration_hours, 24 * 365))
    allow = db.scalar(select(AllowlistEntry).where(AllowlistEntry.entry_type == "ip", AllowlistEntry.value == ip))
    if allow:
        raise HTTPException(409, "IP is allowlisted")
    cmd = queue_command(db, node_id, "BlockIp", {"ip": ip, "duration_hours": duration_hours, "reason": reason[:500]}, user.username)
    audit(db, request, user.username, "manual_ip_block_queued", ip, {"command_id": cmd.id, "hours": duration_hours})
    db.commit()
    return RedirectResponse("/blocks", status_code=303)


@app.post("/blocks/ip/unblock")
def manual_unblock_ip(
    request: Request,
    csrf: str = Form(...),
    node_id: str = Form(...),
    ip: str = Form(...),
    reason: str = Form("Manual unblock"),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    ip = normalize_ip(ip)
    cmd = queue_command(db, node_id, "UnblockIp", {"ip": ip, "reason": reason[:500]}, user.username)
    audit(db, request, user.username, "manual_ip_unblock_queued", ip, {"command_id": cmd.id})
    db.commit()
    return RedirectResponse("/blocks", status_code=303)


@app.post("/blocks/domain")
def manual_block_domain(
    request: Request,
    csrf: str = Form(...),
    node_id: str = Form(...),
    domain: str = Form(...),
    scope: str = Form("subdomains"),
    reason: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    domain = normalize_domain(domain)
    allow = db.scalar(select(AllowlistEntry).where(AllowlistEntry.entry_type == "domain", AllowlistEntry.value == domain))
    if allow:
        raise HTTPException(409, "Domain is allowlisted")
    command_type = "BlockDomainExact" if scope == "exact" else "BlockDomainAndSubdomains"
    cmd = queue_command(db, node_id, command_type, {"domain": domain, "reason": reason[:500]}, user.username)
    audit(db, request, user.username, "manual_domain_block_queued", domain, {"command_id": cmd.id, "scope": scope})
    db.commit()
    return RedirectResponse("/blocks", status_code=303)


@app.post("/blocks/domain/unblock")
def manual_unblock_domain(
    request: Request,
    csrf: str = Form(...),
    node_id: str = Form(...),
    domain: str = Form(...),
    scope: str = Form("subdomains"),
    reason: str = Form("Manual unblock"),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    domain = normalize_domain(domain)
    command_type = "UnblockDomainExact" if scope == "exact" else "UnblockDomainAndSubdomains"
    cmd = queue_command(db, node_id, command_type, {"domain": domain, "reason": reason[:500]}, user.username)
    audit(db, request, user.username, "manual_domain_unblock_queued", domain, {"command_id": cmd.id, "scope": scope})
    db.commit()
    return RedirectResponse("/blocks", status_code=303)


def _edge_node(db: Session) -> Node:
    node = db.get(Node, settings.bootstrap_node_id)
    if not node or not node.enabled:
        raise HTTPException(409, "Edge management node is not configured or enabled")
    return node


def _country_flag(country_code: str | None) -> str:
    code = str(country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(character)) for character in code)


def _public_ip_or_400(value: str) -> str:
    try:
        normalized = normalize_ip(value)
        address = ipaddress.ip_address(normalized)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP address") from exc
    if not address.is_global:
        raise HTTPException(400, "Only public source IP addresses can be managed here")
    return normalized


def _snapshot_blocked_ips(snapshot: Snapshot | None) -> set[str]:
    blocked: set[str] = set()
    if not snapshot:
        return blocked
    for entry in snapshot.active_ip_blocks or []:
        if isinstance(entry, dict) and entry.get("has_expired") is True:
            continue
        raw = entry.get("address") if isinstance(entry, dict) else None
        if not raw:
            continue
        try:
            blocked.add(normalize_ip(str(raw)))
        except ValueError:
            continue
    return blocked


def _active_ip_commands(db: Session, node_id: str) -> dict[str, Command]:
    commands = db.scalars(
        select(Command)
        .where(
            Command.node_id == node_id,
            Command.command_type.in_(["BlockIp", "UnblockIp"]),
            Command.status.in_([CommandStatus.pending, CommandStatus.claimed]),
        )
        .order_by(desc(Command.created_at))
    ).all()
    result: dict[str, Command] = {}
    for command in commands:
        raw_ip = str((command.payload or {}).get("ip") or "")
        try:
            command_ip = normalize_ip(raw_ip)
        except ValueError:
            continue
        result.setdefault(command_ip, command)
    return result


@app.get("/spoofing", response_class=HTMLResponse)
def inbound_spoofing_page(
    request: Request,
    q: str = "",
    risk: str = "",
    state: str = "",
    history: bool = False,
    db: Session = Depends(get_db),
):
    user = require_user(request, db)
    stmt = select(InboundSpoofSource)
    if not history:
        stmt = stmt.where(InboundSpoofSource.active.is_(True))
    if q.strip():
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(InboundSpoofSource.source_ip.ilike(pattern))
    if risk in {"critical", "high", "medium", "low"}:
        stmt = stmt.where(InboundSpoofSource.risk_level == risk)
    records = db.scalars(
        stmt.order_by(
            desc(InboundSpoofSource.accepted_messages),
            desc(InboundSpoofSource.failed_messages),
            desc(InboundSpoofSource.last_seen_at),
        ).limit(2000)
    ).all()

    trusted_entries = db.scalars(
        select(AllowlistEntry).where(AllowlistEntry.entry_type == "ip")
    ).all()
    trusted_by_ip = {entry.value: entry for entry in trusted_entries}
    snapshot = db.scalar(
        select(Snapshot)
        .where(Snapshot.node_id == settings.bootstrap_node_id)
        .order_by(desc(Snapshot.captured_at))
        .limit(1)
    )
    blocked_ips = _snapshot_blocked_ips(snapshot)
    pending_by_ip = _active_ip_commands(db, settings.bootstrap_node_id)
    geo_by_ip = {
        record.source_ip: record
        for record in db.scalars(
            select(IpGeoRecord).where(
                IpGeoRecord.source_ip.in_([record.source_ip for record in records])
            )
        ).all()
    } if records else {}

    rows = []
    for record in records:
        pending = pending_by_ip.get(record.source_ip)
        if record.source_ip in trusted_by_ip:
            effective_state = "trusted"
        elif pending and pending.command_type == "BlockIp":
            effective_state = "block_pending"
        elif pending and pending.command_type == "UnblockIp":
            effective_state = "unblock_pending"
        elif record.source_ip in blocked_ips:
            effective_state = "blocked"
        else:
            effective_state = "open"
        if state and state != effective_state:
            continue
        geo = geo_by_ip.get(record.source_ip)
        rows.append(
            {
                "record": record,
                "state": effective_state,
                "pending": pending,
                "trusted_entry": trusted_by_ip.get(record.source_ip),
                "geo": geo,
                "country_flag": _country_flag(geo.country_code if geo else None),
            }
        )

    latest_run = db.scalar(
        select(InboundSpoofScanRun).order_by(desc(InboundSpoofScanRun.started_at)).limit(1)
    )
    active_records = db.scalars(
        select(InboundSpoofSource).where(InboundSpoofSource.active.is_(True))
    ).all()
    suspicious_records = [
        record
        for record in active_records
        if record.accepted_messages > 0 and record.source_ip not in trusted_by_ip
    ]
    context = base_context(request, db, "Inbound domain spoofing", user)
    context.update(
        {
            "rows": rows,
            "latest_run": latest_run,
            "snapshot": snapshot,
            "counts": {
                "suspicious_sources": len(suspicious_records),
                "accepted_messages": sum(record.accepted_messages for record in suspicious_records),
                "failed_messages": sum(record.failed_messages for record in active_records),
                "trusted_sources": sum(1 for record in active_records if record.source_ip in trusted_by_ip),
                "blocked_sources": sum(1 for record in active_records if record.source_ip in blocked_ips),
            },
            "filters": {"q": q, "risk": risk, "state": state, "history": history},
            "scan": {
                "interval_minutes": settings.inbound_spoof_scan_interval_minutes,
                "initial_lookback_days": settings.inbound_spoof_lookback_days,
                "lookback_hours": settings.inbound_spoof_lookback_hours,
                "organization_domains": settings.organization_domains,
            },
            "geo_policy": {
                "enabled": settings.inbound_geoip_enabled,
                "connection_mode": "proxy" if (
                    settings.inbound_geoip_proxy_url.strip()
                    or settings.telegram_proxy_url.strip()
                ) else "direct",
                "cache_days": settings.inbound_geoip_cache_days,
                "daily_lookup_cap": settings.inbound_geoip_max_lookups_per_day,
                "auto_block": settings.inbound_auto_block_outside_allowed_countries,
                "allowed_countries": settings.inbound_auto_block_allowed_countries,
                "allowed_country_codes": {
                    value.strip().upper()
                    for value in settings.inbound_auto_block_allowed_countries.split(",")
                    if len(value.strip()) == 2 and value.strip().isalpha()
                },
                "block_hours": settings.inbound_auto_block_hours,
                "max_per_scan": settings.inbound_auto_block_max_per_scan,
            },
        }
    )
    return templates.TemplateResponse("spoofing.html", context)


@app.post("/spoofing/scan")
def inbound_spoofing_scan(request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    result = run_inbound_spoof_scan()
    audit(db, request, user.username, "inbound_spoof_scan", details=result)
    db.commit()
    return RedirectResponse("/spoofing", status_code=303)


@app.post("/spoofing/{source_ip}/block")
def inbound_spoofing_block(
    source_ip: str,
    request: Request,
    csrf: str = Form(...),
    duration_hours: int = Form(24),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    source_ip = _public_ip_or_400(source_ip)
    if not db.get(InboundSpoofSource, source_ip):
        raise HTTPException(404, "Spoof source was not found")
    if db.scalar(
        select(AllowlistEntry).where(
            AllowlistEntry.entry_type == "ip",
            AllowlistEntry.value == source_ip,
        )
    ):
        raise HTTPException(409, "IP is trusted; remove trust before blocking it")
    node = _edge_node(db)
    active = _active_ip_commands(db, node.id).get(source_ip)
    if active and active.command_type == "BlockIp":
        return RedirectResponse("/spoofing", status_code=303)
    duration_hours = max(1, min(duration_hours, 24 * 365))
    command = queue_command(
        db,
        node.id,
        "BlockIp",
        {
            "ip": source_ip,
            "duration_hours": duration_hours,
            "reason": "Inbound messages impersonated an organization domain",
            "source_spoof_ip": source_ip,
        },
        user.username,
    )
    audit(
        db,
        request,
        user.username,
        "inbound_spoof_ip_block_queued",
        source_ip,
        {"command_id": command.id, "hours": duration_hours},
    )
    db.commit()
    return RedirectResponse("/spoofing", status_code=303)


@app.post("/spoofing/{source_ip}/unblock")
def inbound_spoofing_unblock(
    source_ip: str,
    request: Request,
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    source_ip = _public_ip_or_400(source_ip)
    node = _edge_node(db)
    active = _active_ip_commands(db, node.id).get(source_ip)
    if active and active.command_type == "UnblockIp":
        return RedirectResponse("/spoofing", status_code=303)
    command = queue_command(
        db,
        node.id,
        "UnblockIp",
        {"ip": source_ip, "reason": "Released from inbound spoofing review"},
        user.username,
    )
    audit(
        db,
        request,
        user.username,
        "inbound_spoof_ip_unblock_queued",
        source_ip,
        {"command_id": command.id},
    )
    db.commit()
    return RedirectResponse("/spoofing", status_code=303)


@app.post("/spoofing/{source_ip}/trust")
def inbound_spoofing_trust(
    source_ip: str,
    request: Request,
    csrf: str = Form(...),
    comment: str = Form("Trusted inbound sender"),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    source_ip = _public_ip_or_400(source_ip)
    node = _edge_node(db)
    entry = db.scalar(
        select(AllowlistEntry).where(
            AllowlistEntry.entry_type == "ip",
            AllowlistEntry.value == source_ip,
        )
    )
    if not entry:
        entry = AllowlistEntry(
            entry_type="ip",
            value=source_ip,
            comment=comment.strip()[:1000] or "Trusted inbound sender",
            created_by=user.username,
        )
        db.add(entry)
        db.flush()

    for command in db.scalars(
        select(Command).where(
            Command.node_id == node.id,
            Command.command_type == "BlockIp",
            Command.status == CommandStatus.pending,
        )
    ).all():
        if str((command.payload or {}).get("ip") or "") == source_ip:
            command.status = CommandStatus.cancelled

    sync_command = queue_command(db, node.id, "SyncAllowlist", {}, user.username)
    unblock_command = queue_command(
        db,
        node.id,
        "UnblockIp",
        {"ip": source_ip, "reason": "IP marked trusted in inbound spoofing review"},
        user.username,
    )
    audit(
        db,
        request,
        user.username,
        "inbound_spoof_ip_trusted",
        source_ip,
        {"sync_command_id": sync_command.id, "unblock_command_id": unblock_command.id},
    )
    db.commit()
    return RedirectResponse("/spoofing", status_code=303)


@app.post("/spoofing/{source_ip}/untrust")
def inbound_spoofing_untrust(
    source_ip: str,
    request: Request,
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    source_ip = _public_ip_or_400(source_ip)
    node = _edge_node(db)
    entry = db.scalar(
        select(AllowlistEntry).where(
            AllowlistEntry.entry_type == "ip",
            AllowlistEntry.value == source_ip,
        )
    )
    if entry:
        db.delete(entry)
        db.flush()
        command = queue_command(db, node.id, "SyncAllowlist", {}, user.username)
        audit(
            db,
            request,
            user.username,
            "inbound_spoof_ip_untrusted",
            source_ip,
            {"sync_command_id": command.id},
        )
        db.commit()
    return RedirectResponse("/spoofing", status_code=303)


@app.get("/allowlist", response_class=HTMLResponse)
def allowlist_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    entries = db.scalars(select(AllowlistEntry).order_by(AllowlistEntry.entry_type, AllowlistEntry.value)).all()
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    context = base_context(request, db, "Allowlist", user)
    context.update({"entries": entries, "nodes": nodes})
    return templates.TemplateResponse("allowlist.html", context)


@app.post("/allowlist")
def allowlist_add(
    request: Request,
    csrf: str = Form(...),
    entry_type: str = Form(...),
    value: str = Form(...),
    comment: str = Form(""),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    if entry_type == "ip":
        value = normalize_ip(value)
    elif entry_type == "domain":
        value = normalize_domain(value)
    else:
        raise HTTPException(400, "Invalid allowlist type")
    entry = AllowlistEntry(entry_type=entry_type, value=value, comment=comment[:1000], created_by=user.username)
    db.add(entry)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Allowlist entry already exists") from exc
    node = _edge_node(db)
    queue_command(db, node.id, "SyncAllowlist", {}, user.username)
    audit(db, request, user.username, "allowlist_added", f"{entry_type}:{value}", {"comment": comment[:1000]})
    db.commit()
    return RedirectResponse("/allowlist", status_code=303)


@app.post("/allowlist/{entry_id}/delete")
def allowlist_delete(entry_id: int, request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    entry = db.get(AllowlistEntry, entry_id)
    if not entry:
        raise HTTPException(404, "Allowlist entry not found")
    target = f"{entry.entry_type}:{entry.value}"
    db.delete(entry)
    db.flush()
    node = _edge_node(db)
    queue_command(db, node.id, "SyncAllowlist", {}, user.username)
    audit(db, request, user.username, "allowlist_removed", target)
    db.commit()
    return RedirectResponse("/allowlist", status_code=303)


@app.get("/commands", response_class=HTMLResponse)
def commands_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    commands = db.scalars(select(Command).order_by(desc(Command.created_at)).limit(500)).all()
    context = base_context(request, db, "Commands", user)
    context["commands"] = commands
    return templates.TemplateResponse("commands.html", context)


@app.post("/commands/{command_id}/cancel")
def command_cancel(command_id: str, request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    cmd = db.get(Command, command_id)
    if not cmd:
        raise HTTPException(404, "Command not found")
    if cmd.status != CommandStatus.pending:
        raise HTTPException(409, "Only pending commands can be cancelled")
    cmd.status = CommandStatus.cancelled
    audit(db, request, user.username, "command_cancelled", cmd.id)
    db.commit()
    return RedirectResponse("/commands", status_code=303)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    app_settings = {item.key: item.value for item in db.scalars(select(AppSetting)).all()}
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    context = base_context(request, db, "Settings", user)
    context.update({"settings": app_settings, "nodes": nodes})
    return templates.TemplateResponse("settings.html", context)


@app.post("/settings/enforcement")
def set_enforcement(
    request: Request,
    csrf: str = Form(...),
    node_id: str = Form(...),
    mode: str = Form(...),
    confirmation: str = Form(""),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    if mode not in {"Audit", "Enforce"}:
        raise HTTPException(400, "Invalid mode")
    if mode == "Enforce" and confirmation != "ENABLE ENFORCE":
        raise HTTPException(400, "Type ENABLE ENFORCE to enable automatic blocking")
    cmd = queue_command(db, node_id, "SetEnforcementMode", {"mode": mode}, user.username)
    audit(db, request, user.username, "enforcement_mode_queued", node_id, {"mode": mode, "command_id": cmd.id})
    db.commit()
    return RedirectResponse("/settings", status_code=303)




@app.post("/settings/thresholds")
def set_thresholds(
    request: Request,
    csrf: str = Form(...),
    node_id: str = Form(...),
    lookback_minutes: int = Form(...),
    min_messages: int = Form(...),
    min_unique_recipients: int = Form(...),
    min_top_subject_ratio: float = Form(...),
    min_domain_dominance_ratio: float = Form(...),
    min_scl: int = Form(...),
    min_scl_samples: int = Form(...),
    min_scl_evidence_ratio: float = Form(...),
    required_consecutive_hits: int = Form(...),
    block_hours: int = Form(...),
    max_blocks_per_run: int = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    values = {
        "LookbackMinutes": max(5, min(240, lookback_minutes)),
        "MinMessages": max(1, min(10000, min_messages)),
        "MinUniqueRecipients": max(1, min(10000, min_unique_recipients)),
        "MinTopSubjectRatio": max(0.1, min(1.0, min_top_subject_ratio)),
        "MinDomainDominanceRatio": max(0.1, min(1.0, min_domain_dominance_ratio)),
        "MinScl": max(0, min(9, min_scl)),
        "MinSclSamples": max(1, min(10000, min_scl_samples)),
        "MinSclEvidenceRatio": max(0.1, min(1.0, min_scl_evidence_ratio)),
        "RequiredConsecutiveHits": max(1, min(10, required_consecutive_hits)),
        "BlockHours": max(1, min(8760, block_hours)),
        "MaxBlocksPerRun": max(1, min(100, max_blocks_per_run)),
    }
    cmd = queue_command(db, node_id, "UpdateThresholds", values, user.username)
    audit(db, request, user.username, "threshold_update_queued", node_id, {"command_id": cmd.id, "values": values})
    db.commit()
    return RedirectResponse("/settings", status_code=303)


def mailbox_filter_statement(search: str = "", policy: str = "", dotted_only: bool = False):
    stmt = select(MailboxRecord).where(MailboxRecord.active.is_(True))
    search = search.strip()
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            MailboxRecord.primary_smtp_address.ilike(pattern)
            | MailboxRecord.display_name.ilike(pattern)
            | MailboxRecord.alias.ilike(pattern)
        )
    if policy == "__default__":
        stmt = stmt.where(MailboxRecord.current_policy.is_(None))
    elif policy == "__assigned__":
        stmt = stmt.where(MailboxRecord.current_policy.is_not(None))
    elif policy:
        stmt = stmt.where(MailboxRecord.current_policy == policy)
    if dotted_only:
        stmt = stmt.where(MailboxRecord.primary_smtp_address.like("%.%@%"))
    return stmt


@app.get("/mailboxes", response_class=HTMLResponse)
def mailboxes_page(
    request: Request,
    q: str = "",
    policy: str = "",
    dotted: bool = False,
    page: int = 1,
    db: Session = Depends(get_db),
):
    user = require_user(request, db)
    page = max(1, page)
    per_page = 100
    filtered = mailbox_filter_statement(q, policy, dotted)
    total = db.scalar(select(func.count()).select_from(filtered.subquery())) or 0
    records = db.scalars(
        filtered.order_by(MailboxRecord.primary_smtp_address)
        .offset((page - 1) * per_page)
        .limit(per_page)
    ).all()
    policies = db.scalars(
        select(ThrottlingPolicyRecord)
        .where(ThrottlingPolicyRecord.active.is_(True))
        .order_by(ThrottlingPolicyRecord.scope, ThrottlingPolicyRecord.name)
    ).all()
    policy_counts = {
        (name or "__default__"): count
        for name, count in db.execute(
            select(MailboxRecord.current_policy, func.count())
            .where(MailboxRecord.active.is_(True))
            .group_by(MailboxRecord.current_policy)
        ).all()
    }
    assigned_policy_count = sum(
        count
        for name, count in policy_counts.items()
        if name != "__default__"
    )
    latest_sync = db.scalar(select(func.max(MailboxRecord.last_synced_at)))
    context = base_context(request, db, "Mailbox policies", user)
    context.update(
        {
            "mailboxes": records,
            "policies": policies,
            "policy_counts": policy_counts,
            "assigned_policy_count": assigned_policy_count,
            "total": total,
            "page": page,
            "pages": max(1, (total + per_page - 1) // per_page),
            "filters": {"q": q, "policy": policy, "dotted": dotted},
            "mailbox_node_id": settings.mailbox_node_id,
            "mailbox_node_ready": db.get(Node, settings.mailbox_node_id) is not None,
            "latest_sync": latest_sync,
        }
    )
    return templates.TemplateResponse("mailboxes.html", context)


@app.post("/mailboxes/sync")
def mailbox_sync(request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    node = db.get(Node, settings.mailbox_node_id)
    if not node or not node.enabled:
        raise HTTPException(409, "Mailbox management node is not configured or enabled")
    cmd = queue_command(db, node.id, "SyncMailboxInventory", {}, user.username)
    audit(db, request, user.username, "mailbox_sync_queued", node.id, {"command_id": cmd.id})
    db.commit()
    return RedirectResponse("/mailboxes", status_code=303)


@app.post("/mailboxes/apply")
def mailbox_policy_apply(
    request: Request,
    csrf: str = Form(...),
    policy_name: str = Form(...),
    mailbox_ids: list[int] = Form(default=[]),
    apply_scope: str = Form("selected"),
    q: str = Form(""),
    current_policy: str = Form(""),
    dotted: bool = Form(False),
    confirmation: str = Form(""),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    node = db.get(Node, settings.mailbox_node_id)
    if not node or not node.enabled:
        raise HTTPException(409, "Mailbox management node is not configured or enabled")
    target_policy = None if policy_name == "__default__" else policy_name.strip()
    if target_policy:
        policy_record = db.get(ThrottlingPolicyRecord, target_policy)
        if not policy_record or not policy_record.active:
            raise HTTPException(400, "Unknown throttling policy")
    if apply_scope == "filtered":
        if confirmation != "APPLY FILTERED":
            raise HTTPException(400, "Type APPLY FILTERED to confirm a filtered bulk change")
        targets = db.scalars(mailbox_filter_statement(q, current_policy, dotted)).all()
    else:
        if not mailbox_ids:
            raise HTTPException(400, "Select at least one mailbox")
        targets = db.scalars(
            select(MailboxRecord).where(MailboxRecord.id.in_(mailbox_ids), MailboxRecord.active.is_(True))
        ).all()
    if not targets:
        raise HTTPException(400, "No mailboxes matched the request")
    command_ids: list[str] = []
    for offset in range(0, len(targets), 100):
        batch = targets[offset : offset + 100]
        assignments = []
        cmd = queue_command(
            db,
            node.id,
            "SetMailboxPolicies",
            {
                "assignments": [
                    {"primary_smtp_address": row.primary_smtp_address, "policy_name": target_policy}
                    for row in batch
                ]
            },
            user.username,
        )
        command_ids.append(cmd.id)
        for row in batch:
            row.previous_policy = row.current_policy
            row.desired_policy = target_policy
            row.last_command_id = cmd.id
            row.last_error = None
            assignments.append(row.primary_smtp_address)
    audit(
        db,
        request,
        user.username,
        "mailbox_policy_queued",
        target_policy or "Organization default",
        {"mailbox_count": len(targets), "command_ids": command_ids, "scope": apply_scope},
    )
    db.commit()
    return RedirectResponse("/mailboxes", status_code=303)


@app.post("/mailboxes/policies")
def throttling_policy_upsert(
    request: Request,
    csrf: str = Form(...),
    name: str = Form(...),
    recipient_rate_limit: str = Form(...),
    confirmation: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    name = name.strip()
    if not name or len(name) > 256:
        raise HTTPException(400, "Invalid policy name")
    existing = db.get(ThrottlingPolicyRecord, name)
    if existing and existing.scope.lower() != "regular":
        raise HTTPException(400, "Only Regular policies can be changed from this page")
    limit = recipient_rate_limit.strip()
    if limit.lower() == "unlimited":
        normalized_limit: int | str = "Unlimited"
    else:
        try:
            normalized_limit = int(limit)
        except ValueError as exc:
            raise HTTPException(400, "Recipient rate limit must be a number or Unlimited") from exc
        if normalized_limit < 1 or normalized_limit > 100000:
            raise HTTPException(400, "Recipient rate limit must be between 1 and 100000")
    if confirmation != name:
        raise HTTPException(400, "Type the exact policy name to confirm")
    node = db.get(Node, settings.mailbox_node_id)
    if not node or not node.enabled:
        raise HTTPException(409, "Mailbox management node is not configured or enabled")
    cmd = queue_command(
        db,
        node.id,
        "UpsertThrottlingPolicy",
        {"name": name, "recipient_rate_limit": normalized_limit},
        user.username,
    )
    audit(db, request, user.username, "throttling_policy_upsert_queued", name, {"limit": normalized_limit, "command_id": cmd.id})
    db.commit()
    return RedirectResponse("/mailboxes", status_code=303)


@app.get("/outbound", response_class=HTMLResponse)
def outbound_page(
    request: Request,
    q: str = "",
    risk: str = "",
    sender: str = "",
    db: Session = Depends(get_db),
):
    user = require_user(request, db)
    stmt = select(OutboundUsageRecord)
    if q.strip():
        stmt = stmt.where(OutboundUsageRecord.sender.ilike(f"%{q.strip()}%"))
    if risk in {"critical", "high", "medium", "low", "bulk", "expected"}:
        stmt = stmt.where(OutboundUsageRecord.risk_level == risk)
    records = db.scalars(
        stmt.order_by(
            desc(OutboundUsageRecord.recipients_10m),
            desc(OutboundUsageRecord.recipients_24h),
        ).limit(1000)
    ).all()
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "expected": 4, "bulk": 5}
    records = sorted(
        records,
        key=lambda row: (
            risk_order.get(row.risk_level, 9),
            -row.recipients_10m,
            -row.recipients_24h,
        ),
    )
    selected_sender = sender.strip().lower()
    selected = next((row for row in records if row.sender == selected_sender), None)
    if selected is None and selected_sender:
        selected = db.get(OutboundUsageRecord, selected_sender)
    if selected is None and records:
        selected = records[0]
    latest_run = db.scalar(select(OutboundScanRun).order_by(desc(OutboundScanRun.started_at)).limit(1))
    incidents = db.scalars(select(MailboxIncident).order_by(desc(MailboxIncident.created_at)).limit(100)).all()
    active_incidents = [
        incident
        for incident in incidents
        if incident.status in {
            IncidentStatus.pending,
            IncidentStatus.quarantined,
            IncidentStatus.partial,
        }
    ]
    response_commands = db.scalars(
        select(Command)
        .where(Command.status.in_([CommandStatus.pending, CommandStatus.claimed]))
        .order_by(desc(Command.created_at))
        .limit(5)
    ).all()
    recent_audit = db.scalars(
        select(AuditLog).order_by(desc(AuditLog.timestamp_utc)).limit(8)
    ).all()
    latest_edge_snapshot = db.scalar(
        select(Snapshot)
        .where(Snapshot.node_id == settings.bootstrap_node_id)
        .order_by(desc(Snapshot.captured_at))
        .limit(1)
    )
    outbound_blocked_ips = _snapshot_blocked_ips(latest_edge_snapshot)
    trusted_ip_entries = db.scalars(
        select(AllowlistEntry)
        .where(AllowlistEntry.entry_type == "ip")
        .order_by(desc(AllowlistEntry.created_at))
        .limit(5)
    ).all()
    trusted_ip_map = {entry.value: entry for entry in trusted_ip_entries}
    recent_spoof_sources = db.scalars(
        select(InboundSpoofSource)
        .where(InboundSpoofSource.active.is_(True))
        .order_by(
            desc(InboundSpoofSource.accepted_messages),
            desc(InboundSpoofSource.last_seen_at),
        )
        .limit(4)
    ).all()
    protection_ips = [source.source_ip for source in recent_spoof_sources]
    for entry in trusted_ip_entries:
        if entry.value not in protection_ips:
            protection_ips.append(entry.value)
        if len(protection_ips) >= 4:
            break
    protection_geo = {
        row.source_ip: row
        for row in (
            db.scalars(select(IpGeoRecord).where(IpGeoRecord.source_ip.in_(protection_ips))).all()
            if protection_ips
            else []
        )
    }
    protection_sources = []
    for source_ip in protection_ips[:4]:
        geo = protection_geo.get(source_ip)
        if source_ip in trusted_ip_map:
            source_state = "trusted"
        elif source_ip in outbound_blocked_ips:
            source_state = "blocked"
        else:
            source_state = "open"
        protection_sources.append(
            {
                "ip": source_ip,
                "state": source_state,
                "country": geo.country_name if geo and geo.lookup_status == "success" else "Unknown country",
                "country_flag": _country_flag(geo.country_code if geo else None),
            }
        )
    telegram_alerts = db.scalars(
        select(TelegramAlert).order_by(desc(TelegramAlert.created_at)).limit(100)
    ).all()
    profiles = db.scalars(
        select(OutboundSenderProfile)
        .where(OutboundSenderProfile.enabled.is_(True))
        .order_by(OutboundSenderProfile.sender)
    ).all()
    profiles_by_sender = {profile.sender: profile for profile in profiles}
    bulk_profiles = [profile for profile in profiles if profile.profile_type == "bulk"]
    bulk_senders = [profile.sender for profile in bulk_profiles]
    bulk_usage = {
        record.sender: record
        for record in (
            db.scalars(select(OutboundUsageRecord).where(OutboundUsageRecord.sender.in_(bulk_senders))).all()
            if bulk_senders
            else []
        )
    }
    counts = {
        level: db.scalar(select(func.count()).select_from(OutboundUsageRecord).where(OutboundUsageRecord.risk_level == level)) or 0
        for level in ["critical", "high", "medium", "low", "bulk", "expected"]
    }
    selected_mailbox = None
    selected_incident = None
    selected_profile = None
    evidence = []
    attachment_items: list[dict[str, Any]] = []
    recipient_counts: dict[str, int] = {}
    domain_counts: dict[str, int] = {}
    chart_data: list[dict[str, Any]] = []
    attachment_summary = {"present": 0, "none": 0, "unavailable": 0, "files": 0}
    selected_state = {
        "ews": "Not collected",
        "last_authentication": "Not collected",
        "transport_source_ip": "Not available",
    }
    if selected:
        selected_mailbox = db.scalar(
            select(MailboxRecord).where(MailboxRecord.primary_smtp_address == selected.sender)
        )
        selected_incident = db.scalar(
            select(MailboxIncident)
            .where(MailboxIncident.primary_smtp_address == selected.sender)
            .order_by(desc(MailboxIncident.created_at))
            .limit(1)
        )
        selected_profile = profiles_by_sender.get(selected.sender)
        evidence = db.scalars(
            select(OutboundEvidenceRecord)
            .where(OutboundEvidenceRecord.sender == selected.sender)
            .order_by(desc(OutboundEvidenceRecord.event_timestamp))
            .limit(100)
        ).all()
        for item in evidence:
            status = item.attachment_status if item.attachment_status in attachment_summary else "unavailable"
            attachment_summary[status] += 1
            for attachment in item.attachments or []:
                normalized = dict(attachment)
                normalized["event_timestamp"] = item.event_timestamp
                normalized["subject"] = item.subject
                normalized["message_id"] = item.message_id
                extension = str(normalized.get("extension") or "").lower().lstrip(".")
                normalized["review_required"] = extension in {
                    "ade", "adp", "apk", "app", "bat", "cmd", "com", "cpl", "exe", "hta",
                    "ins", "iso", "jar", "js", "jse", "lnk", "msc", "msi", "msp", "mst",
                    "pif", "ps1", "rar", "reg", "scr", "sct", "shb", "sys", "vb", "vbe",
                    "vbs", "vhd", "vhdx", "wsc", "wsf", "wsh", "zip",
                }
                attachment_items.append(normalized)
                attachment_summary["files"] += 1
            for recipient in item.recipients or []:
                address = str(recipient).lower()
                recipient_counts[address] = recipient_counts.get(address, 0) + 1
                if "@" in address:
                    domain = address.rsplit("@", 1)[-1]
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
        latest_source = next((item.transport_source_ip for item in evidence if item.transport_source_ip), None)
        if latest_source:
            selected_state["transport_source_ip"] = latest_source
        if selected_incident and selected_incident.status in {
            IncidentStatus.quarantined,
            IncidentStatus.partial,
        }:
            selected_state["ews"] = "Disabled by quarantine"
        elif selected_incident and selected_incident.previous_ews_enabled is not None:
            selected_state["ews"] = "Enabled" if selected_incident.previous_ews_enabled else "Disabled"
        chart_anchor = selected.scanned_at.replace(minute=0, second=0, microsecond=0)
        chart_start = chart_anchor - timedelta(hours=23)
        hourly_rows = db.scalars(
            select(OutboundHourlyRecord)
            .where(
                OutboundHourlyRecord.sender == selected.sender,
                OutboundHourlyRecord.hour_start >= chart_start,
                OutboundHourlyRecord.hour_start <= chart_anchor,
            )
            .order_by(OutboundHourlyRecord.hour_start)
        ).all()
        hourly_map = {
            row.hour_start.replace(minute=0, second=0, microsecond=0): row
            for row in hourly_rows
        }
        values = [row.recipients for row in hourly_rows]
        baseline = float(statistics.median(values)) if values else 0.0
        anomaly_floor = max(10, int(baseline * 3))
        for offset in range(24):
            bucket = chart_start + timedelta(hours=offset)
            hourly = hourly_map.get(bucket)
            recipients = hourly.recipients if hourly else 0
            chart_data.append(
                {
                    "label": bucket.strftime("%H:%M"),
                    "timestamp": bucket.isoformat(),
                    "recipients": recipients,
                    "messages": hourly.messages if hourly else 0,
                    "anomaly": recipients >= anomaly_floor and recipients > baseline,
                }
            )
    context = base_context(request, db, "Outbound triage", user)
    context.update(
        {
            "records": records,
            "selected": selected,
            "selected_mailbox": selected_mailbox,
            "selected_incident": selected_incident,
            "selected_profile": selected_profile,
            "selected_state": selected_state,
            "evidence": evidence,
            "attachment_items": attachment_items,
            "attachment_summary": attachment_summary,
            "top_recipients": sorted(recipient_counts.items(), key=lambda item: (-item[1], item[0]))[:50],
            "top_domains": sorted(domain_counts.items(), key=lambda item: (-item[1], item[0]))[:50],
            "chart_data": chart_data,
            "latest_run": latest_run,
            "incidents": incidents,
            "active_incidents": active_incidents,
            "response_commands": response_commands,
            "recent_audit": recent_audit,
            "protection_sources": protection_sources,
            "telegram_alerts": telegram_alerts,
            "telegram": telegram_configuration(),
            "bulk_profiles": bulk_profiles,
            "bulk_usage": bulk_usage,
            "counts": counts,
            "profiles_by_sender": profiles_by_sender,
            "filters": {"q": q, "risk": risk, "sender": selected.sender if selected else ""},
            "thresholds": {
                "alert_5m": settings.outbound_alert_recipients_5m,
                "critical_10m": settings.outbound_critical_recipients_10m,
                "daily_warning": settings.outbound_daily_warning,
                "daily_critical": settings.outbound_daily_critical,
            },
        }
    )
    return templates.TemplateResponse("outbound.html", context)


@app.post("/outbound/bulk-profiles")
def outbound_bulk_profile_add(
    request: Request,
    csrf: str = Form(...),
    sender: str = Form(...),
    note: str = Form(""),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    address = sender.strip().lower()
    if not address or "@" not in address or address.rsplit("@", 1)[-1] not in {
        value.strip().lower() for value in settings.organization_domains.split(",") if value.strip()
    }:
        raise HTTPException(400, "Bulk sender must be an internal SMTP address")
    mailbox = db.scalar(
        select(MailboxRecord).where(
            MailboxRecord.primary_smtp_address == address,
            MailboxRecord.active.is_(True),
        )
    )
    if not mailbox:
        raise HTTPException(404, "Mailbox is not present in the synced inventory")
    profile = db.get(OutboundSenderProfile, address)
    if profile:
        profile.profile_type = "bulk"
        profile.note = note.strip()[:1000] or profile.note
        profile.enabled = True
        profile.updated_at = utcnow()
    else:
        db.add(
            OutboundSenderProfile(
                sender=address,
                profile_type="bulk",
                note=note.strip()[:1000] or None,
                created_by=user.username,
            )
        )
    audit(db, request, user.username, "outbound_bulk_profile_added", address, {"note": note.strip()[:1000]})
    db.commit()
    run_outbound_scan()
    return RedirectResponse("/outbound", status_code=303)


@app.post("/outbound/bulk-profiles/remove")
def outbound_bulk_profile_remove(
    request: Request,
    csrf: str = Form(...),
    sender: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    address = sender.strip().lower()
    profile = db.get(OutboundSenderProfile, address)
    if not profile:
        raise HTTPException(404, "Bulk sender profile not found")
    audit(db, request, user.username, "outbound_bulk_profile_removed", address)
    db.delete(profile)
    db.commit()
    run_outbound_scan()
    return RedirectResponse("/outbound", status_code=303)


@app.post("/outbound/expected-profiles")
def outbound_expected_profile_add(
    request: Request,
    csrf: str = Form(...),
    sender: str = Form(...),
    note: str = Form("Expected business activity"),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    address = sender.strip().lower()
    mailbox = db.scalar(
        select(MailboxRecord).where(
            MailboxRecord.primary_smtp_address == address,
            MailboxRecord.active.is_(True),
        )
    )
    if not mailbox:
        raise HTTPException(404, "Mailbox is not present in the synced inventory")
    profile = db.get(OutboundSenderProfile, address)
    if profile:
        profile.profile_type = "expected"
        profile.note = note.strip()[:1000] or "Expected business activity"
        profile.enabled = True
        profile.updated_at = utcnow()
    else:
        db.add(
            OutboundSenderProfile(
                sender=address,
                profile_type="expected",
                note=note.strip()[:1000] or "Expected business activity",
                created_by=user.username,
            )
        )
    audit(db, request, user.username, "outbound_expected_profile_added", address, {"note": note.strip()[:1000]})
    db.commit()
    run_outbound_scan()
    return RedirectResponse(f"/outbound?sender={address}", status_code=303)


@app.post("/outbound/expected-profiles/remove")
def outbound_expected_profile_remove(
    request: Request,
    csrf: str = Form(...),
    sender: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    address = sender.strip().lower()
    profile = db.get(OutboundSenderProfile, address)
    if not profile or profile.profile_type != "expected":
        raise HTTPException(404, "Expected sender profile not found")
    audit(db, request, user.username, "outbound_expected_profile_removed", address)
    db.delete(profile)
    db.commit()
    run_outbound_scan()
    return RedirectResponse(f"/outbound?sender={address}", status_code=303)


@app.post("/outbound/scan")
def outbound_scan(request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    result = run_outbound_scan()
    audit(db, request, user.username, "outbound_scan", details=result)
    db.commit()
    return RedirectResponse("/outbound", status_code=303)


@app.post("/outbound/telegram/test")
def telegram_test(request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    try:
        message_id = send_telegram_test(user.username)
    except Exception as exc:
        audit(db, request, user.username, "telegram_test_failed", details={"error": str(exc)[:1000]})
        db.commit()
        raise HTTPException(502, f"Telegram test failed: {exc}") from exc
    audit(db, request, user.username, "telegram_test_sent", details={"message_id": message_id})
    db.commit()
    return RedirectResponse("/outbound", status_code=303)


@app.post("/incidents/quarantine")
def incident_quarantine(
    request: Request,
    csrf: str = Form(...),
    primary_smtp_address: str = Form(...),
    reason: str = Form(...),
    confirmation: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    address = primary_smtp_address.strip().lower()
    if confirmation.strip().lower() != address:
        raise HTTPException(400, "Type the exact email address to confirm quarantine")
    try:
        incident = queue_mailbox_quarantine(db, address, reason, user.username)
    except IncidentQueueError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    audit(
        db,
        request,
        user.username,
        "incident_quarantine_queued",
        address,
        {
            "incident_id": incident.id,
            "mailbox_command_id": incident.mailbox_command_id,
            "edge_command_id": incident.edge_command_id,
        },
    )
    db.commit()
    return RedirectResponse("/outbound", status_code=303)


@app.post("/incidents/{incident_id}/release")
def incident_release(
    incident_id: int,
    request: Request,
    csrf: str = Form(...),
    confirmation: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = require_admin(request, db)
    incident = db.get(MailboxIncident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    if incident.status not in {IncidentStatus.quarantined, IncidentStatus.partial, IncidentStatus.failed}:
        raise HTTPException(409, "Incident is not releasable")
    if confirmation.strip().lower() != incident.primary_smtp_address:
        raise HTTPException(400, "Type the exact email address to confirm release")
    mailbox_node = db.get(Node, settings.mailbox_node_id)
    if not mailbox_node:
        raise HTTPException(409, "Mailbox management node is not configured")
    cmd = queue_command(
        db,
        mailbox_node.id,
        "ReleaseMailbox",
        {
            "primary_smtp_address": incident.primary_smtp_address,
            "blocked_group": settings.blocked_outbound_group,
            "restore_ews_enabled": incident.previous_ews_enabled,
            "incident_id": incident.id,
        },
        user.username,
    )
    incident.mailbox_command_id = cmd.id
    incident.status = IncidentStatus.pending
    incident.released_by = user.username
    incident.last_error = None
    audit(db, request, user.username, "incident_release_queued", incident.primary_smtp_address, {"incident_id": incident.id, "command_id": cmd.id})
    db.commit()
    return RedirectResponse("/outbound", status_code=303)


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    logs = db.scalars(select(AuditLog).order_by(desc(AuditLog.timestamp_utc)).limit(1000)).all()
    context = base_context(request, db, "Audit log", user)
    context["logs"] = logs
    return templates.TemplateResponse("audit.html", context)


@app.get("/nodes", response_class=HTMLResponse)
def nodes_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    context = base_context(request, db, "Nodes", user)
    context["nodes"] = nodes
    return templates.TemplateResponse("nodes.html", context)


@app.post("/api/agent/v1/heartbeat")
async def agent_heartbeat(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    node = verify_agent_request(request, body, db)
    payload = json.loads(body or b"{}")
    node.last_seen_at = utcnow()
    node.last_ip = request.client.host if request.client else None
    node.last_heartbeat = payload
    db.commit()
    return {"ok": True, "server_time_utc": utcnow().isoformat()}


@app.post("/api/agent/v1/events")
async def agent_events(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    node = verify_agent_request(request, body, db)
    payload = json.loads(body or b"{}")
    rows = payload.get("events", [])
    inserted = 0
    for raw in rows[:2000]:
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        event_hash = hashlib.sha256(canonical).hexdigest()
        if db.scalar(select(Event.id).where(Event.event_hash == event_hash)):
            continue
        ts_raw = raw.get("TimestampUtc") or raw.get("timestamp_utc")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")) if ts_raw else utcnow()
        except ValueError:
            ts = utcnow()
        event = Event(
            event_hash=event_hash,
            node_id=node.id,
            timestamp_utc=ts,
            script_version=raw.get("ScriptVersion"),
            mode=raw.get("Mode"),
            action=str(raw.get("Action", "Unknown")),
            client_ip=raw.get("ClientIp"),
            sender_domain=raw.get("SenderDomain"),
            message_count=raw.get("MessageCount"),
            unique_recipient_count=raw.get("UniqueRecipientCount"),
            average_scl=raw.get("AverageScl"),
            scl_evidence_ratio=raw.get("SclEvidenceRatio"),
            consecutive_hits=raw.get("ConsecutiveHits"),
            raw=raw,
        )
        db.add(event)
        db.flush()
        inserted += 1
        if event.action in {"Candidate", "WouldBlock", "Blocked"} and event.client_ip and event.sender_domain:
            candidate = db.scalar(
                select(Candidate).where(
                    Candidate.node_id == node.id,
                    Candidate.client_ip == event.client_ip,
                    Candidate.sender_domain == event.sender_domain,
                )
            )
            if not candidate:
                candidate = Candidate(node_id=node.id, client_ip=event.client_ip, sender_domain=event.sender_domain)
                db.add(candidate)
                db.flush()
            candidate.last_seen_at = event.timestamp_utc
            candidate.message_count = event.message_count or candidate.message_count
            candidate.unique_recipient_count = event.unique_recipient_count or candidate.unique_recipient_count
            candidate.average_scl = event.average_scl
            candidate.scl_evidence_ratio = event.scl_evidence_ratio
            candidate.consecutive_hits = event.consecutive_hits or candidate.consecutive_hits
            candidate.top_subject = raw.get("TopSubject") or candidate.top_subject
            candidate.last_event_id = event.id
            if event.action == "Blocked":
                candidate.status = CandidateStatus.blocked
    node.last_seen_at = utcnow()
    db.commit()
    return {"ok": True, "inserted": inserted}


@app.post("/api/agent/v1/snapshot")
async def agent_snapshot(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    node = verify_agent_request(request, body, db)
    payload = json.loads(body or b"{}")
    allow_ips = [x.value for x in db.scalars(select(AllowlistEntry).where(AllowlistEntry.entry_type == "ip")).all()]
    allow_domains = [x.value for x in db.scalars(select(AllowlistEntry).where(AllowlistEntry.entry_type == "domain")).all()]
    snapshot = Snapshot(
        node_id=node.id,
        active_ip_blocks=payload.get("active_ip_blocks", []),
        blocked_domains=payload.get("blocked_domains", []),
        blocked_domains_and_subdomains=payload.get("blocked_domains_and_subdomains", []),
        allowlisted_ips=allow_ips,
        allowlisted_domains=allow_domains,
        raw=payload,
    )
    db.add(snapshot)
    node.last_seen_at = utcnow()
    db.commit()
    return {"ok": True, "allowlisted_ips": allow_ips, "allowlisted_domains": allow_domains}


@app.post("/api/agent/v1/mailboxes/snapshot")
async def agent_mailbox_snapshot(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    node = verify_agent_request(request, body, db)
    if node.id != settings.mailbox_node_id:
        raise HTTPException(403, "This node cannot submit mailbox inventory")
    payload = json.loads(body or b"{}")
    mailbox_rows = payload.get("mailboxes", [])
    policy_rows = payload.get("policies", [])
    if not isinstance(mailbox_rows, list) or len(mailbox_rows) > 20000:
        raise HTTPException(400, "Invalid mailbox inventory")
    if not isinstance(policy_rows, list) or len(policy_rows) > 1000:
        raise HTTPException(400, "Invalid policy inventory")
    now = utcnow()
    existing_mailboxes = {
        row.primary_smtp_address.lower(): row
        for row in db.scalars(select(MailboxRecord)).all()
    }
    seen_mailboxes: set[str] = set()
    for item in mailbox_rows:
        address = str(item.get("primary_smtp_address", "")).strip().lower()
        if not address or "@" not in address or len(address) > 320:
            continue
        seen_mailboxes.add(address)
        row = existing_mailboxes.get(address)
        if not row:
            row = MailboxRecord(primary_smtp_address=address)
            db.add(row)
            existing_mailboxes[address] = row
        row.display_name = str(item.get("display_name") or "")[:512]
        row.alias = str(item.get("alias") or "")[:256]
        row.sam_account_name = str(item.get("sam_account_name") or "")[:256] or None
        row.recipient_type = str(item.get("recipient_type") or "UserMailbox")[:128]
        row.organizational_unit = str(item.get("organizational_unit") or "")[:4000] or None
        row.current_policy = str(item.get("throttling_policy") or "")[:256] or None
        row.active = True
        row.last_synced_at = now
        if row.desired_policy == row.current_policy:
            row.last_error = None
    for address, row in existing_mailboxes.items():
        if address not in seen_mailboxes:
            row.active = False
    existing_policies = {row.name: row for row in db.scalars(select(ThrottlingPolicyRecord)).all()}
    seen_policies: set[str] = set()
    for item in policy_rows:
        name = str(item.get("name") or "").strip()[:256]
        if not name:
            continue
        seen_policies.add(name)
        row = existing_policies.get(name)
        if not row:
            row = ThrottlingPolicyRecord(name=name, scope="Regular")
            db.add(row)
            existing_policies[name] = row
        row.scope = str(item.get("scope") or "Regular")[:64]
        row.recipient_rate_limit = str(item.get("recipient_rate_limit") or "Unlimited")[:64]
        row.active = True
        row.last_synced_at = now
    for name, row in existing_policies.items():
        if name not in seen_policies:
            row.active = False
    node.last_seen_at = now
    audit(db, None, f"agent:{node.id}", "mailbox_inventory_synced", node.id, {"mailboxes": len(seen_mailboxes), "policies": len(seen_policies)})
    db.commit()
    return {"ok": True, "mailboxes": len(seen_mailboxes), "policies": len(seen_policies)}


@app.post("/api/agent/v1/outbound/attachments")
async def agent_outbound_attachments(request: Request, db: Session = Depends(get_db)):
    """Enrich transport evidence with attachment metadata; message bodies are never accepted."""
    body = await request.body()
    node = verify_agent_request(request, body, db)
    if node.id != settings.mailbox_node_id:
        raise HTTPException(403, "This node cannot submit attachment metadata")
    payload = json.loads(body or b"{}")
    items = payload.get("items", [])
    if not isinstance(items, list) or len(items) > 1000:
        raise HTTPException(400, "Invalid attachment metadata batch")
    matched = 0
    files_seen = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        sender = str(item.get("sender") or "").strip().lower()
        message_id = str(item.get("message_id") or "").strip().lower() or None
        network_message_id = str(item.get("network_message_id") or "").strip() or None
        event_key = str(item.get("event_key") or "").strip().lower() or None
        if "@" not in sender or (not event_key and not message_id and not network_message_id):
            continue
        raw_attachments = item.get("attachments", [])
        if not isinstance(raw_attachments, list) or len(raw_attachments) > 50:
            continue
        attachments: list[dict[str, Any]] = []
        for raw_attachment in raw_attachments:
            if not isinstance(raw_attachment, dict):
                continue
            filename = str(raw_attachment.get("filename") or "").replace("\\", "/").rsplit("/", 1)[-1][:512]
            if not filename:
                continue
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            try:
                size_bytes = max(0, int(raw_attachment.get("size_bytes") or 0))
            except (TypeError, ValueError):
                size_bytes = 0
            attachments.append(
                {
                    "filename": filename,
                    "extension": extension[:32],
                    "content_type": str(raw_attachment.get("content_type") or "")[:255] or None,
                    "size_bytes": size_bytes,
                }
            )
        stmt = select(OutboundEvidenceRecord).where(OutboundEvidenceRecord.sender == sender)
        if event_key:
            stmt = stmt.where(OutboundEvidenceRecord.event_key == event_key)
        elif message_id and network_message_id:
            stmt = stmt.where(
                (OutboundEvidenceRecord.message_id == message_id)
                | (OutboundEvidenceRecord.network_message_id == network_message_id)
            )
        elif message_id:
            stmt = stmt.where(OutboundEvidenceRecord.message_id == message_id)
        else:
            stmt = stmt.where(OutboundEvidenceRecord.network_message_id == network_message_id)
        evidence_rows = db.scalars(stmt.limit(20)).all()
        for evidence in evidence_rows:
            evidence.attachments = attachments
            evidence.attachment_status = "present" if attachments else "none"
            matched += 1
        files_seen += len(attachments)
    node.last_seen_at = utcnow()
    audit(
        db,
        None,
        f"agent:{node.id}",
        "outbound_attachment_metadata_synced",
        node.id,
        {"items": len(items), "matched_evidence": matched, "files": files_seen},
    )
    db.commit()
    return {"ok": True, "items": len(items), "matched_evidence": matched, "files": files_seen}


@app.get("/api/agent/v1/commands")
async def agent_get_commands(request: Request, db: Session = Depends(get_db)):
    body = b""
    node = verify_agent_request(request, body, db)
    now = utcnow()
    stale_claims = db.scalars(
        select(Command).where(
            Command.node_id == node.id,
            Command.status == CommandStatus.claimed,
            Command.claimed_at < now - timedelta(minutes=10),
            Command.expires_at >= now,
        )
    ).all()
    for cmd in stale_claims:
        cmd.status = CommandStatus.pending
        cmd.claimed_at = None
    expired = db.scalars(
        select(Command).where(Command.node_id == node.id, Command.status.in_([CommandStatus.pending, CommandStatus.claimed]), Command.expires_at < now)
    ).all()
    for cmd in expired:
        cmd.status = CommandStatus.expired
    commands = db.scalars(
        select(Command)
        .where(Command.node_id == node.id, Command.status == CommandStatus.pending, Command.expires_at >= now)
        .order_by(Command.created_at)
        .limit(20)
        .with_for_update(skip_locked=True)
    ).all()
    result = []
    for cmd in commands:
        cmd.status = CommandStatus.claimed
        cmd.claimed_at = now
        result.append({"id": cmd.id, "type": cmd.command_type, "payload": cmd.payload, "expires_at": cmd.expires_at.isoformat()})
    node.last_seen_at = now
    db.commit()
    return {"commands": result}


@app.post("/api/agent/v1/commands/{command_id}/result")
async def agent_command_result(command_id: str, request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    node = verify_agent_request(request, body, db)
    payload = json.loads(body or b"{}")
    cmd = db.get(Command, command_id)
    if not cmd or cmd.node_id != node.id:
        raise HTTPException(404, "Command not found")
    success = bool(payload.get("success"))
    cmd.status = CommandStatus.succeeded if success else CommandStatus.failed
    cmd.finished_at = utcnow()
    cmd.result = payload.get("result")
    cmd.error = payload.get("error")
    audit(db, None, f"agent:{node.id}", "command_result", cmd.id, {"success": success, "type": cmd.command_type})
    if success and cmd.command_type == "BlockIp":
        candidate_id = cmd.payload.get("source_candidate_id")
        if candidate_id:
            candidate = db.get(Candidate, int(candidate_id))
            if candidate:
                candidate.status = CandidateStatus.blocked
    if success and cmd.command_type in {"BlockDomainExact", "BlockDomainAndSubdomains"}:
        reputation_id = cmd.payload.get("source_reputation_id")
        if reputation_id:
            record = db.get(ReputationRecord, int(reputation_id))
            if record:
                record.status = ReputationStatus.blocked
    if cmd.command_type == "SetMailboxPolicies":
        result_rows = (payload.get("result") or {}).get("results", [])
        if not result_rows and not success:
            for assignment in cmd.payload.get("assignments", []):
                address = str(assignment.get("primary_smtp_address") or "").lower()
                mailbox = db.scalar(select(MailboxRecord).where(MailboxRecord.primary_smtp_address == address))
                if mailbox:
                    mailbox.last_command_id = cmd.id
                    mailbox.last_error = str(payload.get("error") or "Mailbox policy command failed")[:4000]
        for result_row in result_rows:
            address = str(result_row.get("primary_smtp_address") or "").lower()
            mailbox = db.scalar(select(MailboxRecord).where(MailboxRecord.primary_smtp_address == address))
            if not mailbox:
                continue
            mailbox.last_command_id = cmd.id
            if result_row.get("success"):
                mailbox.current_policy = str(result_row.get("policy_name") or "") or None
                mailbox.desired_policy = mailbox.current_policy
                mailbox.last_error = None
            else:
                mailbox.last_error = str(result_row.get("error") or payload.get("error") or "Unknown error")[:4000]
    if cmd.command_type in {"QuarantineMailbox", "ReleaseMailbox", "PurgeSenderQueue"}:
        incident = db.scalar(
            select(MailboxIncident).where(
                (MailboxIncident.mailbox_command_id == cmd.id) | (MailboxIncident.edge_command_id == cmd.id)
            )
        )
        if incident:
            if cmd.command_type == "ReleaseMailbox":
                if success:
                    incident.status = IncidentStatus.released
                    incident.released_at = utcnow()
                    incident.last_error = None
                else:
                    incident.status = IncidentStatus.failed
                    incident.last_error = str(payload.get("error") or "Release failed")[:4000]
            else:
                if cmd.command_type == "QuarantineMailbox" and success:
                    previous_ews = (payload.get("result") or {}).get("previous_ews_enabled")
                    if previous_ews is not None:
                        incident.previous_ews_enabled = bool(previous_ews)
                mailbox_command = db.get(Command, incident.mailbox_command_id) if incident.mailbox_command_id else None
                edge_command = db.get(Command, incident.edge_command_id) if incident.edge_command_id else None
                statuses = {x.status for x in [mailbox_command, edge_command] if x}
                if statuses and statuses <= {CommandStatus.succeeded}:
                    incident.status = IncidentStatus.quarantined
                    incident.quarantined_at = utcnow()
                    incident.last_error = None
                elif CommandStatus.failed in statuses:
                    incident.status = IncidentStatus.partial if CommandStatus.succeeded in statuses else IncidentStatus.failed
                    errors = [x.error for x in [mailbox_command, edge_command] if x and x.error]
                    incident.last_error = " | ".join(errors)[:4000] or "Incident command failed"
    db.commit()
    return {"ok": True}


@app.get("/api/agent/v1/allowlist")
async def agent_allowlist(request: Request, db: Session = Depends(get_db)):
    node = verify_agent_request(request, b"", db)
    ips = [x.value for x in db.scalars(select(AllowlistEntry).where(AllowlistEntry.entry_type == "ip")).all()]
    domains = [x.value for x in db.scalars(select(AllowlistEntry).where(AllowlistEntry.entry_type == "domain")).all()]
    node.last_seen_at = utcnow()
    db.commit()
    return {"ips": ips, "domains": domains}
