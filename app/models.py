from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    viewer = "viewer"
    admin = "admin"


class CommandStatus(str, enum.Enum):
    pending = "pending"
    claimed = "claimed"
    succeeded = "succeeded"
    failed = "failed"
    expired = "expired"
    cancelled = "cancelled"


class CandidateStatus(str, enum.Enum):
    open = "open"
    approved = "approved"
    dismissed = "dismissed"
    blocked = "blocked"
    expired = "expired"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(256), default="Exchange Edge")
    shared_secret: Mapped[str] = mapped_column(String(512))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_heartbeat: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentNonce(Base):
    __tablename__ = "agent_nonces"
    __table_args__ = (UniqueConstraint("node_id", "nonce", name="uq_agent_nonce"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    nonce: Mapped[str] = mapped_column(String(128))
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("event_hash", name="uq_event_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_hash: Mapped[str] = mapped_column(String(64), index=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    script_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    client_ip: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    sender_domain: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    message_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unique_recipient_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    average_scl: Mapped[float | None] = mapped_column(Float, nullable=True)
    scl_evidence_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    consecutive_hits: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Candidate(Base):
    __tablename__ = "candidates"
    __table_args__ = (UniqueConstraint("node_id", "client_ip", "sender_domain", name="uq_candidate_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    client_ip: Mapped[str] = mapped_column(String(128), index=True)
    sender_domain: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[CandidateStatus] = mapped_column(Enum(CandidateStatus), default=CandidateStatus.open, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_recipient_count: Mapped[int] = mapped_column(Integer, default=0)
    average_scl: Mapped[float | None] = mapped_column(Float, nullable=True)
    scl_evidence_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    consecutive_hits: Mapped[int] = mapped_column(Integer, default=0)
    top_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"), nullable=True)
    dismissed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    command_type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[CommandStatus] = mapped_column(Enum(CommandStatus), default=CommandStatus.pending, index=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class MailboxRecord(Base):
    __tablename__ = "mailbox_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    primary_smtp_address: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(512), default="")
    alias: Mapped[str] = mapped_column(String(256), default="")
    sam_account_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    recipient_type: Mapped[str] = mapped_column(String(128), default="UserMailbox", index=True)
    organizational_unit: Mapped[str | None] = mapped_column(Text, nullable=True)
    current_policy: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    desired_policy: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    previous_policy: Mapped[str | None] = mapped_column(String(256), nullable=True)
    last_command_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ThrottlingPolicyRecord(Base):
    __tablename__ = "throttling_policy_records"

    name: Mapped[str] = mapped_column(String(256), primary_key=True)
    scope: Mapped[str] = mapped_column(String(64), index=True)
    recipient_rate_limit: Mapped[str] = mapped_column(String(64), default="Unlimited")
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IncidentStatus(str, enum.Enum):
    pending = "pending"
    quarantined = "quarantined"
    partial = "partial"
    released = "released"
    failed = "failed"


class MailboxIncident(Base):
    __tablename__ = "mailbox_incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    primary_smtp_address: Mapped[str] = mapped_column(String(320), index=True)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.pending, index=True)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    mailbox_command_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    edge_command_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    previous_ews_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    quarantined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class OutboundSenderProfile(Base):
    __tablename__ = "outbound_sender_profiles"

    sender: Mapped[str] = mapped_column(String(320), primary_key=True)
    profile_type: Mapped[str] = mapped_column(String(32), default="bulk", index=True)
    note: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class OutboundUsageRecord(Base):
    __tablename__ = "outbound_usage_records"

    sender: Mapped[str] = mapped_column(String(320), primary_key=True)
    messages_5m: Mapped[int] = mapped_column(Integer, default=0)
    recipients_5m: Mapped[int] = mapped_column(Integer, default=0)
    messages_10m: Mapped[int] = mapped_column(Integer, default=0)
    recipients_10m: Mapped[int] = mapped_column(Integer, default=0)
    messages_1h: Mapped[int] = mapped_column(Integer, default=0)
    recipients_1h: Mapped[int] = mapped_column(Integer, default=0)
    messages_24h: Mapped[int] = mapped_column(Integer, default=0)
    recipients_24h: Mapped[int] = mapped_column(Integer, default=0)
    unique_recipients_24h: Mapped[int] = mapped_column(Integer, default=0)
    unique_domains_24h: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", index=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class OutboundHourlyRecord(Base):
    __tablename__ = "outbound_hourly_records"
    __table_args__ = (UniqueConstraint("sender", "hour_start", name="uq_outbound_sender_hour"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender: Mapped[str] = mapped_column(String(320), index=True)
    hour_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    messages: Mapped[int] = mapped_column(Integer, default=0)
    recipients: Mapped[int] = mapped_column(Integer, default=0)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class OutboundEvidenceRecord(Base):
    __tablename__ = "outbound_evidence_records"

    event_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    sender: Mapped[str] = mapped_column(String(320), index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    message_id: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)
    network_message_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    recipients: Mapped[list[str]] = mapped_column(JSON, default=list)
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    transport_source_ip: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attachments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    attachment_status: Mapped[str] = mapped_column(String(32), default="unavailable", index=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class OutboundScanRun(Base):
    __tablename__ = "outbound_scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    rows_read: Mapped[int] = mapped_column(Integer, default=0)
    senders_seen: Mapped[int] = mapped_column(Integer, default=0)
    rows_capped: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class InboundSpoofSource(Base):
    __tablename__ = "inbound_spoof_sources"

    source_ip: Mapped[str] = mapped_column(String(128), primary_key=True)
    accepted_messages: Mapped[int] = mapped_column(Integer, default=0)
    accepted_recipients: Mapped[int] = mapped_column(Integer, default=0)
    failed_messages: Mapped[int] = mapped_column(Integer, default=0)
    unique_senders: Mapped[int] = mapped_column(Integer, default=0)
    unique_recipients: Mapped[int] = mapped_column(Integer, default=0)
    sample_senders: Mapped[list[str]] = mapped_column(JSON, default=list)
    sample_recipients: Mapped[list[str]] = mapped_column(JSON, default=list)
    sample_subjects: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class InboundSpoofScanRun(Base):
    __tablename__ = "inbound_spoof_scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    rows_read: Mapped[int] = mapped_column(Integer, default=0)
    sources_seen: Mapped[int] = mapped_column(Integer, default=0)
    lookback_hours: Mapped[int] = mapped_column(Integer, default=24)
    rows_capped: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class IpGeoRecord(Base):
    __tablename__ = "ip_geo_records"

    source_ip: Mapped[str] = mapped_column(String(128), primary_key=True)
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True, index=True)
    country_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    city: Mapped[str | None] = mapped_column(String(256), nullable=True)
    isp: Mapped[str | None] = mapped_column(String(512), nullable=True)
    lookup_status: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    provider: Mapped[str] = mapped_column(String(64), default="ipwho.is")
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class TelegramAlert(Base):
    __tablename__ = "telegram_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender: Mapped[str] = mapped_column(String(320), index=True)
    risk_level: Mapped[str] = mapped_column(String(32), default="critical", index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    risk_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    action_token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    telegram_chat_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    telegram_message_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("mailbox_incidents.id"), nullable=True, index=True)
    acted_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outcome_notified: Mapped[bool] = mapped_column(Boolean, default=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    action_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    acted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Snapshot(Base):
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    active_ip_blocks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    blocked_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    blocked_domains_and_subdomains: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowlisted_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowlisted_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AllowlistEntry(Base):
    __tablename__ = "allowlist_entries"
    __table_args__ = (UniqueConstraint("entry_type", "value", name="uq_allowlist_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entry_type: Mapped[str] = mapped_column(String(16), index=True)  # ip or domain
    value: Mapped[str] = mapped_column(String(255), index=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str] = mapped_column(String(128))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    remote_ip: Mapped[str | None] = mapped_column(String(128), nullable=True)


class ReputationStatus(str, enum.Enum):
    open = "open"
    dismissed = "dismissed"
    blocked = "blocked"
    allowlisted = "allowlisted"


class ReputationRecord(Base):
    __tablename__ = "reputation_records"
    __table_args__ = (UniqueConstraint("domain", name="uq_reputation_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    inbound_count: Mapped[int] = mapped_column(Integer, default=0)
    outbound_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_recipients: Mapped[int] = mapped_column(Integer, default=0)
    source_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    recommendation: Mapped[str] = mapped_column(String(64), default="monitor")
    status: Mapped[ReputationStatus] = mapped_column(Enum(ReputationStatus), default=ReputationStatus.open, index=True)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    provider_results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    dismissed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class ReputationScanRun(Base):
    __tablename__ = "reputation_scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    discovered: Mapped[int] = mapped_column(Integer, default=0)
    checked: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
