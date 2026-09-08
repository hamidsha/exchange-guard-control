from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import Command, IncidentStatus, MailboxIncident, MailboxRecord, Node, utcnow


class IncidentQueueError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int = 409,
        code: str = "incident_queue_error",
        incident_id: int | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.incident_id = incident_id


def _queue_command(db: Session, node_id: str, command_type: str, payload: dict, actor: str) -> Command:
    command = Command(
        node_id=node_id,
        command_type=command_type,
        payload=payload,
        created_by=actor,
        expires_at=utcnow() + timedelta(minutes=settings.command_ttl_minutes),
    )
    db.add(command)
    db.flush()
    return command


def queue_mailbox_quarantine(db: Session, address: str, reason: str, actor: str) -> MailboxIncident:
    normalized = address.strip().lower()
    mailbox = db.scalar(
        select(MailboxRecord).where(
            MailboxRecord.primary_smtp_address == normalized,
            MailboxRecord.active.is_(True),
        ).with_for_update()
    )
    if not mailbox:
        raise IncidentQueueError(
            "Mailbox is not present in the synced inventory",
            404,
            "mailbox_not_found",
        )

    active = db.scalar(
        select(MailboxIncident).where(
            MailboxIncident.primary_smtp_address == normalized,
            MailboxIncident.status.in_(
                [IncidentStatus.pending, IncidentStatus.quarantined, IncidentStatus.partial]
            ),
        )
    )
    if active:
        raise IncidentQueueError(
            "This mailbox already has an active incident",
            409,
            "active_incident_exists",
            active.id,
        )

    mailbox_node = db.get(Node, settings.mailbox_node_id)
    edge_node = db.get(Node, settings.bootstrap_node_id)
    if not mailbox_node or not mailbox_node.enabled or not edge_node or not edge_node.enabled:
        raise IncidentQueueError(
            "Mailbox or Edge management node is not configured or enabled",
            409,
            "management_node_unavailable",
        )

    incident = MailboxIncident(
        primary_smtp_address=normalized,
        reason=reason.strip()[:2000],
        created_by=actor[:128],
    )
    db.add(incident)
    db.flush()

    mailbox_command = _queue_command(
        db,
        mailbox_node.id,
        "QuarantineMailbox",
        {
            "primary_smtp_address": normalized,
            "blocked_group": settings.blocked_outbound_group,
            "incident_id": incident.id,
        },
        actor,
    )
    edge_command = _queue_command(
        db,
        edge_node.id,
        "PurgeSenderQueue",
        {"primary_smtp_address": normalized, "incident_id": incident.id},
        actor,
    )
    incident.mailbox_command_id = mailbox_command.id
    incident.edge_command_id = edge_command.id
    return incident
