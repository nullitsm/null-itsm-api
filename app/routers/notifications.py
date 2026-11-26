"""Notifications — Phase 2 ITSM engine.

Read-only from the API: notifications are created by
``app.services.notification_service.create_notification`` (used by
the ITSM engine, the SLA engine, and the email worker). Each caller
sees only their own notifications; marking read is per-notification
or all-at-once.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.itsm import Notification
from app.services.itsm_service import get_org_row

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


class NotificationOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    user_id: uuid.UUID
    type: str
    title: str
    body: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    channel: str
    email_status: str
    read_at: datetime | None
    created_at: datetime
    updated_at: datetime


def _out(n: Notification) -> NotificationOut:
    return NotificationOut(
        id=n.id,
        organization_id=n.organization_id,
        user_id=n.user_id,
        type=n.type,
        title=n.title,
        body=n.body,
        resource_type=n.resource_type,
        resource_id=n.resource_id,
        channel=n.channel,
        email_status=n.email_status,
        read_at=n.read_at,
        created_at=n.created_at,
        updated_at=n.updated_at,
    )


def _own_or_404(session: Session, principal: Principal, notification_id: uuid.UUID) -> Notification:
    row = get_org_row(session, Notification, notification_id, principal.organization_id)
    if row.user_id != principal.user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return row


@router.get("", response_model=list[NotificationOut])
def list_notifications(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("notifications:read"))
):
    rows = session.execute(
        select(Notification)
        .where(
            Notification.organization_id == principal.organization_id,
            Notification.user_id == principal.user_id,
        )
        .order_by(Notification.created_at.desc())
    ).scalars()
    return [_out(n) for n in rows]


@router.post("/read-all", response_model=list[NotificationOut])
def mark_all_read(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("notifications:read"))
):
    now = datetime.now(timezone.utc)
    rows = session.execute(
        select(Notification).where(
            Notification.organization_id == principal.organization_id,
            Notification.user_id == principal.user_id,
            Notification.read_at.is_(None),
        )
    ).scalars()
    rows = list(rows)
    for row in rows:
        row.read_at = now
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.NOTIFICATION_READ_ALL,
        resource_type="notification",
        resource_id=str(principal.user_id),
        outcome="success",
        metadata={"marked_read": len(rows)},
    )
    session.flush()
    out = [_out(n) for n in rows]
    session.commit()
    return out


@router.get("/{notification_id}", response_model=NotificationOut)
def get_notification(
    notification_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("notifications:read")),
):
    return _out(_own_or_404(session, principal, notification_id))


@router.post("/{notification_id}/read", response_model=NotificationOut)
def mark_read(
    notification_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("notifications:read")),
):
    row = _own_or_404(session, principal, notification_id)
    if row.read_at is None:
        row.read_at = datetime.now(timezone.utc)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.NOTIFICATION_READ,
        resource_type="notification",
        resource_id=str(row.id),
        outcome="success",
        metadata={},
    )
    session.flush()
    out = _out(row)
    session.commit()
    return out
