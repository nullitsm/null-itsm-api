"""Celery application and tenant-aware tasks.

Every task carries ``org_id`` in its kwargs. The worker opens a DB session
RLS-scoped to that organization, so background work is tenant-isolated
exactly like request handling.

Tasks in Phase 1:
- ``expire_memberships`` (periodic): suspend memberships past expires_at.
- ``send_invitation_email``: deliver an invitation (dev: logged).
- ``export_audit_log``: produce an audit export for an organization.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from celery import Celery
from sqlalchemy import select

from app.config import get_settings
from app.database import tenant_session
from app.models.platform import Membership

settings = get_settings()
logger = logging.getLogger("null.tasks")

celery_app = Celery(
    "null_itsm",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "expire-memberships-hourly": {
            "task": "null.tasks.expire_memberships",
            "schedule": 3600.0,
        },
    },
)


@celery_app.task(name="null.tasks.expire_memberships")
def expire_memberships() -> dict:
    """Suspend memberships whose access expiration has passed.

    Scans all organizations (system-level sweep) and suspends expired
    memberships one organization at a time, each in its own RLS scope.
    """
    from app.database import SessionLocal

    now = datetime.now(timezone.utc)
    suspended = 0
    with SessionLocal() as session:
        org_ids = [r[0] for r in session.execute(select(Membership.organization_id).distinct()).all()]
    for org_id in org_ids:
        with tenant_session(org_id) as session:
            rows = session.execute(
                select(Membership).where(
                    Membership.organization_id == org_id,
                    Membership.status == "active",
                    Membership.expires_at.is_not(None),
                    Membership.expires_at < now,
                )
            ).scalars()
            for membership in rows:
                membership.status = "suspended"
                suspended += 1
                logger.info("Suspended expired membership %s in org %s", membership.id, org_id)
    return {"suspended": suspended}


@celery_app.task(name="null.tasks.send_invitation_email")
def send_invitation_email(org_id: str, email: str, org_name: str, accept_url: str) -> dict:
    """Tenant-aware invitation delivery (dev: logged, never sent)."""
    from app.services import email as email_service

    with tenant_session(uuid.UUID(org_id)):
        email_service.send_invitation_email(email, org_name, accept_url)
    return {"sent": True, "to": email}


@celery_app.task(name="null.tasks.export_audit_log")
def export_audit_log(org_id: str, actor_id: str) -> dict:
    """Export an organization's audit log (Phase 1: row count + S3 key stub).

    The full export writer (CSV to S3) lands with the reporting work in
    Phase 4; this task proves the tenant-aware job plumbing now.
    """
    from app.models.audit import AuditLog

    with tenant_session(uuid.UUID(org_id)) as session:
        count = session.execute(select(AuditLog).where(AuditLog.organization_id == uuid.UUID(org_id))).scalars()
        total = len(list(count))
    logger.info("Audit export for org %s requested by %s: %d events", org_id, actor_id, total)
    return {"organization_id": org_id, "events": total, "status": "counted"}
