"""Identity background tasks: temporary-access expiry sweep.

Celery beat entry the coordinator wires into ``app/tasks/celery_app.py``::

    "expire-temp-grants-hourly": {
        "task": "null.tasks.expire_temp_grants",
        "schedule": 3600.0,
    }

The sweep is system-wide: it scans every organization and expires that
org's overdue grants inside its own RLS-scoped session, exactly like
``expire_memberships``.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select

from app.database import SessionLocal, tenant_session
from app.models.identity_assets import TemporaryAccessGrant
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks.identity")


@celery_app.task(name="null.tasks.expire_temp_grants")
def expire_temp_grants() -> dict:
    """Expire temporary access grants past their expiry, per org."""
    from app.services import identity_service

    expired = 0
    with SessionLocal() as session:
        org_ids = [r[0] for r in session.execute(select(TemporaryAccessGrant.organization_id).distinct()).all()]
    for org_id in org_ids:
        with tenant_session(uuid.UUID(str(org_id))) as session:
            count = identity_service.expire_temp_grants(session, uuid.UUID(str(org_id)))
            if count:
                logger.info("Expired %d temporary access grants in org %s", count, org_id)
            expired += count
    return {"expired": expired}
