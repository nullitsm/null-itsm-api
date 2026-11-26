"""Recurring-ticket Celery tasks (Phase 2 ITSM engine).

The sweep is tenant-aware: each task run carries one ``org_id`` and
opens an RLS-scoped session for that organization only (see
``app.database.tenant_session``). The dispatcher
``sweep_recurring_tickets`` enumerates organizations through the
grant-checked SECURITY DEFINER function ``list_organization_ids()``
(migration 0008) — the application role cannot enumerate organizations
itself — and runs the per-org task for each. Beat wiring is the
coordinator's.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from app.database import list_organization_ids, system_session, tenant_session
from app.services.itsm_service import process_due_recurring
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks")


@celery_app.task(name="null.tasks.sweep_recurring_tickets")
def sweep_recurring_tickets() -> dict:
    """Dispatcher: create due recurring tickets in every organization.

    Runs every 15 minutes (beat entry wired by the coordinator). Each
    org's work runs in its own RLS scope; a bad org yields zero rows,
    never another org's tickets.
    """
    with system_session() as session:
        org_ids = list_organization_ids(session)
    total = {"orgs": 0, "created": 0, "numbers": []}
    for org_id in org_ids:
        try:
            result = create_due_recurring_tickets(str(org_id))
        except Exception:
            logger.exception("Recurring sweep failed for org %s", org_id)
            continue
        total["orgs"] += 1
        total["created"] += result["created"]
        total["numbers"].extend(result["numbers"])
    logger.info("Recurring sweep complete: %s", total)
    return total


@celery_app.task(name="null.tasks.create_due_recurring_tickets")
def create_due_recurring_tickets(org_id: str) -> dict:
    """Create tickets for every due active recurring template in ``org_id``.

    Returns the count and the numbers of the tickets created. Runs
    inside the org's RLS scope; a bad org id yields zero rows, never
    another org's tickets.
    """
    now = datetime.now(timezone.utc)
    with tenant_session(uuid.UUID(org_id)) as session:
        created = process_due_recurring(session, uuid.UUID(org_id), now)
        numbers = [t.number for t in created]
    logger.info("Recurring sweep for org %s: %d ticket(s) created", org_id, len(numbers))
    return {"organization_id": org_id, "created": len(numbers), "numbers": numbers}
