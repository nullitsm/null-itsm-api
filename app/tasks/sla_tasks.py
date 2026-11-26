"""SLA Celery tasks — periodic breach scan + per-ticket recompute.

The coordinator wires the beat schedule (see the suggested entries in
the workstream report); this module only defines the tasks. Each org is
processed in its own RLS-scoped ``tenant_session``.

Org enumeration goes through the grant-checked SECURITY DEFINER function
``list_organization_ids()`` (migration 0008): the application role
cannot read the organizations table without an RLS context, so the
function (owner-owned, ids only) is the enumeration path. Per-org work
itself is always RLS-scoped.
"""

from __future__ import annotations

import logging
import uuid

from app.database import list_organization_ids, system_session, tenant_session
from app.services import automation_service, sla_service
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks.sla")


def _all_org_ids() -> list[uuid.UUID]:
    with system_session() as session:
        return list_organization_ids(session)


@celery_app.task(name="null.tasks.scan_sla_breaches")
def scan_sla_breaches() -> dict:
    """Sweep every org: detect SLA breaches, then evaluate escalations.

    Runs every 5 minutes (beat entry wired by the coordinator). Breach
    detection is idempotent, so overlapping runs are safe.

    Order inside one org is deliberate: detect breaches, evaluate the
    Phase 2 escalation rules against the breached tickets, THEN fire
    Phase 4 automation rules (``sla_breach`` trigger) for the tickets
    that breached in this scan. Automation runs last so an automation
    action that changes a ticket (e.g. sets priority critical) cannot
    defeat an escalation rule's conditions for the same breach.
    """
    total = {
        "orgs": 0,
        "tickets_scanned": 0,
        "breaches_created": 0,
        "notifications_sent": 0,
        "events_created": 0,
        "automation_runs": 0,
    }
    for org_id in _all_org_ids():
        total["orgs"] += 1
        try:
            with tenant_session(org_id) as session:
                breaches = sla_service.scan_breaches(session, org_id)
                escalations = sla_service.evaluate_escalations(session, org_id)
                automation_runs = 0
                for ticket_id in breaches.get("breached_ticket_ids", []):
                    # A failing action is recorded on the AutomationRun,
                    # never raised — one bad rule cannot break the sweep.
                    runs = automation_service.evaluate_rules(
                        session,
                        org_id=org_id,
                        trigger="sla_breach",
                        entity_type="ticket",
                        entity_id=uuid.UUID(ticket_id),
                        actor_id=None,
                    )
                    automation_runs += len(runs)
        except Exception:
            logger.exception("SLA sweep failed for org %s", org_id)
            continue
        total["tickets_scanned"] += breaches["tickets_scanned"]
        total["breaches_created"] += breaches["breaches_created"]
        total["notifications_sent"] += breaches["notifications_sent"]
        total["events_created"] += escalations["events_created"]
        total["automation_runs"] += automation_runs
    logger.info("SLA sweep complete: %s", total)
    return total


@celery_app.task(name="null.tasks.recompute_ticket_sla")
def recompute_ticket_sla(org_id: str, ticket_id: str) -> dict:
    """Recompute due dates + stamp SLA state for one ticket."""
    from app.models.ticket import Ticket

    with tenant_session(uuid.UUID(org_id)) as session:
        ticket = session.get(Ticket, uuid.UUID(ticket_id))
        if ticket is None or ticket.organization_id != uuid.UUID(org_id):
            return {"organization_id": org_id, "ticket_id": ticket_id, "status": "not_found"}
        sla_service.stamp_sla_state(session, uuid.UUID(org_id), ticket)
        session.flush()
        return {
            "organization_id": org_id,
            "ticket_id": ticket_id,
            "status": "ok",
            "sla_policy_id": str(ticket.sla_policy_id) if ticket.sla_policy_id else None,
            "first_response_due_at": ticket.first_response_due_at.isoformat() if ticket.first_response_due_at else None,
            "resolution_due_at": ticket.resolution_due_at.isoformat() if ticket.resolution_due_at else None,
            "sla_breached": ticket.sla_breached,
        }
