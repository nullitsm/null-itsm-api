"""Network health Celery task — periodic availability sweep.

The coordinator wires the beat schedule (see the workstream report);
this module only defines the task. Each org is processed in its own
RLS-scoped ``tenant_session``.

Org enumeration goes through the grant-checked SECURITY DEFINER function
``list_organization_ids()`` (migration 0008): the application role
cannot read the organizations table without an RLS context, so the
function (owner-owned, ids only) is the enumeration path. Per-org work
itself is always RLS-scoped.

Idempotency: a device is marked down (and one outage event created) only
on the up -> down transition. A device already down gets no new event,
so overlapping runs never spam one event per run; a device that recovers
(status back to ``up`` via discovery or metric ingest) and goes stale
again starts a new downtime episode and gets a fresh event.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import list_organization_ids, system_session, tenant_session
from app.models.cmdb_network import NetworkDevice, NetworkEvent
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks.network")

STALE_AFTER = timedelta(hours=1)


def _all_org_ids() -> list[uuid.UUID]:
    with system_session() as session:
        return list_organization_ids(session)


def check_org_network_health(session, org_id: uuid.UUID) -> dict:
    """Mark stale ``up`` devices down and record one outage event each.

    A device is stale when ``last_seen_at`` is older than one hour.
    Devices never seen (``last_seen_at`` NULL) are not marked down:
    no sighting exists to go stale from.
    """
    now = datetime.now(timezone.utc)
    stale_before = now - STALE_AFTER
    rows = session.execute(
        select(NetworkDevice).where(
            NetworkDevice.organization_id == org_id,
            NetworkDevice.status == "up",
            NetworkDevice.last_seen_at.is_not(None),
            NetworkDevice.last_seen_at < stale_before,
        )
    ).scalars()
    marked_down = 0
    events_created = 0
    for device in rows:
        device.status = "down"
        marked_down += 1
        event = NetworkEvent(
            organization_id=org_id,
            device_id=device.id,
            event_type="outage",
            severity="critical",
            message=(
                f"Device {device.hostname} ({device.ip_address or 'no IP'}) "
                f"has not been seen since {device.last_seen_at.isoformat()}; marked down."
            ),
            occurred_at=now,
        )
        session.add(event)
        events_created += 1
        logger.warning("Device %s in org %s marked down (stale since %s)", device.id, org_id, device.last_seen_at)
    session.flush()
    return {"devices_marked_down": marked_down, "events_created": events_created}


@celery_app.task(name="null.tasks.check_network_health")
def check_network_health() -> dict:
    """Sweep every org: mark stale up-devices down, one outage event each.

    Runs hourly (beat entry wired by the coordinator). Idempotent per
    downtime episode, so overlapping runs are safe.
    """
    total = {"orgs": 0, "devices_marked_down": 0, "events_created": 0}
    for org_id in _all_org_ids():
        total["orgs"] += 1
        try:
            with tenant_session(org_id) as session:
                result = check_org_network_health(session, org_id)
        except Exception:
            logger.exception("Network health sweep failed for org %s", org_id)
            continue
        total["devices_marked_down"] += result["devices_marked_down"]
        total["events_created"] += result["events_created"]
    logger.info("Network health sweep complete: %s", total)
    return total
