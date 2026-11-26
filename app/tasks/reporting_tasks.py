"""Scheduled-report sweep — find due schedules and enqueue generation.

Beat runs this every 5 minutes. For each active schedule in each org,
the cron expression is checked against every minute since the
schedule's last run (or the last 5 minutes when it never ran): when
any of those minutes matches, the schedule is due and
``reporting.generate_scheduled_report`` is enqueued once for it.
Checking the whole window (instead of only "now") means a missed or
late sweep still fires a due schedule exactly once, and a schedule
that already ran for a minute never re-fires for it.

Generation itself runs in the enqueued task, in the schedule's own
tenant session; this sweep only decides what is due.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import list_organization_ids, system_session, tenant_session
from app.models.reporting import ScheduledReport
from app.services.reporting_service import cron_matches, generate_scheduled_report
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks.reporting")

SWEEP_WINDOW_MINUTES = 5


def _due_minutes(scheduled: ScheduledReport, now: datetime) -> bool:
    """True when the schedule's cron fired in (last run, now]."""
    window_start = scheduled.last_run_at or (now - timedelta(minutes=SWEEP_WINDOW_MINUTES))
    first = window_start.astimezone(timezone.utc).replace(second=0, microsecond=0) + timedelta(minutes=1)
    last = now.astimezone(timezone.utc).replace(second=0, microsecond=0)
    minute = first
    while minute <= last:
        if cron_matches(scheduled.cron_expression, minute):
            return True
        minute += timedelta(minutes=1)
    return False


@celery_app.task(name="null.tasks.sweep_scheduled_reports")
def sweep_scheduled_reports() -> dict:
    """Enqueue generation for every due scheduled report. Returns counts."""
    now = datetime.now(timezone.utc)
    total = {"orgs": 0, "schedules_checked": 0, "enqueued": 0}
    with system_session() as session:
        org_ids = list_organization_ids(session)
    for org_id in org_ids:
        total["orgs"] += 1
        try:
            with tenant_session(org_id) as session:
                schedules = (
                    session.execute(
                        select(ScheduledReport).where(
                            ScheduledReport.organization_id == org_id,
                            ScheduledReport.is_active.is_(True),
                        )
                    )
                    .scalars()
                    .all()
                )
                due_ids = [s.id for s in schedules if _due_minutes(s, now)]
                total["schedules_checked"] += len(schedules)
        except Exception:
            logger.exception("Scheduled-report sweep failed for org %s", org_id)
            continue
        for schedule_id in due_ids:
            generate_scheduled_report.delay(str(schedule_id))
            total["enqueued"] += 1
    logger.info("Scheduled-report sweep complete: %s", total)
    return total
