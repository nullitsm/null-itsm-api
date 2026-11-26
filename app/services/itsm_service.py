"""Phase 2 ITSM engine — shared helpers.

Per-organization human-number counters (row-locked, same pattern as
``app.routers.tickets._next_number``), the org-scoped row loader used
by every ITSM router (cross-org ids are 404, never 403), the
frequency-based next-run computation for recurring tickets (no
croniter dependency), and the due-recurring sweep that creates tickets
from templates (used by the Celery task in ``app.tasks.recurring_tasks``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, time, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.itsm import ChangeCounter, ProblemCounter, RecurringTicket, RequestCounter, TicketTemplate
from app.models.ticket import Ticket

# --- Per-org number counters -------------------------------------------------


def _next_counter(session: Session, model, org_id: uuid.UUID, prefix: str) -> str:
    counter = session.execute(
        select(model).where(model.organization_id == org_id).with_for_update()
    ).scalar_one_or_none()
    if counter is None:
        counter = model(organization_id=org_id, last_number=0)
        session.add(counter)
        session.flush()
    counter.last_number += 1
    return f"{prefix}-{counter.last_number:06d}"


def next_request_number(session: Session, org_id: uuid.UUID) -> str:
    return _next_counter(session, RequestCounter, org_id, "REQ")


def next_change_number(session: Session, org_id: uuid.UUID) -> str:
    return _next_counter(session, ChangeCounter, org_id, "CHG")


def next_problem_number(session: Session, org_id: uuid.UUID) -> str:
    return _next_counter(session, ProblemCounter, org_id, "PRB")


# --- Org-scoped row loading --------------------------------------------------


def get_org_row(session: Session, model, row_id: uuid.UUID, org_id: uuid.UUID):
    """Load a row by id, scoped to ``org_id``.

    Returns 404 when the row does not exist OR belongs to another
    organization — never reveals whether another org's row exists.
    """
    row = session.get(model, row_id)
    if row is None or row.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return row


# --- Recurring schedules ------------------------------------------------------

_FREQUENCIES = {"daily", "weekly", "monthly"}


def parse_schedule_time(schedule: dict) -> time:
    """Parse the ``HH:MM`` time from a recurring schedule (default 09:00)."""
    raw = schedule.get("time", "09:00")
    try:
        hour, minute = (int(part) for part in str(raw).split(":"))
        return time(hour=hour, minute=minute)
    except (ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="schedule.time must be HH:MM")


def validate_schedule(schedule: dict) -> None:
    """Validate a recurring-ticket schedule dict (400 on bad input)."""
    frequency = schedule.get("frequency")
    if frequency not in _FREQUENCIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="schedule.frequency must be daily, weekly, or monthly",
        )
    parse_schedule_time(schedule)
    if frequency == "weekly":
        weekday = schedule.get("weekday")
        if weekday is not None and (not isinstance(weekday, int) or not 0 <= weekday <= 6):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="schedule.weekday must be 0-6 (Monday=0)"
            )


def compute_next_run(schedule: dict, from_dt: datetime) -> datetime | None:
    """Next run strictly after ``from_dt`` for a frequency schedule.

    ``from_dt`` is timezone-aware (UTC). Returns None for an empty or
    unparseable schedule rather than raising — the sweep skips those.
    """
    try:
        frequency = schedule.get("frequency")
        if frequency not in _FREQUENCIES:
            return None
        run_time = parse_schedule_time(schedule)
    except HTTPException:
        return None
    base = from_dt.astimezone(timezone.utc)
    candidate = datetime.combine(base.date(), run_time, tzinfo=timezone.utc)
    if frequency == "daily":
        if candidate <= base:
            candidate += timedelta(days=1)
        return candidate
    if frequency == "weekly":
        weekday = schedule.get("weekday", 0)
        if not isinstance(weekday, int) or not 0 <= weekday <= 6:
            weekday = 0
        days_ahead = (weekday - base.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= base:
            candidate += timedelta(weeks=1)
        return candidate
    # monthly: same day-of-month, rolling to the next month when passed
    # (clamped to the last day of the month when the day does not exist).
    day = base.day
    year, month = base.year, base.month
    for _ in range(3):  # at most this month + next month + one retry
        import calendar

        last_day = calendar.monthrange(year, month)[1]
        candidate = datetime.combine(datetime(year, month, min(day, last_day)).date(), run_time, tzinfo=timezone.utc)
        if candidate > base:
            return candidate
        month += 1
        if month > 12:
            month, year = 1, year + 1
    return None


# --- Due-recurring sweep -------------------------------------------------------


def create_ticket_from_template(
    session: Session, org_id: uuid.UUID, template: TicketTemplate, created_by_id: uuid.UUID | None
) -> Ticket:
    """Create one ticket from an active template (caller commits)."""
    from app.routers.tickets import _next_number as _next_ticket_number

    ticket = Ticket(
        organization_id=org_id,
        number=_next_ticket_number(session, org_id),
        title=template.name,
        description=template.description or "",
        priority=template.priority,
        category=template.category,
        requester_id=created_by_id,
        assignee_id=template.default_assignee_id,
        status="open",
    )
    session.add(ticket)
    session.flush()
    return ticket


def process_due_recurring(session: Session, org_id: uuid.UUID, now: datetime) -> list[Ticket]:
    """Create tickets for every due active recurring template in ``org_id``.

    A recurring row is due when ``is_active`` and ``next_run_at`` is
    set and <= ``now``. Each run stamps ``last_run_at`` and advances
    ``next_run_at`` to the next future occurrence; a schedule that
    cannot produce a next run deactivates the row instead of spinning.
    Returns the tickets created. The caller commits.
    """
    from app import audit as audit_mod

    due = session.execute(
        select(RecurringTicket).where(
            RecurringTicket.organization_id == org_id,
            RecurringTicket.is_active.is_(True),
            RecurringTicket.next_run_at.is_not(None),
            RecurringTicket.next_run_at <= now,
        )
    ).scalars()
    created: list[Ticket] = []
    for row in due:
        template = session.get(TicketTemplate, row.template_id)
        if template is None or not template.is_active:
            row.is_active = False
            continue
        ticket = create_ticket_from_template(session, org_id, template, row.created_by_id)
        audit_mod.write_audit(
            session,
            organization_id=org_id,
            actor_id=row.created_by_id,
            action=audit_mod.TICKET_CREATED,
            resource_type="ticket",
            resource_id=str(ticket.id),
            outcome="success",
            metadata={"number": ticket.number, "recurring_ticket_id": str(row.id)},
        )
        row.last_run_at = now
        nxt = compute_next_run(row.schedule or {}, now)
        if nxt is None:
            row.is_active = False
            row.next_run_at = None
        else:
            row.next_run_at = nxt
        created.append(ticket)
    return created
