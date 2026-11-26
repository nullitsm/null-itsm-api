"""SLA service — business-hours math, due dates, breach scan, escalations.

All functions take an explicit RLS-scoped session plus ``org_id`` and
never trust a client-supplied org id. Functions flush but do not commit;
the caller (router or Celery task) owns the transaction.

Two dependencies land with the sibling ITSM migration (0004) and are
imported lazily so this module stays importable before they exist:
``app.models.itsm.TicketComment`` (first-response derivation) and the
``Notification`` model behind ``notification_service.create_notification``.
Until 0004 lands, first-response derivation and breach notifications are
skipped (logged) instead of crashing; breach rows and audit still land.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.models.platform import Membership
from app.models.sla import BusinessHours, EscalationEvent, EscalationRule, SlaBreach, SlaPolicy
from app.models.ticket import Ticket

logger = logging.getLogger("null.sla")

PRIORITY_ORDER = ["low", "medium", "high", "critical"]
OPEN_STATUSES = ("open", "in_progress", "pending")
RESOLVED_STATUSES = ("resolved", "closed")
_DAY_KEYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(value: datetime) -> datetime:
    """Treat a naive datetime as UTC (all app datetimes are aware)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# ---------------------------------------------------------------------------
# Business-hours arithmetic
# ---------------------------------------------------------------------------


def _parse_hhmm(value: str) -> time:
    hours, minutes = value.split(":")
    return time(int(hours), int(minutes))


def _windows_for_day(business_hours: dict, local_date) -> list[tuple[time, time]]:
    """Sorted [start, end) windows for one local date (empty = closed)."""
    schedule = business_hours.get("schedule") or {}
    # Tolerate being handed the schedule dict itself.
    if not any(k in business_hours for k in ("schedule", "timezone", "holidays")):
        schedule = business_hours
    holidays = set(business_hours.get("holidays") or [])
    if local_date.isoformat() in holidays:
        return []
    day_key = _DAY_KEYS[local_date.weekday()]
    windows = []
    for start_s, end_s in schedule.get(day_key) or []:
        start_t, end_t = _parse_hhmm(start_s), _parse_hhmm(end_s)
        if end_t > start_t:
            windows.append((start_t, end_t))
    return sorted(windows)


def add_business_minutes(start: datetime, minutes: int, business_hours: dict) -> datetime:
    """Add ``minutes`` of business time to ``start``.

    ``business_hours`` is a dict with ``timezone`` (IANA name),
    ``schedule`` (``mon``..``sun`` -> list of ``["HH:MM", "HH:MM"]`` pairs)
    and ``holidays`` (list of ``"YYYY-MM-DD"``). A start outside business
    hours rolls forward to the next opening; closed days, closed hours,
    and holidays are skipped. Pure function — no database access.

    Raises ``ValueError`` for a non-positive minute count is NOT raised:
    ``minutes <= 0`` returns ``start`` unchanged. An unknown timezone or
    a schedule with no business windows at all raises ``ValueError``.
    """
    start = _as_aware(start)
    if minutes <= 0:
        return start
    tz_name = business_hours.get("timezone") or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception as exc:
        raise ValueError(f"Unknown business-hours timezone: {tz_name!r}") from exc
    if not any(
        _windows_for_day(business_hours, _as_aware(start).astimezone(tz).date() + timedelta(days=d)) for d in range(8)
    ):
        raise ValueError("Business-hours schedule has no open windows in the next 8 days")

    remaining = float(minutes)
    current = start.astimezone(tz)
    # Safety bound: never loop more than ~2 years of days.
    for _ in range(366 * 3):
        windows = _windows_for_day(business_hours, current.date())
        for window_start, window_end in windows:
            day = current.date()
            win_start_dt = datetime.combine(day, window_start, tzinfo=tz)
            win_end_dt = datetime.combine(day, window_end, tzinfo=tz)
            if current >= win_end_dt:
                continue
            if current < win_start_dt:
                current = win_start_dt
            available = (win_end_dt - current).total_seconds() / 60.0
            if remaining <= available:
                return current + timedelta(minutes=remaining)
            remaining -= available
            current = win_end_dt
        # Past the last window today (or closed today): next midnight.
        current = datetime.combine(current.date() + timedelta(days=1), time(0, 0), tzinfo=tz)
    raise ValueError("Could not place business minutes within 3 years (schedule may be empty)")


# ---------------------------------------------------------------------------
# Policy resolution + due dates
# ---------------------------------------------------------------------------


def _policy_matches(policy: SlaPolicy, ticket: Ticket) -> bool:
    applies = policy.applies_to or {}
    categories = applies.get("categories") or []
    priorities = applies.get("priorities") or []
    if categories and ticket.category not in categories:
        return False
    if priorities and ticket.priority not in priorities:
        return False
    return True


def resolve_policy(session: Session, org_id: uuid.UUID, ticket: Ticket) -> SlaPolicy | None:
    """The policy for a ticket: its pinned policy first, then the active
    policy whose ``applies_to`` matches category/priority, then the org's
    active default policy, else None."""
    if ticket.sla_policy_id is not None:
        pinned = session.get(SlaPolicy, ticket.sla_policy_id)
        if pinned is not None and pinned.organization_id == org_id and pinned.is_active:
            return pinned
    policies = session.execute(
        select(SlaPolicy)
        .where(SlaPolicy.organization_id == org_id, SlaPolicy.is_active.is_(True))
        .order_by(SlaPolicy.is_default.asc(), SlaPolicy.created_at.asc())
    ).scalars()
    default = None
    for policy in policies:
        if policy.is_default:
            default = policy
        if _policy_matches(policy, ticket):
            return policy
    return default


def _business_hours_dict(session: Session, org_id: uuid.UUID, policy: SlaPolicy) -> dict | None:
    if policy.business_hours_id is None:
        return None
    bh = session.get(BusinessHours, policy.business_hours_id)
    if bh is None or bh.organization_id != org_id:
        return None
    return {"timezone": bh.timezone, "schedule": bh.schedule or {}, "holidays": bh.holidays or []}


def compute_due_dates(session: Session, org_id: uuid.UUID, ticket: Ticket) -> tuple[datetime | None, datetime | None]:
    """(first_response_due_at, resolution_due_at) from ticket.created_at
    plus the resolved policy's minutes — through business hours when the
    policy names them, else calendar minutes. ``None`` per leg when the
    policy (or that priority's minutes) is missing."""
    policy = resolve_policy(session, org_id, ticket)
    if policy is None:
        return None, None
    base = _as_aware(ticket.created_at)
    bh = _business_hours_dict(session, org_id, policy)

    def _due(minutes_map: dict | None) -> datetime | None:
        if not minutes_map:
            return None
        minutes = minutes_map.get(ticket.priority)
        if minutes is None:
            return None
        if bh is not None:
            return add_business_minutes(base, int(minutes), bh)
        return base + timedelta(minutes=int(minutes))

    return _due(policy.response_minutes), _due(policy.resolution_minutes)


# ---------------------------------------------------------------------------
# SLA state stamping
# ---------------------------------------------------------------------------


def _derive_first_response_at(session: Session, ticket: Ticket) -> datetime | None:
    """Earliest comment on the ticket by someone other than the requester.

    TicketComment lands with the sibling ITSM migration (0004); before
    that the lazy import fails and this returns None.
    """
    try:
        from app.models.itsm import TicketComment
    except ImportError:
        return None
    try:
        row = session.execute(
            select(TicketComment)
            .where(
                TicketComment.ticket_id == ticket.id,
                TicketComment.author_id != ticket.requester_id,
            )
            .order_by(TicketComment.created_at.asc())
            .limit(1)
        ).scalar_one_or_none()
    except Exception:
        logger.warning("Could not derive first_response_at for ticket %s", ticket.id, exc_info=True)
        return None
    return _as_aware(row.created_at) if row is not None else None


def stamp_sla_state(session: Session, org_id: uuid.UUID, ticket: Ticket) -> Ticket:
    """Refresh a ticket's SLA state in place (flush, no commit).

    - first_response_at from the earliest non-requester comment.
    - resolved_at from status (resolved/closed -> updated_at when unset;
      reopened -> cleared).
    - due dates computed (and the resolved policy pinned) when missing.
    - sla_breached when now is past a due date whose timestamp is null.
    """
    if ticket.first_response_at is None:
        derived = _derive_first_response_at(session, ticket)
        if derived is not None:
            ticket.first_response_at = derived
    if ticket.status in RESOLVED_STATUSES:
        if ticket.resolved_at is None:
            ticket.resolved_at = _as_aware(ticket.updated_at) if ticket.updated_at else _now()
    elif ticket.resolved_at is not None:
        ticket.resolved_at = None

    if ticket.first_response_due_at is None or ticket.resolution_due_at is None:
        policy = resolve_policy(session, org_id, ticket)
        if policy is not None:
            if ticket.sla_policy_id is None:
                ticket.sla_policy_id = policy.id
            first_due, resolution_due = compute_due_dates(session, org_id, ticket)
            if ticket.first_response_due_at is None:
                ticket.first_response_due_at = first_due
            if ticket.resolution_due_at is None:
                ticket.resolution_due_at = resolution_due

    now = _now()
    breached = False
    if (
        ticket.first_response_due_at is not None
        and ticket.first_response_at is None
        and now > _as_aware(ticket.first_response_due_at)
    ):
        breached = True
    if (
        ticket.resolution_due_at is not None
        and ticket.resolved_at is None
        and now > _as_aware(ticket.resolution_due_at)
    ):
        breached = True
    ticket.sla_breached = breached
    session.flush()
    return ticket


# ---------------------------------------------------------------------------
# Breach scan
# ---------------------------------------------------------------------------


def _notify_breach(session: Session, org_id: uuid.UUID, ticket: Ticket, breach_type: str, due: datetime) -> bool:
    """Best-effort breach notification to assignee (else requester).

    Returns False when there is nobody to notify or the Notification
    model (migration 0004) is not importable yet.
    """
    recipient_id = ticket.assignee_id or ticket.requester_id
    if recipient_id is None:
        return False
    try:
        from app.services.notification_service import create_notification
    except ImportError:
        logger.warning("notification_service unavailable; skipping breach notification for %s", ticket.id)
        return False
    try:
        create_notification(
            session,
            organization_id=org_id,
            user_id=recipient_id,
            type="sla_breach",
            title=f"SLA breach: {ticket.number}",
            body=f"Ticket {ticket.number} breached its {breach_type.replace('_', ' ')} SLA (due {due.isoformat()}).",
            resource_type="ticket",
            resource_id=ticket.id,
        )
    except ImportError:
        logger.warning("Notification model not yet available; skipping breach notification for %s", ticket.id)
        return False
    except Exception:
        logger.warning("Breach notification failed for ticket %s", ticket.id, exc_info=True)
        return False
    return True


def scan_breaches(session: Session, org_id: uuid.UUID) -> dict:
    """Detect SLA breaches for open tickets in one org.

    Idempotent: a breach row is created only when no row exists for
    (org, ticket, breach_type) — the unique constraint is the backstop.
    Creates the breach row, a notification, and an SLA_BREACH_DETECTED
    audit event per new breach. Returns counts plus
    ``breached_ticket_ids`` — the tickets that breached in THIS scan
    (a ticket appears once even when both legs breach). Automation
    rules do NOT fire here: the sweep task (``scan_sla_breaches``)
    fires them after ``evaluate_escalations``, so an automation action
    that changes a ticket cannot defeat an escalation rule's
    conditions for the same breach.
    """
    now = _now()
    tickets = session.execute(
        select(Ticket).where(Ticket.organization_id == org_id, Ticket.status.in_(OPEN_STATUSES))
    ).scalars()
    scanned = 0
    created = 0
    notified = 0
    breached_ids: set[str] = set()
    for ticket in tickets:
        stamp_sla_state(session, org_id, ticket)
        scanned += 1
        legs = [
            ("first_response", ticket.first_response_due_at, ticket.first_response_at),
            ("resolution", ticket.resolution_due_at, ticket.resolved_at),
        ]
        for breach_type, due_at, done_at in legs:
            if due_at is None or done_at is not None or now <= _as_aware(due_at):
                continue
            existing = session.execute(
                select(SlaBreach).where(
                    SlaBreach.organization_id == org_id,
                    SlaBreach.ticket_id == ticket.id,
                    SlaBreach.breach_type == breach_type,
                )
            ).scalar_one_or_none()
            if existing is not None:
                continue
            breach = SlaBreach(
                organization_id=org_id,
                ticket_id=ticket.id,
                policy_id=ticket.sla_policy_id,
                breach_type=breach_type,
                breached_at=_as_aware(due_at),
                status="open",
            )
            session.add(breach)
            session.flush()
            if _notify_breach(session, org_id, ticket, breach_type, _as_aware(due_at)):
                breach.notified_at = now
                notified += 1
            audit_mod.write_audit(
                session,
                organization_id=org_id,
                actor_id=None,
                action=audit_mod.SLA_BREACH_DETECTED,
                resource_type="ticket",
                resource_id=str(ticket.id),
                outcome="success",
                metadata={"breach_type": breach_type, "breach_id": str(breach.id), "due_at": due_at.isoformat()},
            )
            ticket.sla_breached = True
            breached_ids.add(str(ticket.id))
            created += 1
    session.flush()
    return {
        "tickets_scanned": scanned,
        "breaches_created": created,
        "notifications_sent": notified,
        "breached_ticket_ids": sorted(breached_ids),
    }


# ---------------------------------------------------------------------------
# Escalations
# ---------------------------------------------------------------------------


def _is_active_org_member(session: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    row = session.execute(
        select(Membership).where(
            Membership.organization_id == org_id,
            Membership.user_id == user_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    return row is not None


def _rule_trigger_due(session: Session, org_id: uuid.UUID, rule: EscalationRule, ticket: Ticket, now: datetime):
    """Return the datetime the rule's trigger fired for this ticket, or
    None when the trigger has not fired."""
    trigger = rule.trigger or {}
    event = trigger.get("event")
    after_minutes = trigger.get("after_minutes")
    if after_minutes is None:
        return None
    threshold = timedelta(minutes=int(after_minutes))
    if event == "sla_breach":
        breach = session.execute(
            select(SlaBreach)
            .where(
                SlaBreach.organization_id == org_id,
                SlaBreach.ticket_id == ticket.id,
                SlaBreach.status == "open",
            )
            .order_by(SlaBreach.breached_at.asc())
            .limit(1)
        ).scalar_one_or_none()
        if breach is not None:
            fired_at = _as_aware(breach.breached_at)
        elif ticket.sla_breached:
            fired_at = _as_aware(ticket.first_response_due_at or ticket.resolution_due_at or ticket.created_at)
        else:
            return None
        return fired_at if now - fired_at >= threshold else None
    if event == "no_response":
        if ticket.first_response_at is not None:
            return None
        fired_at = _as_aware(ticket.created_at)
        return fired_at if now - fired_at >= threshold else None
    if event == "no_update":
        if ticket.status in RESOLVED_STATUSES:
            return None
        fired_at = _as_aware(ticket.updated_at) if ticket.updated_at else _as_aware(ticket.created_at)
        return fired_at if now - fired_at >= threshold else None
    return None


def _rule_conditions_match(rule: EscalationRule, ticket: Ticket) -> bool:
    conditions = rule.conditions or {}
    priorities = conditions.get("priority") or []
    categories = conditions.get("category") or []
    if priorities and ticket.priority not in priorities:
        return False
    if categories and ticket.category not in categories:
        return False
    return True


def evaluate_escalations(session: Session, org_id: uuid.UUID) -> dict:
    """Evaluate active escalation rules for open tickets in one org.

    One-shot per (rule, ticket): a rule that already has an executed
    event for a ticket does not fire again for it. Actions run in the
    order listed; a failed action (e.g. reassign to a non-member) marks
    the event ``failed`` and is recorded, not silently dropped. Returns
    counts.
    """
    now = _now()
    rules = session.execute(
        select(EscalationRule)
        .where(EscalationRule.organization_id == org_id, EscalationRule.is_active.is_(True))
        .order_by(EscalationRule.sort_order.asc(), EscalationRule.created_at.asc())
    ).scalars()
    rules = list(rules)
    tickets = session.execute(
        select(Ticket).where(Ticket.organization_id == org_id, Ticket.status.in_(OPEN_STATUSES))
    ).scalars()
    tickets = list(tickets)
    events_created = 0
    actions_executed = 0
    actions_failed = 0
    for rule in rules:
        actions = rule.actions or []
        if not isinstance(actions, list):
            actions = [actions]
        for ticket in tickets:
            if not _rule_conditions_match(rule, ticket):
                continue
            if _rule_trigger_due(session, org_id, rule, ticket, now) is None:
                continue
            already = session.execute(
                select(EscalationEvent).where(
                    EscalationEvent.organization_id == org_id,
                    EscalationEvent.rule_id == rule.id,
                    EscalationEvent.ticket_id == ticket.id,
                    EscalationEvent.status == "executed",
                )
            ).scalar_one_or_none()
            if already is not None:
                continue
            taken: list[dict] = []
            failed = False
            for action in actions:
                if not isinstance(action, dict):
                    taken.append({"type": str(action), "result": "failed", "error": "action is not an object"})
                    failed = True
                    continue
                a_type = action.get("type")
                if a_type == "priority_bump":
                    idx = PRIORITY_ORDER.index(ticket.priority) if ticket.priority in PRIORITY_ORDER else 1
                    if idx < len(PRIORITY_ORDER) - 1:
                        old = ticket.priority
                        ticket.priority = PRIORITY_ORDER[idx + 1]
                        taken.append({"type": "priority_bump", "from": old, "to": ticket.priority})
                    else:
                        taken.append(
                            {
                                "type": "priority_bump",
                                "from": ticket.priority,
                                "to": ticket.priority,
                                "result": "already_max",
                            }
                        )
                elif a_type == "reassign":
                    to_user_id = action.get("to_user_id")
                    try:
                        target = uuid.UUID(str(to_user_id)) if to_user_id else None
                    except ValueError:
                        target = None
                    if target is None or not _is_active_org_member(session, org_id, target):
                        taken.append(
                            {
                                "type": "reassign",
                                "to_user_id": str(to_user_id),
                                "result": "failed",
                                "error": "target is not an active member of the organization",
                            }
                        )
                        failed = True
                    else:
                        ticket.assignee_id = target
                        taken.append({"type": "reassign", "to_user_id": str(target)})
                elif a_type == "notify":
                    to_user_id = action.get("to_user_id")
                    recipient = None
                    if to_user_id:
                        try:
                            candidate = uuid.UUID(str(to_user_id))
                        except ValueError:
                            candidate = None
                        if candidate is not None and _is_active_org_member(session, org_id, candidate):
                            recipient = candidate
                        else:
                            taken.append(
                                {
                                    "type": "notify",
                                    "to_user_id": str(to_user_id),
                                    "result": "failed",
                                    "error": "target is not an active member of the organization",
                                }
                            )
                            failed = True
                            continue
                    else:
                        recipient = ticket.assignee_id or ticket.requester_id
                    if recipient is None:
                        taken.append({"type": "notify", "result": "failed", "error": "no recipient"})
                        failed = True
                    else:
                        try:
                            from app.services.notification_service import create_notification

                            create_notification(
                                session,
                                organization_id=org_id,
                                user_id=recipient,
                                type="sla_escalation",
                                title=f"Escalated: {ticket.number}",
                                body=action.get("message")
                                or f"Ticket {ticket.number} was escalated by rule '{rule.name}'.",
                                resource_type="ticket",
                                resource_id=ticket.id,
                            )
                            taken.append({"type": "notify", "to_user_id": str(recipient)})
                        except ImportError:
                            taken.append(
                                {"type": "notify", "result": "failed", "error": "notification service unavailable"}
                            )
                            failed = True
                        except Exception as exc:
                            taken.append({"type": "notify", "result": "failed", "error": str(exc)})
                            failed = True
                else:
                    taken.append({"type": str(a_type), "result": "failed", "error": "unknown action type"})
                    failed = True
            event = EscalationEvent(
                organization_id=org_id,
                rule_id=rule.id,
                ticket_id=ticket.id,
                action_taken={"actions": taken, "rule": rule.name},
                status="failed" if failed else "executed",
            )
            session.add(event)
            session.flush()
            audit_mod.write_audit(
                session,
                organization_id=org_id,
                actor_id=None,
                action=audit_mod.SLA_ESCALATED,
                resource_type="ticket",
                resource_id=str(ticket.id),
                outcome="failed" if failed else "success",
                metadata={"rule_id": str(rule.id), "rule": rule.name, "event_id": str(event.id), "actions": taken},
            )
            events_created += 1
            actions_executed += sum(1 for a in taken if a.get("result") != "failed")
            actions_failed += sum(1 for a in taken if a.get("result") == "failed")
    session.flush()
    return {"events_created": events_created, "actions_executed": actions_executed, "actions_failed": actions_failed}
