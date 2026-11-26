"""Guided organization onboarding (backend state + endpoints).

Steps: profile → departments → invite_technicians → service_desk →
business_hours_sla → assets_endpoints → finish. Progress is stored per
org in ``org_onboarding``; every step except profile and finish is
skippable. Completing a step may carry step data:

- departments: {"departments": [{"name", "description"}]}
- service_desk: {"service_desk": {...}} — merged into org settings
- business_hours_sla: {"business_hours": {...}, "sla_policy": {...}}
  (either may be omitted; defaults are created instead)
- profile: {"name", "contact_email", "website", "industry", "size"}

Finishing requires every other step complete or skipped. The frontend
wizard (separate track) drives these endpoints; the API is the source
of truth for progress.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.models.platform import Organization
from app.models.registration import ONBOARDING_STEPS, SKIPPABLE_STEPS, OrgOnboarding
from app.models.sla import BusinessHours, SlaPolicy
from app.services import org_service

DEFAULT_SCHEDULE = {
    "mon": [["09:00", "17:00"]],
    "tue": [["09:00", "17:00"]],
    "wed": [["09:00", "17:00"]],
    "thu": [["09:00", "17:00"]],
    "fri": [["09:00", "17:00"]],
    "sat": [],
    "sun": [],
}

DEFAULT_RESPONSE_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 480}
DEFAULT_RESOLUTION_MINUTES = {"critical": 240, "high": 480, "medium": 1440, "low": 2880}


def get_or_init_onboarding(session: Session, org_id: uuid.UUID) -> OrgOnboarding:
    row = session.get(OrgOnboarding, org_id)
    if row is None:
        row = OrgOnboarding(
            organization_id=org_id,
            current_step="departments",
            steps={
                "profile": "complete",
                "departments": "pending",
                "invite_technicians": "pending",
                "service_desk": "pending",
                "business_hours_sla": "pending",
                "assets_endpoints": "pending",
                "finish": "pending",
            },
        )
        session.add(row)
        session.flush()
    return row


def _advance(row: OrgOnboarding) -> None:
    for step in ONBOARDING_STEPS:
        if row.steps.get(step) in ("pending", "in_progress"):
            row.current_step = step
            return
    row.current_step = "finish"


def _ensure_default_business_hours(session: Session, org: Organization, data: dict | None) -> BusinessHours:
    existing = session.execute(
        select(BusinessHours).where(BusinessHours.organization_id == org.id, BusinessHours.is_default.is_(True))
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    payload = (data or {}).get("business_hours") or {}
    timezone = payload.get("timezone") or (org.settings or {}).get("timezone") or "UTC"
    row = BusinessHours(
        organization_id=org.id,
        name=payload.get("name") or "Default business hours",
        timezone=timezone,
        schedule=payload.get("schedule") or DEFAULT_SCHEDULE,
        holidays=payload.get("holidays") or [],
        is_default=True,
    )
    session.add(row)
    session.flush()
    return row


def _ensure_default_sla_policy(
    session: Session, org: Organization, business_hours: BusinessHours, data: dict | None
) -> SlaPolicy:
    existing = session.execute(
        select(SlaPolicy).where(SlaPolicy.organization_id == org.id, SlaPolicy.is_default.is_(True))
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    payload = (data or {}).get("sla_policy") or {}
    row = SlaPolicy(
        organization_id=org.id,
        name=payload.get("name") or "Default SLA policy",
        description=payload.get("description") or "",
        applies_to=payload.get("applies_to") or {},
        response_minutes=payload.get("response_minutes") or dict(DEFAULT_RESPONSE_MINUTES),
        resolution_minutes=payload.get("resolution_minutes") or dict(DEFAULT_RESOLUTION_MINUTES),
        business_hours_id=business_hours.id,
        is_default=True,
        is_active=True,
    )
    session.add(row)
    session.flush()
    return row


def update_step(
    session: Session,
    org: Organization,
    actor_id: uuid.UUID,
    step: str,
    status: str,
    data: dict | None = None,
) -> OrgOnboarding:
    """Mark an onboarding step complete or skipped, applying step data."""
    if step not in ONBOARDING_STEPS:
        raise ValueError(f"Unknown onboarding step: {step}")
    if status not in ("complete", "skipped", "in_progress"):
        raise ValueError("status must be 'complete', 'skipped' or 'in_progress'")
    if status == "skipped" and step not in SKIPPABLE_STEPS:
        raise ValueError(f"Step '{step}' cannot be skipped")
    row = get_or_init_onboarding(session, org.id)
    if row.completed_at is not None:
        raise ValueError("Onboarding is already finished for this organization")

    if step == "finish" and status == "complete":
        pending = [s for s in ONBOARDING_STEPS if s != "finish" and row.steps.get(s) not in ("complete", "skipped")]
        if pending:
            raise ValueError(f"Cannot finish onboarding while steps are pending: {', '.join(pending)}")

    if step == "profile" and status == "complete" and data:
        for field in ("name", "contact_email", "website", "industry", "size"):
            if field in data and data[field] is not None:
                setattr(org, field, data[field])
    if step == "departments" and status == "complete" and data:
        for dept in data.get("departments") or []:
            try:
                org_service.create_department(session, org.id, dept.get("name", ""), dept.get("description", ""))
            except ValueError:
                continue  # already exists — onboarding is idempotent
    if step == "service_desk" and status == "complete" and data:
        settings = dict(org.settings or {})
        service_desk = dict(settings.get("service_desk") or {})
        service_desk.update(data.get("service_desk") or {})
        settings["service_desk"] = service_desk
        org.settings = settings
    if step == "business_hours_sla" and status == "complete":
        hours = _ensure_default_business_hours(session, org, data)
        _ensure_default_sla_policy(session, org, hours, data)

    steps = dict(row.steps or {})
    steps[step] = status
    row.steps = steps
    if step == "finish" and status == "complete":
        from datetime import datetime, timezone

        row.completed_at = datetime.now(timezone.utc)
        row.current_step = "finish"
        audit_mod.write_audit(
            session,
            organization_id=org.id,
            actor_id=actor_id,
            action=audit_mod.ONBOARDING_COMPLETED,
            resource_type="organization",
            resource_id=str(org.id),
            outcome="success",
            metadata={},
        )
    else:
        _advance(row)
        audit_mod.write_audit(
            session,
            organization_id=org.id,
            actor_id=actor_id,
            action=audit_mod.ONBOARDING_UPDATED,
            resource_type="organization",
            resource_id=str(org.id),
            outcome="success",
            metadata={"step": step, "status": status},
        )
    session.flush()
    return row
