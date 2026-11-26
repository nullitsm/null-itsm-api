"""GRC service: derived control status (Phase 4 workstream D).

A control's status is never written by a client. It is derived here,
from the latest assessment covering the control and from active
exceptions:

* active (unexpired, unrevoked) exception -> ``exception``
* latest assessment ``passed``             -> ``satisfied``
* latest assessment ``failed``             -> ``failed``
* latest assessment ``in_progress``        -> ``in_progress``
* no assessment                            -> ``not_assessed``

``satisfied`` means only that the latest assessment of that control
passed on the evidence recorded at the time. It is not a compliance
certification of anything, and this module never claims otherwise.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.grc import (
    GrcAssessment,
    GrcAssessmentControl,
    GrcControl,
    GrcException,
)

UTC = timezone.utc

_ASSESSMENT_TO_CONTROL_STATUS = {
    "passed": "satisfied",
    "failed": "failed",
    "in_progress": "in_progress",
}


def effective_exception_status(exc: GrcException, now: datetime | None = None) -> str:
    """Derived exception status: revoked | expired | active."""
    now = now or datetime.now(UTC)
    if exc.revoked_at is not None:
        return "revoked"
    if exc.expires_at is not None and exc.expires_at <= now:
        return "expired"
    return "active"


def derive_control_status(session: Session, org_id: uuid.UUID, control_id: uuid.UUID) -> str:
    """Compute a control's status from its exceptions + assessments."""
    now = datetime.now(UTC)
    exceptions = (
        session.execute(
            select(GrcException).where(
                GrcException.organization_id == org_id, GrcException.control_id == control_id
            )
        )
        .scalars()
        .all()
    )
    if any(effective_exception_status(exc, now) == "active" for exc in exceptions):
        return "exception"
    latest = session.execute(
        select(GrcAssessment)
        .join(GrcAssessmentControl, GrcAssessmentControl.assessment_id == GrcAssessment.id)
        .where(
            GrcAssessment.organization_id == org_id,
            GrcAssessmentControl.control_id == control_id,
        )
        .order_by(GrcAssessment.assessed_at.desc().nullslast(), GrcAssessment.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if latest is None:
        return "not_assessed"
    return _ASSESSMENT_TO_CONTROL_STATUS.get(latest.status, "not_assessed")


def refresh_control_status(session: Session, control: GrcControl) -> str:
    """Recompute and store one control's derived status. Returns it."""
    control.status = derive_control_status(session, control.organization_id, control.id)
    session.flush()
    return control.status


def refresh_controls_for_assessment(session: Session, assessment: GrcAssessment) -> None:
    """Recompute the derived status of every control an assessment covers."""
    control_ids = (
        session.execute(
            select(GrcAssessmentControl.control_id).where(
                GrcAssessmentControl.assessment_id == assessment.id
            )
        )
        .scalars()
        .all()
    )
    for control_id in control_ids:
        control = session.get(GrcControl, control_id)
        if control is not None and control.organization_id == assessment.organization_id:
            refresh_control_status(session, control)


def controls_for_assessment(session: Session, assessment_id: uuid.UUID) -> list[uuid.UUID]:
    """Control ids covered by one assessment, in attach order."""
    return (
        session.execute(
            select(GrcAssessmentControl.control_id)
            .where(GrcAssessmentControl.assessment_id == assessment_id)
            .order_by(GrcAssessmentControl.created_at)
        )
        .scalars()
        .all()
    )
