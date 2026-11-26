"""GRC routes: controls, framework mappings, evidence, assessments,
exceptions.

Permissions: ``compliance:read`` / ``compliance:manage`` (both exist in
the org permission catalog). Control ``status`` is derived from
assessments and exceptions by ``app.services.grc_service`` — the API
never accepts it from a client, and a ``satisfied`` control is a
recorded assessment outcome, not a compliance certification.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.grc import (
    ASSESSMENT_STATUSES,
    FRAMEWORKS,
    GrcAssessment,
    GrcAssessmentControl,
    GrcControl,
    GrcControlMapping,
    GrcEvidence,
    GrcException,
)
from app.models.platform import Membership
from app.services import grc_service, linking_service

UTC = timezone.utc

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])

EVIDENCE_TYPES = {"reference", "link", "document"}


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class ControlCreate(BaseModel):
    code: str = Field(min_length=1, max_length=50)
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    category: str | None = None
    owner_id: uuid.UUID | None = None


class ControlUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    owner_id: uuid.UUID | None = None


class MappingCreate(BaseModel):
    framework: str
    clause: str = Field(min_length=1, max_length=100)
    notes: str = ""


class MappingOut(BaseModel):
    id: uuid.UUID
    control_id: uuid.UUID
    framework: str
    clause: str
    notes: str
    created_at: datetime


class EvidenceCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    evidence_type: str = "reference"
    reference: str | None = None
    linked_entity_type: str | None = None
    linked_entity_id: uuid.UUID | None = None
    notes: str = ""


class EvidenceOut(BaseModel):
    id: uuid.UUID
    control_id: uuid.UUID
    title: str
    evidence_type: str
    reference: str | None
    linked_entity_type: str | None
    linked_entity_id: uuid.UUID | None
    notes: str
    collected_by_id: uuid.UUID | None
    collected_at: datetime | None
    created_at: datetime


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    control_ids: list[uuid.UUID] = Field(min_length=1)
    status: str = "in_progress"
    summary: str = ""
    findings: list[dict] = []
    assessed_at: datetime | None = None


class AssessmentUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    summary: str | None = None
    findings: list[dict] | None = None
    assessed_at: datetime | None = None


class AssessmentOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    status: str
    summary: str
    findings: list
    assessor_id: uuid.UUID | None
    assessed_at: datetime | None
    control_ids: list[uuid.UUID]
    created_at: datetime
    updated_at: datetime


class ExceptionCreate(BaseModel):
    reason: str = Field(min_length=1)
    approver_id: uuid.UUID | None = None
    expires_at: datetime


class ExceptionOut(BaseModel):
    id: uuid.UUID
    control_id: uuid.UUID
    reason: str
    approver_id: uuid.UUID | None
    expires_at: datetime
    revoked_at: datetime | None
    status: str
    created_at: datetime


class ControlOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    code: str
    title: str
    description: str
    category: str | None
    owner_id: uuid.UUID | None
    status: str
    created_at: datetime
    updated_at: datetime


class ControlDetailOut(ControlOut):
    mappings: list[MappingOut] = []
    evidence: list[EvidenceOut] = []
    exceptions: list[ExceptionOut] = []
    latest_assessment: AssessmentOut | None = None


# --- Helpers ----------------------------------------------------------------


def _audit(
    session: Session,
    principal: Principal,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict | None = None,
):
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="success",
        metadata=metadata or {},
    )


def _get_control(session: Session, org_id: uuid.UUID, control_id: uuid.UUID) -> GrcControl:
    control = session.get(GrcControl, control_id)
    if control is None or control.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")
    return control


def _mapping_out(m: GrcControlMapping) -> MappingOut:
    return MappingOut(
        id=m.id,
        control_id=m.control_id,
        framework=m.framework,
        clause=m.clause,
        notes=m.notes,
        created_at=m.created_at,
    )


def _evidence_out(e: GrcEvidence) -> EvidenceOut:
    return EvidenceOut(
        id=e.id,
        control_id=e.control_id,
        title=e.title,
        evidence_type=e.evidence_type,
        reference=e.reference,
        linked_entity_type=e.linked_entity_type,
        linked_entity_id=e.linked_entity_id,
        notes=e.notes,
        collected_by_id=e.collected_by_id,
        collected_at=e.collected_at,
        created_at=e.created_at,
    )


def _exception_out(e: GrcException) -> ExceptionOut:
    return ExceptionOut(
        id=e.id,
        control_id=e.control_id,
        reason=e.reason,
        approver_id=e.approver_id,
        expires_at=e.expires_at,
        revoked_at=e.revoked_at,
        status=grc_service.effective_exception_status(e),
        created_at=e.created_at,
    )


def _latest_assessment(session: Session, org_id: uuid.UUID, control_id: uuid.UUID) -> GrcAssessment | None:
    return session.execute(
        select(GrcAssessment)
        .join(GrcAssessmentControl, GrcAssessmentControl.assessment_id == GrcAssessment.id)
        .where(
            GrcAssessment.organization_id == org_id,
            GrcAssessmentControl.control_id == control_id,
        )
        .order_by(GrcAssessment.assessed_at.desc().nullslast(), GrcAssessment.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _assessment_out(session: Session, a: GrcAssessment) -> AssessmentOut:
    return AssessmentOut(
        id=a.id,
        organization_id=a.organization_id,
        name=a.name,
        status=a.status,
        summary=a.summary,
        findings=a.findings or [],
        assessor_id=a.assessor_id,
        assessed_at=a.assessed_at,
        control_ids=grc_service.controls_for_assessment(session, a.id),
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


def _control_detail(session: Session, org_id: uuid.UUID, c: GrcControl) -> ControlDetailOut:
    mappings = (
        session.execute(
            select(GrcControlMapping)
            .where(GrcControlMapping.control_id == c.id)
            .order_by(GrcControlMapping.framework, GrcControlMapping.clause)
        )
        .scalars()
        .all()
    )
    evidence = (
        session.execute(
            select(GrcEvidence).where(GrcEvidence.control_id == c.id).order_by(GrcEvidence.created_at)
        )
        .scalars()
        .all()
    )
    exceptions = (
        session.execute(
            select(GrcException).where(GrcException.control_id == c.id).order_by(GrcException.created_at.desc())
        )
        .scalars()
        .all()
    )
    latest = _latest_assessment(session, org_id, c.id)
    return ControlDetailOut(
        id=c.id,
        organization_id=c.organization_id,
        code=c.code,
        title=c.title,
        description=c.description,
        category=c.category,
        owner_id=c.owner_id,
        status=c.status,
        created_at=c.created_at,
        updated_at=c.updated_at,
        mappings=[_mapping_out(m) for m in mappings],
        evidence=[_evidence_out(e) for e in evidence],
        exceptions=[_exception_out(e) for e in exceptions],
        latest_assessment=_assessment_out(session, latest) if latest else None,
    )


def _control_out(c: GrcControl) -> ControlOut:
    return ControlOut(
        id=c.id,
        organization_id=c.organization_id,
        code=c.code,
        title=c.title,
        description=c.description,
        category=c.category,
        owner_id=c.owner_id,
        status=c.status,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _check_member(session: Session, org_id: uuid.UUID, user_id: uuid.UUID, what: str) -> None:
    member = session.execute(
        select(Membership).where(
            Membership.organization_id == org_id,
            Membership.user_id == user_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} is not a member of this organization"
        )


# --- Controls ---------------------------------------------------------------


@router.get("/summary", response_model=dict)
def control_summary(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("compliance:read"))
):
    rows = (
        session.execute(
            select(GrcControl.status, func.count())
            .where(GrcControl.organization_id == principal.organization_id)
            .group_by(GrcControl.status)
        )
        .all()
    )
    by_status = {row[0]: row[1] for row in rows}
    return {"total": sum(by_status.values()), "by_status": by_status}


@router.get("/controls", response_model=list[ControlOut])
def list_controls(
    status_filter: str | None = None,
    framework: str | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:read")),
):
    query = select(GrcControl).where(GrcControl.organization_id == principal.organization_id)
    if status_filter is not None:
        if status_filter not in grc_service.CONTROL_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid control status")
        query = query.where(GrcControl.status == status_filter)
    if framework is not None:
        if framework not in FRAMEWORKS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid framework")
        query = query.join(GrcControlMapping, GrcControlMapping.control_id == GrcControl.id).where(
            GrcControlMapping.framework == framework
        )
    rows = session.execute(query.order_by(GrcControl.code)).scalars().all()
    return [_control_out(c) for c in rows]


@router.post("/controls", response_model=ControlOut, status_code=status.HTTP_201_CREATED)
def create_control(
    body: ControlCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    if body.owner_id is not None:
        _check_member(session, principal.organization_id, body.owner_id, "Owner")
    control = GrcControl(
        organization_id=principal.organization_id,
        code=body.code,
        title=body.title,
        description=body.description,
        category=body.category,
        owner_id=body.owner_id,
    )
    session.add(control)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=f"Control code {body.code} already exists"
        )
    _audit(session, principal, audit_mod.GRC_CONTROL_CREATED, "grc_control", str(control.id), {"code": body.code})
    out = _control_out(control)
    session.commit()
    return out


@router.get("/controls/{control_id}", response_model=ControlDetailOut)
def get_control(
    control_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:read")),
):
    control = _get_control(session, principal.organization_id, control_id)
    return _control_detail(session, principal.organization_id, control)


@router.patch("/controls/{control_id}", response_model=ControlOut)
def update_control(
    control_id: uuid.UUID,
    body: ControlUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    control = _get_control(session, principal.organization_id, control_id)
    if body.title is not None:
        control.title = body.title
    if body.description is not None:
        control.description = body.description
    if body.category is not None:
        control.category = body.category
    if body.owner_id is not None:
        _check_member(session, principal.organization_id, body.owner_id, "Owner")
        control.owner_id = body.owner_id
    session.flush()
    _audit(session, principal, audit_mod.GRC_CONTROL_UPDATED, "grc_control", str(control.id), {"code": control.code})
    out = _control_out(control)
    session.commit()
    return out


@router.delete("/controls/{control_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_control(
    control_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    control = _get_control(session, principal.organization_id, control_id)
    code = control.code
    session.delete(control)
    session.flush()
    _audit(session, principal, audit_mod.GRC_CONTROL_DELETED, "grc_control", str(control.id), {"code": code})
    session.commit()
    return None


# --- Framework mappings -------------------------------------------------------


@router.post("/controls/{control_id}/mappings", response_model=MappingOut, status_code=status.HTTP_201_CREATED)
def create_mapping(
    control_id: uuid.UUID,
    body: MappingCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    control = _get_control(session, principal.organization_id, control_id)
    if body.framework not in FRAMEWORKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid framework: {body.framework} (expected one of soc2, iso27001, nist_csf, cis)",
        )
    mapping = GrcControlMapping(
        organization_id=principal.organization_id,
        control_id=control.id,
        framework=body.framework,
        clause=body.clause,
        notes=body.notes,
    )
    session.add(mapping)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Control already maps to {body.framework} {body.clause}",
        )
    _audit(
        session,
        principal,
        audit_mod.GRC_MAPPING_CREATED,
        "grc_control_mapping",
        str(mapping.id),
        {"control_id": str(control.id), "framework": body.framework, "clause": body.clause},
    )
    out = _mapping_out(mapping)
    session.commit()
    return out


@router.delete("/controls/{control_id}/mappings/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_mapping(
    control_id: uuid.UUID,
    mapping_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    control = _get_control(session, principal.organization_id, control_id)
    mapping = session.get(GrcControlMapping, mapping_id)
    if mapping is None or mapping.control_id != control.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mapping not found")
    session.delete(mapping)
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.GRC_MAPPING_DELETED,
        "grc_control_mapping",
        str(mapping.id),
        {"control_id": str(control.id)},
    )
    session.commit()
    return None


# --- Evidence -----------------------------------------------------------------


@router.get("/controls/{control_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(
    control_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:read")),
):
    control = _get_control(session, principal.organization_id, control_id)
    rows = (
        session.execute(
            select(GrcEvidence).where(GrcEvidence.control_id == control.id).order_by(GrcEvidence.created_at)
        )
        .scalars()
        .all()
    )
    return [_evidence_out(e) for e in rows]


@router.post("/controls/{control_id}/evidence", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED)
def create_evidence(
    control_id: uuid.UUID,
    body: EvidenceCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    control = _get_control(session, principal.organization_id, control_id)
    if body.evidence_type not in EVIDENCE_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid evidence type")
    if body.linked_entity_type is not None or body.linked_entity_id is not None:
        if body.linked_entity_type is None or body.linked_entity_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="linked_entity_type and linked_entity_id must be provided together",
            )
        try:
            linking_service.validate_entity(
                session, principal.organization_id, body.linked_entity_type, body.linked_entity_id
            )
        except linking_service.UnknownEntityType as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        except linking_service.EntityNotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    evidence = GrcEvidence(
        organization_id=principal.organization_id,
        control_id=control.id,
        title=body.title,
        evidence_type=body.evidence_type,
        reference=body.reference,
        linked_entity_type=body.linked_entity_type,
        linked_entity_id=body.linked_entity_id,
        notes=body.notes,
        collected_by_id=principal.user_id,
        collected_at=datetime.now(UTC),
    )
    session.add(evidence)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Evidence titled {body.title!r} already exists for this control",
        )
    _audit(
        session,
        principal,
        audit_mod.GRC_EVIDENCE_CREATED,
        "grc_evidence",
        str(evidence.id),
        {"control_id": str(control.id), "title": body.title},
    )
    out = _evidence_out(evidence)
    session.commit()
    return out


@router.delete("/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_evidence(
    evidence_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    evidence = session.get(GrcEvidence, evidence_id)
    if evidence is None or evidence.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    control_id = evidence.control_id
    session.delete(evidence)
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.GRC_EVIDENCE_DELETED,
        "grc_evidence",
        str(evidence.id),
        {"control_id": str(control_id)},
    )
    session.commit()
    return None


# --- Assessments --------------------------------------------------------------


@router.get("/assessments", response_model=list[AssessmentOut])
def list_assessments(
    control_id: uuid.UUID | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:read")),
):
    query = select(GrcAssessment).where(GrcAssessment.organization_id == principal.organization_id)
    if control_id is not None:
        query = query.join(
            GrcAssessmentControl, GrcAssessmentControl.assessment_id == GrcAssessment.id
        ).where(GrcAssessmentControl.control_id == control_id)
    rows = session.execute(query.order_by(GrcAssessment.created_at.desc())).scalars().all()
    return [_assessment_out(session, a) for a in rows]


@router.post("/assessments", response_model=AssessmentOut, status_code=status.HTTP_201_CREATED)
def create_assessment(
    body: AssessmentCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    if body.status not in ASSESSMENT_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid assessment status")
    controls = []
    for control_id in dict.fromkeys(body.control_ids):
        controls.append(_get_control(session, principal.organization_id, control_id))
    assessment = GrcAssessment(
        organization_id=principal.organization_id,
        name=body.name,
        status=body.status,
        summary=body.summary,
        findings=body.findings,
        assessor_id=principal.user_id,
        assessed_at=body.assessed_at or datetime.now(UTC),
    )
    session.add(assessment)
    session.flush()
    for control in controls:
        session.add(
            GrcAssessmentControl(
                organization_id=principal.organization_id,
                assessment_id=assessment.id,
                control_id=control.id,
            )
        )
    session.flush()
    for control in controls:
        grc_service.refresh_control_status(session, control)
    _audit(
        session,
        principal,
        audit_mod.GRC_ASSESSMENT_CREATED,
        "grc_assessment",
        str(assessment.id),
        {"name": body.name, "status": body.status, "control_ids": [str(c.id) for c in controls]},
    )
    out = _assessment_out(session, assessment)
    session.commit()
    return out


@router.get("/assessments/{assessment_id}", response_model=AssessmentOut)
def get_assessment(
    assessment_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:read")),
):
    assessment = session.get(GrcAssessment, assessment_id)
    if assessment is None or assessment.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return _assessment_out(session, assessment)


@router.patch("/assessments/{assessment_id}", response_model=AssessmentOut)
def update_assessment(
    assessment_id: uuid.UUID,
    body: AssessmentUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    assessment = session.get(GrcAssessment, assessment_id)
    if assessment is None or assessment.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    if body.status is not None:
        if body.status not in ASSESSMENT_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid assessment status")
        assessment.status = body.status
    if body.name is not None:
        assessment.name = body.name
    if body.summary is not None:
        assessment.summary = body.summary
    if body.findings is not None:
        assessment.findings = body.findings
    if body.assessed_at is not None:
        assessment.assessed_at = body.assessed_at
    session.flush()
    grc_service.refresh_controls_for_assessment(session, assessment)
    _audit(
        session,
        principal,
        audit_mod.GRC_ASSESSMENT_UPDATED,
        "grc_assessment",
        str(assessment.id),
        {"name": assessment.name, "status": assessment.status},
    )
    out = _assessment_out(session, assessment)
    session.commit()
    return out


# --- Exceptions ---------------------------------------------------------------


@router.get("/controls/{control_id}/exceptions", response_model=list[ExceptionOut])
def list_exceptions(
    control_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:read")),
):
    control = _get_control(session, principal.organization_id, control_id)
    rows = (
        session.execute(
            select(GrcException).where(GrcException.control_id == control.id).order_by(GrcException.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_exception_out(e) for e in rows]


@router.post("/controls/{control_id}/exceptions", response_model=ExceptionOut, status_code=status.HTTP_201_CREATED)
def create_exception(
    control_id: uuid.UUID,
    body: ExceptionCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    control = _get_control(session, principal.organization_id, control_id)
    if body.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be in the future")
    approver_id = body.approver_id or principal.user_id
    _check_member(session, principal.organization_id, approver_id, "Approver")
    exception = GrcException(
        organization_id=principal.organization_id,
        control_id=control.id,
        reason=body.reason,
        approver_id=approver_id,
        expires_at=body.expires_at,
        created_by_id=principal.user_id,
    )
    session.add(exception)
    session.flush()
    grc_service.refresh_control_status(session, control)
    _audit(
        session,
        principal,
        audit_mod.GRC_EXCEPTION_CREATED,
        "grc_exception",
        str(exception.id),
        {"control_id": str(control.id), "expires_at": body.expires_at.isoformat()},
    )
    out = _exception_out(exception)
    session.commit()
    return out


@router.post("/exceptions/{exception_id}/revoke", response_model=ExceptionOut)
def revoke_exception(
    exception_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("compliance:manage")),
):
    exception = session.get(GrcException, exception_id)
    if exception is None or exception.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exception not found")
    if exception.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Exception is already revoked")
    exception.revoked_at = datetime.now(UTC)
    exception.revoked_by_id = principal.user_id
    session.flush()
    control = session.get(GrcControl, exception.control_id)
    if control is not None:
        grc_service.refresh_control_status(session, control)
    _audit(
        session,
        principal,
        audit_mod.GRC_EXCEPTION_REVOKED,
        "grc_exception",
        str(exception.id),
        {"control_id": str(exception.control_id)},
    )
    out = _exception_out(exception)
    session.commit()
    return out
