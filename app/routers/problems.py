"""Problems, known errors, and major incidents — Phase 2 ITSM engine.

A problem may link to a known error (bidirectional: the known error
also points back at the problem). A major incident is declared from
an existing ticket. Static sub-routes are registered before the
``/{problem_id}`` routes so they are never captured as an id.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.itsm import KnownError, MajorIncident, Problem
from app.models.ticket import Ticket
from app.services.itsm_service import get_org_row, next_problem_number

router = APIRouter(prefix="/api/v1/problems", tags=["problems"])

PROBLEM_STATUSES = {"open", "investigating", "root_cause_identified", "resolved", "closed"}
PRIORITIES = {"low", "medium", "high", "critical"}
KE_STATUSES = {"active", "resolved"}
SEVERITIES = {"low", "medium", "high", "critical"}
INCIDENT_STATUSES = {"declared", "investigating", "mitigating", "resolved", "closed"}
PROBLEM_TRANSITIONS: dict[str, set[str]] = {
    "open": {"investigating", "resolved", "closed"},
    "investigating": {"root_cause_identified", "resolved", "closed"},
    "root_cause_identified": {"resolved", "closed"},
    "resolved": {"closed", "open"},
    "closed": set(),
}


class ProblemCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    priority: str = "medium"
    assignee_id: uuid.UUID | None = None
    root_cause: str | None = None
    workaround: str | None = None


class ProblemUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    description: str | None = None
    status: str | None = None
    priority: str | None = None
    assignee_id: uuid.UUID | None = None
    root_cause: str | None = None
    workaround: str | None = None


class ProblemOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    number: str
    title: str
    description: str
    status: str
    priority: str
    root_cause: str | None
    workaround: str | None
    known_error_id: uuid.UUID | None
    assignee_id: uuid.UUID | None
    requester_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class KnownErrorCreate(BaseModel):
    code: str = Field(min_length=1, max_length=20)
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    workaround: str = ""
    problem_id: uuid.UUID | None = None


class KnownErrorUpdate(BaseModel):
    code: str | None = Field(default=None, max_length=20)
    title: str | None = Field(default=None, max_length=255)
    description: str | None = None
    workaround: str | None = None
    status: str | None = None
    problem_id: uuid.UUID | None = None


class KnownErrorOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    code: str
    title: str
    description: str
    workaround: str
    status: str
    problem_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class LinkKnownErrorBody(BaseModel):
    known_error_id: uuid.UUID


class IncidentCreate(BaseModel):
    ticket_id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    severity: str = "high"
    commander_id: uuid.UUID | None = None
    summary: str = ""


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    severity: str | None = None
    status: str | None = None
    commander_id: uuid.UUID | None = None
    summary: str | None = None


class IncidentOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    ticket_id: uuid.UUID
    title: str
    severity: str
    status: str
    commander_id: uuid.UUID | None
    started_at: datetime
    resolved_at: datetime | None
    summary: str
    created_at: datetime
    updated_at: datetime


def _problem_out(p: Problem) -> ProblemOut:
    return ProblemOut(
        id=p.id,
        organization_id=p.organization_id,
        number=p.number,
        title=p.title,
        description=p.description,
        status=p.status,
        priority=p.priority,
        root_cause=p.root_cause,
        workaround=p.workaround,
        known_error_id=p.known_error_id,
        assignee_id=p.assignee_id,
        requester_id=p.requester_id,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


def _ke_out(k: KnownError) -> KnownErrorOut:
    return KnownErrorOut(
        id=k.id,
        organization_id=k.organization_id,
        code=k.code,
        title=k.title,
        description=k.description,
        workaround=k.workaround,
        status=k.status,
        problem_id=k.problem_id,
        created_at=k.created_at,
        updated_at=k.updated_at,
    )


def _incident_out(i: MajorIncident) -> IncidentOut:
    return IncidentOut(
        id=i.id,
        organization_id=i.organization_id,
        ticket_id=i.ticket_id,
        title=i.title,
        severity=i.severity,
        status=i.status,
        commander_id=i.commander_id,
        started_at=i.started_at,
        resolved_at=i.resolved_at,
        summary=i.summary,
        created_at=i.created_at,
        updated_at=i.updated_at,
    )


def _audit(session: Session, principal: Principal, action: str, resource_type: str, resource_id: str, **meta) -> None:
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="success",
        metadata=meta,
    )


# --- Known errors (static routes first) --------------------------------------


@router.get("/known-errors", response_model=list[KnownErrorOut])
def list_known_errors(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("problems:read"))
):
    rows = session.execute(
        select(KnownError).where(KnownError.organization_id == principal.organization_id).order_by(KnownError.code)
    ).scalars()
    return [_ke_out(k) for k in rows]


@router.post("/known-errors", response_model=KnownErrorOut, status_code=status.HTTP_201_CREATED)
def create_known_error(
    body: KnownErrorCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:manage")),
):
    clash = session.execute(
        select(KnownError).where(KnownError.organization_id == principal.organization_id, KnownError.code == body.code)
    ).scalar_one_or_none()
    if clash is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Code already in use in this organization")
    if body.problem_id is not None:
        problem = session.get(Problem, body.problem_id)
        if problem is None or problem.organization_id != principal.organization_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Problem not found")
    ke = KnownError(
        organization_id=principal.organization_id,
        code=body.code,
        title=body.title,
        description=body.description,
        workaround=body.workaround,
        problem_id=body.problem_id,
        status="active",
    )
    session.add(ke)
    session.flush()
    _audit(session, principal, audit_mod.KNOWN_ERROR_CREATED, "known_error", str(ke.id), code=ke.code)
    out = _ke_out(ke)
    session.commit()
    return out


@router.get("/known-errors/{ke_id}", response_model=KnownErrorOut)
def get_known_error(
    ke_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:read")),
):
    return _ke_out(get_org_row(session, KnownError, ke_id, principal.organization_id))


@router.patch("/known-errors/{ke_id}", response_model=KnownErrorOut)
def update_known_error(
    ke_id: uuid.UUID,
    body: KnownErrorUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:manage")),
):
    ke = get_org_row(session, KnownError, ke_id, principal.organization_id)
    if body.code is not None and body.code != ke.code:
        clash = session.execute(
            select(KnownError).where(
                KnownError.organization_id == principal.organization_id, KnownError.code == body.code
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Code already in use in this organization"
            )
        ke.code = body.code
    if body.status is not None:
        if body.status not in KE_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        ke.status = body.status
    if body.title is not None:
        ke.title = body.title
    if body.description is not None:
        ke.description = body.description
    if body.workaround is not None:
        ke.workaround = body.workaround
    if body.problem_id is not None:
        problem = session.get(Problem, body.problem_id)
        if problem is None or problem.organization_id != principal.organization_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Problem not found")
        ke.problem_id = body.problem_id
    _audit(session, principal, audit_mod.KNOWN_ERROR_UPDATED, "known_error", str(ke.id), code=ke.code)
    session.flush()
    out = _ke_out(ke)
    session.commit()
    return out


@router.delete("/known-errors/{ke_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_known_error(
    ke_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:manage")),
):
    ke = get_org_row(session, KnownError, ke_id, principal.organization_id)
    session.delete(ke)
    _audit(session, principal, audit_mod.KNOWN_ERROR_DELETED, "known_error", str(ke.id), code=ke.code)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Major incidents (static routes first) -------------------------------------


@router.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("incidents:manage"))
):
    rows = session.execute(
        select(MajorIncident)
        .where(MajorIncident.organization_id == principal.organization_id)
        .order_by(MajorIncident.created_at.desc())
    ).scalars()
    return [_incident_out(i) for i in rows]


@router.post("/incidents", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def declare_incident(
    body: IncidentCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("incidents:manage")),
):
    if body.severity not in SEVERITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid severity")
    ticket = session.get(Ticket, body.ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ticket not found")
    incident = MajorIncident(
        organization_id=principal.organization_id,
        ticket_id=ticket.id,
        title=body.title,
        severity=body.severity,
        commander_id=body.commander_id,
        summary=body.summary,
        status="declared",
        started_at=datetime.now(timezone.utc),
    )
    session.add(incident)
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.INCIDENT_DECLARED,
        "major_incident",
        str(incident.id),
        ticket_id=str(ticket.id),
        severity=incident.severity,
    )
    out = _incident_out(incident)
    session.commit()
    return out


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("incidents:manage")),
):
    return _incident_out(get_org_row(session, MajorIncident, incident_id, principal.organization_id))


@router.patch("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("incidents:manage")),
):
    incident = get_org_row(session, MajorIncident, incident_id, principal.organization_id)
    if body.status is not None:
        if body.status not in INCIDENT_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        incident.status = body.status
        if body.status in {"resolved", "closed"} and incident.resolved_at is None:
            incident.resolved_at = datetime.now(timezone.utc)
    if body.severity is not None:
        if body.severity not in SEVERITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid severity")
        incident.severity = body.severity
    if body.title is not None:
        incident.title = body.title
    if body.commander_id is not None:
        incident.commander_id = body.commander_id
    if body.summary is not None:
        incident.summary = body.summary
    _audit(session, principal, audit_mod.INCIDENT_UPDATED, "major_incident", str(incident.id), status=incident.status)
    session.flush()
    out = _incident_out(incident)
    session.commit()
    return out


# --- Problems -------------------------------------------------------------------


@router.get("", response_model=list[ProblemOut])
def list_problems(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("problems:read"))
):
    rows = session.execute(
        select(Problem).where(Problem.organization_id == principal.organization_id).order_by(Problem.created_at.desc())
    ).scalars()
    return [_problem_out(p) for p in rows]


@router.post("", response_model=ProblemOut, status_code=status.HTTP_201_CREATED)
def create_problem(
    body: ProblemCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:create")),
):
    if body.priority not in PRIORITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
    problem = Problem(
        organization_id=principal.organization_id,
        number=next_problem_number(session, principal.organization_id),
        title=body.title,
        description=body.description,
        priority=body.priority,
        assignee_id=body.assignee_id,
        root_cause=body.root_cause,
        workaround=body.workaround,
        requester_id=principal.user_id,
        status="open",
    )
    session.add(problem)
    session.flush()
    _audit(session, principal, audit_mod.PROBLEM_CREATED, "problem", str(problem.id), number=problem.number)
    out = _problem_out(problem)
    session.commit()
    return out


@router.get("/{problem_id}", response_model=ProblemOut)
def get_problem(
    problem_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:read")),
):
    return _problem_out(get_org_row(session, Problem, problem_id, principal.organization_id))


@router.patch("/{problem_id}", response_model=ProblemOut)
def update_problem(
    problem_id: uuid.UUID,
    body: ProblemUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:manage")),
):
    problem = get_org_row(session, Problem, problem_id, principal.organization_id)
    if body.status is not None:
        if body.status not in PROBLEM_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        if body.status != problem.status and body.status not in PROBLEM_TRANSITIONS.get(problem.status, set()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot move problem from {problem.status} to {body.status}",
            )
        problem.status = body.status
    if body.priority is not None:
        if body.priority not in PRIORITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
        problem.priority = body.priority
    if body.title is not None:
        problem.title = body.title
    if body.description is not None:
        problem.description = body.description
    if body.assignee_id is not None:
        problem.assignee_id = body.assignee_id
    if body.root_cause is not None:
        problem.root_cause = body.root_cause
    if body.workaround is not None:
        problem.workaround = body.workaround
    _audit(session, principal, audit_mod.PROBLEM_UPDATED, "problem", str(problem.id), status=problem.status)
    session.flush()
    out = _problem_out(problem)
    session.commit()
    return out


@router.delete("/{problem_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_problem(
    problem_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:manage")),
):
    problem = get_org_row(session, Problem, problem_id, principal.organization_id)
    session.delete(problem)
    _audit(session, principal, audit_mod.PROBLEM_UPDATED, "problem", str(problem.id), deleted=True)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{problem_id}/link-known-error", response_model=ProblemOut)
def link_known_error(
    problem_id: uuid.UUID,
    body: LinkKnownErrorBody,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("problems:manage")),
):
    problem = get_org_row(session, Problem, problem_id, principal.organization_id)
    ke = session.get(KnownError, body.known_error_id)
    if ke is None or ke.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Known error not found")
    problem.known_error_id = ke.id
    ke.problem_id = problem.id
    _audit(
        session,
        principal,
        audit_mod.KNOWN_ERROR_LINKED,
        "problem",
        str(problem.id),
        known_error_id=str(ke.id),
    )
    session.flush()
    out = _problem_out(problem)
    session.commit()
    return out
