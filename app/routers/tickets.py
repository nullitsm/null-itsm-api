"""Tickets — Phase 1 tenant-isolation proof domain.

Minimal CRUD backed by the RLS-scoped ``tickets`` table. Phase 2 extends
this module (SLA, comments, attachments, workflow). Ticket numbers are
per-organization (INC-000001, ...) via a row-locked counter.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.itsm import (
    Change,
    Problem,
    RecurringTicket,
    ServiceRequest,
    Survey,
    SurveyResponse,
    TicketAttachment,
    TicketComment,
    TicketLink,
    TicketTemplate,
)
from app.models.ticket import Ticket, TicketCounter
from app.schemas import TicketCreate, TicketOut, TicketUpdate
from app.services import automation_service, sla_service, webhook_service
from app.services.itsm_service import compute_next_run, get_org_row, validate_schedule
from app.services.storage import StorageError, get_storage

router = APIRouter(prefix="/api/v1/tickets", tags=["tickets"])

VALID_STATUSES = {"open", "in_progress", "pending", "resolved", "closed"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}


def _ticket_out(t: Ticket) -> TicketOut:
    return TicketOut(
        id=t.id,
        organization_id=t.organization_id,
        number=t.number,
        title=t.title,
        description=t.description,
        status=t.status,
        priority=t.priority,
        category=t.category,
        requester_id=t.requester_id,
        assignee_id=t.assignee_id,
        created_at=t.created_at,
        updated_at=t.updated_at,
        first_response_due_at=t.first_response_due_at,
        resolution_due_at=t.resolution_due_at,
        first_response_at=t.first_response_at,
        resolved_at=t.resolved_at,
        sla_policy_id=t.sla_policy_id,
        sla_breached=t.sla_breached,
    )


def _next_number(session: Session, org_id: uuid.UUID) -> str:
    counter = session.execute(
        select(TicketCounter).where(TicketCounter.organization_id == org_id).with_for_update()
    ).scalar_one_or_none()
    if counter is None:
        counter = TicketCounter(organization_id=org_id, last_number=0)
        session.add(counter)
        session.flush()
    counter.last_number += 1
    return f"INC-{counter.last_number:06d}"


@router.get("", response_model=list[TicketOut])
def list_tickets(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("tickets:read"))
):
    rows = session.execute(
        select(Ticket).where(Ticket.organization_id == principal.organization_id).order_by(Ticket.created_at.desc())
    ).scalars()
    return [_ticket_out(t) for t in rows]


@router.post("", response_model=TicketOut, status_code=status.HTTP_201_CREATED)
def create_ticket(
    body: TicketCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:create")),
):
    if body.priority not in VALID_PRIORITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
    ticket = Ticket(
        organization_id=principal.organization_id,
        number=_next_number(session, principal.organization_id),
        title=body.title,
        description=body.description,
        priority=body.priority,
        category=body.category,
        requester_id=principal.user_id,
        status="open",
    )
    session.add(ticket)
    session.flush()
    # Stamp SLA due dates immediately (Phase 2): the 5-minute breach
    # sweep would do this eventually, but the ticket should carry its due
    # dates from creation. stamp_sla_state flushes, never commits; when
    # no SLA policy matches, the ticket simply has no due dates.
    sla_service.stamp_sla_state(session, principal.organization_id, ticket)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.TICKET_CREATED,
        resource_type="ticket",
        resource_id=str(ticket.id),
        outcome="success",
        metadata={"number": ticket.number},
    )
    # Automation (Phase 4): rules fire against the real ticket before the
    # response is built, so an action such as assign/set_priority is
    # reflected in the returned ticket. A failing action is recorded on
    # the AutomationRun, never raised — ticket creation still succeeds.
    automation_service.evaluate_rules(
        session,
        org_id=principal.organization_id,
        trigger="ticket.created",
        entity_type="ticket",
        entity_id=ticket.id,
        actor_id=principal.user_id,
    )
    # Build the payload AND the response BEFORE commit: the RLS context
    # is SET LOCAL to this transaction and dies at commit, so any
    # attribute that needs a refresh after commit (e.g. server-computed
    # updated_at) would fail.
    payload = {
        "ticket_id": str(ticket.id),
        "number": ticket.number,
        "title": ticket.title,
        "status": ticket.status,
        "priority": ticket.priority,
        "category": ticket.category,
    }
    out = _ticket_out(ticket)
    session.commit()
    # Webhooks (Phase 4): best-effort post-commit fan-out in a fresh
    # tenant session; never fails the request.
    webhook_service.emit_event(
        principal.organization_id, "ticket.created", payload, user_id=principal.user_id
    )
    return out


# --- Ticket templates / recurring tickets / surveys (Phase 2) -------------
# These static routes are registered BEFORE the "/{ticket_id}" routes
# below: Starlette matches in registration order, and a single-segment
# GET such as /tickets/templates would otherwise be captured by
# "/{ticket_id}" and fail UUID validation.

TEMPLATE_PRIORITIES = {"low", "medium", "high", "critical"}


class TemplateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    category: str = "General"
    priority: str = "medium"
    default_assignee_id: uuid.UUID | None = None
    form_schema: dict = {}
    is_active: bool = True


class TemplateUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    category: str | None = Field(default=None, max_length=50)
    priority: str | None = None
    default_assignee_id: uuid.UUID | None = None
    form_schema: dict | None = None
    is_active: bool | None = None


class TemplateOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    category: str
    priority: str
    default_assignee_id: uuid.UUID | None
    form_schema: dict
    is_active: bool
    created_at: datetime
    updated_at: datetime


class RecurringCreate(BaseModel):
    template_id: uuid.UUID
    schedule: dict
    is_active: bool = True


class RecurringUpdate(BaseModel):
    schedule: dict | None = None
    is_active: bool | None = None


class RecurringOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    template_id: uuid.UUID
    schedule: dict
    next_run_at: datetime | None
    last_run_at: datetime | None
    is_active: bool
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class SurveyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    target_type: str = "ticket"
    questions: list = []
    is_active: bool = True


class SurveyUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    target_type: str | None = None
    questions: list | None = None
    is_active: bool | None = None


class SurveyOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    target_type: str
    questions: list
    is_active: bool
    created_at: datetime
    updated_at: datetime


class SurveyResponseCreate(BaseModel):
    target_type: str
    target_id: uuid.UUID
    answers: dict = {}
    score: int | None = None


class SurveyResponseOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    survey_id: uuid.UUID
    target_type: str
    target_id: uuid.UUID
    respondent_id: uuid.UUID | None
    answers: dict
    score: int | None
    submitted_at: datetime
    created_at: datetime


def _template_out(t: TicketTemplate) -> TemplateOut:
    return TemplateOut(
        id=t.id,
        organization_id=t.organization_id,
        name=t.name,
        description=t.description,
        category=t.category,
        priority=t.priority,
        default_assignee_id=t.default_assignee_id,
        form_schema=t.form_schema or {},
        is_active=t.is_active,
        created_at=t.created_at,
        updated_at=t.updated_at,
    )


def _recurring_out(r: RecurringTicket) -> RecurringOut:
    return RecurringOut(
        id=r.id,
        organization_id=r.organization_id,
        template_id=r.template_id,
        schedule=r.schedule or {},
        next_run_at=r.next_run_at,
        last_run_at=r.last_run_at,
        is_active=r.is_active,
        created_by_id=r.created_by_id,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _survey_out(s: Survey) -> SurveyOut:
    return SurveyOut(
        id=s.id,
        organization_id=s.organization_id,
        name=s.name,
        description=s.description,
        target_type=s.target_type,
        questions=s.questions or [],
        is_active=s.is_active,
        created_at=s.created_at,
        updated_at=s.updated_at,
    )


def _response_out(r: SurveyResponse) -> SurveyResponseOut:
    return SurveyResponseOut(
        id=r.id,
        organization_id=r.organization_id,
        survey_id=r.survey_id,
        target_type=r.target_type,
        target_id=r.target_id,
        respondent_id=r.respondent_id,
        answers=r.answers or {},
        score=r.score,
        submitted_at=r.submitted_at,
        created_at=r.created_at,
    )


def _audit_tickets(
    session: Session, principal: Principal, action: str, resource_type: str, resource_id: str, **meta
) -> None:
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


@router.get("/templates", response_model=list[TemplateOut])
def list_templates(
    session: Session = Depends(get_db),
    # No templates:read code exists in the catalog; all template
    # administration is gated on templates:manage.
    principal: Principal = Depends(require_permission("templates:manage")),
):
    rows = session.execute(
        select(TicketTemplate)
        .where(TicketTemplate.organization_id == principal.organization_id)
        .order_by(TicketTemplate.name)
    ).scalars()
    return [_template_out(t) for t in rows]


@router.post("/templates", response_model=TemplateOut, status_code=status.HTTP_201_CREATED)
def create_template(
    body: TemplateCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    if body.priority not in TEMPLATE_PRIORITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
    template = TicketTemplate(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        category=body.category,
        priority=body.priority,
        default_assignee_id=body.default_assignee_id,
        form_schema=body.form_schema or {},
        is_active=body.is_active,
    )
    session.add(template)
    session.flush()
    _audit_tickets(
        session, principal, audit_mod.TEMPLATE_CREATED, "ticket_template", str(template.id), name=template.name
    )
    out = _template_out(template)
    session.commit()
    return out


@router.get("/templates/{template_id}", response_model=TemplateOut)
def get_template(
    template_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    return _template_out(get_org_row(session, TicketTemplate, template_id, principal.organization_id))


@router.patch("/templates/{template_id}", response_model=TemplateOut)
def update_template(
    template_id: uuid.UUID,
    body: TemplateUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    template = get_org_row(session, TicketTemplate, template_id, principal.organization_id)
    if body.priority is not None:
        if body.priority not in TEMPLATE_PRIORITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
        template.priority = body.priority
    if body.name is not None:
        template.name = body.name
    if body.description is not None:
        template.description = body.description
    if body.category is not None:
        template.category = body.category
    if body.default_assignee_id is not None:
        template.default_assignee_id = body.default_assignee_id
    if body.form_schema is not None:
        template.form_schema = body.form_schema
    if body.is_active is not None:
        template.is_active = body.is_active
    _audit_tickets(
        session, principal, audit_mod.TEMPLATE_UPDATED, "ticket_template", str(template.id), name=template.name
    )
    session.flush()
    out = _template_out(template)
    session.commit()
    return out


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_template(
    template_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    template = get_org_row(session, TicketTemplate, template_id, principal.organization_id)
    session.delete(template)
    _audit_tickets(
        session, principal, audit_mod.TEMPLATE_DELETED, "ticket_template", str(template.id), name=template.name
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/recurring/due", response_model=list[RecurringOut])
def list_due_recurring(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    now = datetime.now(timezone.utc)
    rows = session.execute(
        select(RecurringTicket).where(
            RecurringTicket.organization_id == principal.organization_id,
            RecurringTicket.is_active.is_(True),
            RecurringTicket.next_run_at.is_not(None),
            RecurringTicket.next_run_at <= now,
        )
    ).scalars()
    return [_recurring_out(r) for r in rows]


@router.get("/recurring", response_model=list[RecurringOut])
def list_recurring(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    rows = session.execute(
        select(RecurringTicket)
        .where(RecurringTicket.organization_id == principal.organization_id)
        .order_by(RecurringTicket.next_run_at)
    ).scalars()
    return [_recurring_out(r) for r in rows]


@router.post("/recurring", response_model=RecurringOut, status_code=status.HTTP_201_CREATED)
def create_recurring(
    body: RecurringCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    template = session.get(TicketTemplate, body.template_id)
    if template is None or template.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Template not found")
    validate_schedule(body.schedule)
    now = datetime.now(timezone.utc)
    next_run = compute_next_run(body.schedule, now)
    if next_run is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Schedule produces no future run")
    row = RecurringTicket(
        organization_id=principal.organization_id,
        template_id=template.id,
        schedule=body.schedule,
        next_run_at=next_run,
        is_active=body.is_active,
        created_by_id=principal.user_id,
    )
    session.add(row)
    session.flush()
    _audit_tickets(
        session, principal, audit_mod.RECURRING_CREATED, "recurring_ticket", str(row.id), template_id=str(template.id)
    )
    out = _recurring_out(row)
    session.commit()
    return out


@router.get("/recurring/{recurring_id}", response_model=RecurringOut)
def get_recurring(
    recurring_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    return _recurring_out(get_org_row(session, RecurringTicket, recurring_id, principal.organization_id))


@router.patch("/recurring/{recurring_id}", response_model=RecurringOut)
def update_recurring(
    recurring_id: uuid.UUID,
    body: RecurringUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    row = get_org_row(session, RecurringTicket, recurring_id, principal.organization_id)
    if body.schedule is not None:
        validate_schedule(body.schedule)
        row.schedule = body.schedule
        nxt = compute_next_run(body.schedule, datetime.now(timezone.utc))
        if nxt is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Schedule produces no future run")
        row.next_run_at = nxt
    if body.is_active is not None:
        row.is_active = body.is_active
    _audit_tickets(session, principal, audit_mod.RECURRING_UPDATED, "recurring_ticket", str(row.id))
    session.flush()
    out = _recurring_out(row)
    session.commit()
    return out


@router.delete("/recurring/{recurring_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_recurring(
    recurring_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("templates:manage")),
):
    row = get_org_row(session, RecurringTicket, recurring_id, principal.organization_id)
    session.delete(row)
    _audit_tickets(session, principal, audit_mod.RECURRING_DELETED, "recurring_ticket", str(row.id))
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/surveys", response_model=list[SurveyOut])
def list_surveys(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("surveys:read"))
):
    rows = session.execute(
        select(Survey).where(Survey.organization_id == principal.organization_id).order_by(Survey.name)
    ).scalars()
    return [_survey_out(s) for s in rows]


@router.post("/surveys", response_model=SurveyOut, status_code=status.HTTP_201_CREATED)
def create_survey(
    body: SurveyCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("surveys:manage")),
):
    if body.target_type not in {"ticket", "request"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target_type must be ticket or request")
    survey = Survey(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        target_type=body.target_type,
        questions=body.questions or [],
        is_active=body.is_active,
    )
    session.add(survey)
    session.flush()
    _audit_tickets(session, principal, audit_mod.SURVEY_CREATED, "survey", str(survey.id), name=survey.name)
    out = _survey_out(survey)
    session.commit()
    return out


@router.get("/surveys/{survey_id}", response_model=SurveyOut)
def get_survey(
    survey_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("surveys:read")),
):
    return _survey_out(get_org_row(session, Survey, survey_id, principal.organization_id))


@router.patch("/surveys/{survey_id}", response_model=SurveyOut)
def update_survey(
    survey_id: uuid.UUID,
    body: SurveyUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("surveys:manage")),
):
    survey = get_org_row(session, Survey, survey_id, principal.organization_id)
    if body.target_type is not None:
        if body.target_type not in {"ticket", "request"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target_type must be ticket or request")
        survey.target_type = body.target_type
    if body.name is not None:
        survey.name = body.name
    if body.description is not None:
        survey.description = body.description
    if body.questions is not None:
        survey.questions = body.questions
    if body.is_active is not None:
        survey.is_active = body.is_active
    _audit_tickets(session, principal, audit_mod.SURVEY_UPDATED, "survey", str(survey.id), name=survey.name)
    session.flush()
    out = _survey_out(survey)
    session.commit()
    return out


@router.delete("/surveys/{survey_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_survey(
    survey_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("surveys:manage")),
):
    survey = get_org_row(session, Survey, survey_id, principal.organization_id)
    session.delete(survey)
    _audit_tickets(session, principal, audit_mod.SURVEY_DELETED, "survey", str(survey.id), name=survey.name)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/surveys/{survey_id}/responses", response_model=SurveyResponseOut, status_code=status.HTTP_201_CREATED)
def submit_survey_response(
    survey_id: uuid.UUID,
    body: SurveyResponseCreate,
    session: Session = Depends(get_db),
    # Any authenticated org member may submit (surveys:read is the
    # broadest member-level gate); the target must exist in-org.
    principal: Principal = Depends(require_permission("surveys:read")),
):
    survey = get_org_row(session, Survey, survey_id, principal.organization_id)
    if body.target_type not in {"ticket", "request"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="target_type must be ticket or request")
    target_model = Ticket if body.target_type == "ticket" else ServiceRequest
    target = session.get(target_model, body.target_id)
    if target is None or target.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target not found")
    score = body.score
    if score is None:
        numeric = [v for v in (body.answers or {}).values() if isinstance(v, int) and not isinstance(v, bool)]
        if numeric and len(numeric) == len(body.answers or {}):
            score = round(sum(numeric) / len(numeric))
    response = SurveyResponse(
        organization_id=principal.organization_id,
        survey_id=survey.id,
        target_type=body.target_type,
        target_id=body.target_id,
        respondent_id=principal.user_id,
        answers=body.answers or {},
        score=score,
    )
    session.add(response)
    session.flush()
    # submitted_at carries the submission time (server now on insert).
    response.submitted_at = response.created_at or datetime.now(timezone.utc)
    _audit_tickets(
        session,
        principal,
        audit_mod.SURVEY_RESPONSE_SUBMITTED,
        "survey_response",
        str(response.id),
        survey_id=str(survey.id),
    )
    out = _response_out(response)
    session.commit()
    return out


@router.get("/surveys/{survey_id}/responses", response_model=list[SurveyResponseOut])
def list_survey_responses(
    survey_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("surveys:read")),
):
    survey = get_org_row(session, Survey, survey_id, principal.organization_id)
    rows = session.execute(
        select(SurveyResponse).where(SurveyResponse.survey_id == survey.id).order_by(SurveyResponse.created_at.desc())
    ).scalars()
    return [_response_out(r) for r in rows]


@router.get("/{ticket_id}", response_model=TicketOut)
def get_ticket(
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:read")),
):
    ticket = session.get(Ticket, ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        # 404 either way: never reveal whether another org's ticket exists.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")
    return _ticket_out(ticket)


@router.patch("/{ticket_id}", response_model=TicketOut)
def update_ticket(
    ticket_id: uuid.UUID,
    body: TicketUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:update")),
):
    ticket = session.get(Ticket, ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")
    old_status = ticket.status
    old_priority = ticket.priority
    if body.status is not None:
        if body.status not in VALID_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        ticket.status = body.status
    if body.priority is not None:
        if body.priority not in VALID_PRIORITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
        ticket.priority = body.priority
    if body.assignee_id is not None:
        ticket.assignee_id = body.assignee_id
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.TICKET_UPDATED,
        resource_type="ticket",
        resource_id=str(ticket.id),
        outcome="success",
        metadata={"status": ticket.status, "priority": ticket.priority},
    )
    # Flush first: the UPDATE expires the server-computed updated_at, and
    # its refresh must happen inside this transaction (RLS context alive).
    # Automation (Phase 4) fires ticket.updated, plus
    # ticket.priority_changed when the priority actually changed; both
    # evaluate against the real ticket before the response is built.
    # Build the payload before commit for the same reason as create.
    session.flush()
    automation_service.evaluate_rules(
        session,
        org_id=principal.organization_id,
        trigger="ticket.updated",
        entity_type="ticket",
        entity_id=ticket.id,
        actor_id=principal.user_id,
    )
    if body.priority is not None and body.priority != old_priority:
        automation_service.evaluate_rules(
            session,
            org_id=principal.organization_id,
            trigger="ticket.priority_changed",
            entity_type="ticket",
            entity_id=ticket.id,
            actor_id=principal.user_id,
        )
    payload = {
        "ticket_id": str(ticket.id),
        "number": ticket.number,
        "title": ticket.title,
        "status": ticket.status,
        "priority": ticket.priority,
        "category": ticket.category,
    }
    newly_resolved = old_status != "resolved" and ticket.status == "resolved"
    out = _ticket_out(ticket)
    session.commit()
    webhook_service.emit_event(
        principal.organization_id, "ticket.updated", payload, user_id=principal.user_id
    )
    if newly_resolved:
        webhook_service.emit_event(
            principal.organization_id, "ticket.resolved", payload, user_id=principal.user_id
        )
    return out


# --- Phase 2 ticket extensions: comments / attachments / links --------------

LINK_TARGET_TYPES = {"ticket", "request", "change", "problem"}
LINK_TYPES = {"parent", "child", "related", "caused_by", "blocks"}
_LINK_TARGET_MODELS = {"ticket": Ticket, "request": ServiceRequest, "change": Change, "problem": Problem}


class CommentCreate(BaseModel):
    body: str = Field(min_length=1)
    is_internal: bool = True


class CommentOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    ticket_id: uuid.UUID
    author_id: uuid.UUID | None
    body: str
    is_internal: bool
    created_at: datetime
    updated_at: datetime


class AttachmentCreate(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    # Optional base64-encoded file bytes. When present the bytes are
    # uploaded to storage; when absent only metadata is recorded and
    # size_bytes is taken as given.
    content_base64: str | None = None


class AttachmentOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    ticket_id: uuid.UUID
    uploaded_by_id: uuid.UUID | None
    filename: str
    content_type: str
    size_bytes: int
    storage_key: str | None
    created_at: datetime
    updated_at: datetime


class LinkCreate(BaseModel):
    target_type: str
    target_id: uuid.UUID
    link_type: str = "related"


class LinkOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    source_ticket_id: uuid.UUID
    target_type: str
    target_id: uuid.UUID
    link_type: str
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


def _comment_out(c: TicketComment) -> CommentOut:
    return CommentOut(
        id=c.id,
        organization_id=c.organization_id,
        ticket_id=c.ticket_id,
        author_id=c.author_id,
        body=c.body,
        is_internal=c.is_internal,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _attachment_out(a: TicketAttachment) -> AttachmentOut:
    return AttachmentOut(
        id=a.id,
        organization_id=a.organization_id,
        ticket_id=a.ticket_id,
        uploaded_by_id=a.uploaded_by_id,
        filename=a.filename,
        content_type=a.content_type,
        size_bytes=a.size_bytes,
        storage_key=a.storage_key,
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


def _link_out(link: TicketLink) -> LinkOut:
    return LinkOut(
        id=link.id,
        organization_id=link.organization_id,
        source_ticket_id=link.source_ticket_id,
        target_type=link.target_type,
        target_id=link.target_id,
        link_type=link.link_type,
        created_by_id=link.created_by_id,
        created_at=link.created_at,
        updated_at=link.updated_at,
    )


def _get_ticket_or_404(session: Session, principal: Principal, ticket_id: uuid.UUID) -> Ticket:
    ticket = session.get(Ticket, ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")
    return ticket


@router.get("/{ticket_id}/comments", response_model=list[CommentOut])
def list_comments(
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:read")),
):
    ticket = _get_ticket_or_404(session, principal, ticket_id)
    rows = session.execute(
        select(TicketComment).where(TicketComment.ticket_id == ticket.id).order_by(TicketComment.created_at)
    ).scalars()
    # Both internal notes and public replies appear in the list; the
    # is_internal flag distinguishes them.
    return [_comment_out(c) for c in rows]


@router.post("/{ticket_id}/comments", response_model=CommentOut, status_code=status.HTTP_201_CREATED)
def create_comment(
    ticket_id: uuid.UUID,
    body: CommentCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:comment")),
):
    ticket = _get_ticket_or_404(session, principal, ticket_id)
    comment = TicketComment(
        organization_id=principal.organization_id,
        ticket_id=ticket.id,
        author_id=principal.user_id,
        body=body.body,
        is_internal=body.is_internal,
    )
    session.add(comment)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.TICKET_COMMENTED,
        resource_type="ticket",
        resource_id=str(ticket.id),
        outcome="success",
        metadata={"comment_id": str(comment.id), "is_internal": comment.is_internal},
    )
    out = _comment_out(comment)
    session.commit()
    return out


@router.get("/{ticket_id}/attachments", response_model=list[AttachmentOut])
def list_attachments(
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:read")),
):
    ticket = _get_ticket_or_404(session, principal, ticket_id)
    rows = session.execute(
        select(TicketAttachment).where(TicketAttachment.ticket_id == ticket.id).order_by(TicketAttachment.created_at)
    ).scalars()
    return [_attachment_out(a) for a in rows]


@router.post("/{ticket_id}/attachments", response_model=AttachmentOut, status_code=status.HTTP_201_CREATED)
def create_attachment(
    ticket_id: uuid.UUID,
    body: AttachmentCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:update")),
):
    ticket = _get_ticket_or_404(session, principal, ticket_id)
    # Metadata only: file bytes go to the storage backend when it is
    # configured. When it is not, fail honestly and store nothing.
    # (JSON body, not multipart: python-multipart is not a project
    # dependency, so uploads arrive as base64 in content_base64.)
    storage = get_storage()
    if not storage.configured:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage not configured")
    data = b""
    if body.content_base64 is not None:
        import base64

        try:
            data = base64.b64decode(body.content_base64, validate=True)
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="content_base64 is not valid base64")
    storage_key = f"tickets/{ticket.id}/{uuid.uuid4()}-{body.filename}"
    client = getattr(storage, "_client", None)
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="storage not configured")
    try:
        client.put_object(
            Bucket=storage.bucket,
            Key=storage_key,
            Body=data,
            ContentType=body.content_type,
        )
    except StorageError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"storage upload failed: {exc}"
        ) from exc
    attachment = TicketAttachment(
        organization_id=principal.organization_id,
        ticket_id=ticket.id,
        uploaded_by_id=principal.user_id,
        filename=body.filename,
        content_type=body.content_type,
        size_bytes=len(data) if body.content_base64 is not None else body.size_bytes,
        storage_key=storage_key,
    )
    session.add(attachment)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.TICKET_ATTACHMENT_CREATED,
        resource_type="ticket",
        resource_id=str(ticket.id),
        outcome="success",
        metadata={"attachment_id": str(attachment.id), "filename": attachment.filename},
    )
    out = _attachment_out(attachment)
    session.commit()
    return out


@router.get("/{ticket_id}/links", response_model=list[LinkOut])
def list_links(
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:read")),
):
    ticket = _get_ticket_or_404(session, principal, ticket_id)
    rows = session.execute(
        select(TicketLink).where(TicketLink.source_ticket_id == ticket.id).order_by(TicketLink.created_at)
    ).scalars()
    return [_link_out(link) for link in rows]


@router.post("/{ticket_id}/links", response_model=LinkOut, status_code=status.HTTP_201_CREATED)
def create_link(
    ticket_id: uuid.UUID,
    body: LinkCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:update")),
):
    ticket = _get_ticket_or_404(session, principal, ticket_id)
    if body.target_type not in LINK_TARGET_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid target_type")
    if body.link_type not in LINK_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid link_type")
    target_model = _LINK_TARGET_MODELS[body.target_type]
    target = session.get(target_model, body.target_id)
    if target is None or target.organization_id != principal.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Link target not found in this organization"
        )
    link = TicketLink(
        organization_id=principal.organization_id,
        source_ticket_id=ticket.id,
        target_type=body.target_type,
        target_id=body.target_id,
        link_type=body.link_type,
        created_by_id=principal.user_id,
    )
    session.add(link)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.TICKET_LINK_CREATED,
        resource_type="ticket",
        resource_id=str(ticket.id),
        outcome="success",
        metadata={"link_id": str(link.id), "target_type": body.target_type},
    )
    out = _link_out(link)
    session.commit()
    return out


@router.delete("/{ticket_id}/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_link(
    ticket_id: uuid.UUID,
    link_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("tickets:update")),
):
    ticket = _get_ticket_or_404(session, principal, ticket_id)
    link = session.get(TicketLink, link_id)
    if link is None or link.source_ticket_id != ticket.id or link.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found")
    session.delete(link)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.TICKET_LINK_DELETED,
        resource_type="ticket",
        resource_id=str(ticket.id),
        outcome="success",
        metadata={"link_id": str(link.id)},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
