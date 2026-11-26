"""SLA — Phase 2. Business hours, SLA policies, breaches, escalations.

Every endpoint is org-scoped: the caller's organization comes from the
authenticated principal, never from the request body. Cross-org ids
return 404 (never reveal existence). Mutations are audited with the SLA
constants in ``app/audit.py`` (no dedicated business-hours / escalation
constants exist there, so those mutations use SLA_POLICY_CREATED /
SLA_POLICY_UPDATED with a distinguishing ``resource_type``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.sla import BusinessHours, EscalationEvent, EscalationRule, SlaBreach, SlaPolicy
from app.models.ticket import Ticket
from app.services import sla_service

router = APIRouter(prefix="/api/v1/sla", tags=["sla"])

VALID_PRIORITIES = {"low", "medium", "high", "critical"}
VALID_BREACH_TYPES = {"first_response", "resolution"}
VALID_BREACH_STATUSES = {"open", "acknowledged", "resolved"}
VALID_TRIGGER_EVENTS = {"sla_breach", "no_response", "no_update"}
VALID_DAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}


# --- Schemas ----------------------------------------------------------------


class BusinessHoursIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    timezone: str = Field(default="UTC", max_length=64)
    schedule: dict = Field(default_factory=dict)
    holidays: list[str] = Field(default_factory=list)
    is_default: bool = False

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except Exception as exc:
            raise PydanticCustomError("value_error", f"Unknown timezone: {v}") from exc
        return v

    @field_validator("schedule")
    @classmethod
    def _valid_schedule(cls, v: dict) -> dict:
        for day, windows in v.items():
            if day not in VALID_DAYS:
                raise PydanticCustomError("value_error", f"Invalid day key: {day}")
            if not isinstance(windows, list):
                raise PydanticCustomError("value_error", f"Windows for {day} must be a list")
            for pair in windows:
                if not (isinstance(pair, (list, tuple)) and len(pair) == 2):
                    raise PydanticCustomError("value_error", f"Window for {day} must be [start, end]")
                for hhmm in pair:
                    parts = str(hhmm).split(":")
                    if len(parts) != 2 or not all(p.isdigit() for p in parts):
                        raise PydanticCustomError("value_error", f"Invalid time {hhmm!r} for {day}")
                    h, m = int(parts[0]), int(parts[1])
                    if not (0 <= h < 24 and 0 <= m < 60):
                        raise PydanticCustomError("value_error", f"Invalid time {hhmm!r} for {day}")
        return v


class BusinessHoursOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    timezone: str
    schedule: dict
    holidays: list
    is_default: bool
    created_at: datetime
    updated_at: datetime


class SlaPolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = ""
    applies_to: dict = Field(default_factory=dict)
    response_minutes: dict = Field(default_factory=dict)
    resolution_minutes: dict = Field(default_factory=dict)
    business_hours_id: uuid.UUID | None = None
    is_default: bool = False
    is_active: bool = True

    @field_validator("response_minutes", "resolution_minutes")
    @classmethod
    def _valid_minutes(cls, v: dict) -> dict:
        for priority, minutes in v.items():
            if priority not in VALID_PRIORITIES:
                raise PydanticCustomError("value_error", f"Invalid priority: {priority}")
            if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes < 0:
                raise PydanticCustomError("value_error", f"Minutes for {priority} must be a non-negative integer")
        return v

    @field_validator("applies_to")
    @classmethod
    def _valid_applies_to(cls, v: dict) -> dict:
        for key in ("categories", "priorities"):
            if key in v and v[key] is not None and not isinstance(v[key], list):
                raise PydanticCustomError("value_error", f"applies_to.{key} must be a list")
        if "priorities" in v and v["priorities"]:
            for p in v["priorities"]:
                if p not in VALID_PRIORITIES:
                    raise PydanticCustomError("value_error", f"Invalid priority in applies_to: {p}")
        return v


class SlaPolicyOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    applies_to: dict
    response_minutes: dict
    resolution_minutes: dict
    business_hours_id: uuid.UUID | None
    is_default: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime


class SlaBreachOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    ticket_id: uuid.UUID
    policy_id: uuid.UUID | None
    breach_type: str
    breached_at: datetime
    notified_at: datetime | None
    acknowledged_at: datetime | None
    acknowledged_by_id: uuid.UUID | None
    status: str
    created_at: datetime
    updated_at: datetime


class EscalationRuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    trigger: dict = Field(default_factory=dict)
    conditions: dict = Field(default_factory=dict)
    actions: list = Field(default_factory=list)
    is_active: bool = True
    sort_order: int = 0

    @field_validator("trigger")
    @classmethod
    def _valid_trigger(cls, v: dict) -> dict:
        if v:
            if v.get("event") not in VALID_TRIGGER_EVENTS:
                raise PydanticCustomError("value_error", f"trigger.event must be one of {sorted(VALID_TRIGGER_EVENTS)}")
            after = v.get("after_minutes")
            if after is None or not isinstance(after, int) or isinstance(after, bool) or after < 0:
                raise PydanticCustomError("value_error", "trigger.after_minutes must be a non-negative integer")
        return v

    @field_validator("actions")
    @classmethod
    def _valid_actions(cls, v: list) -> list:
        for action in v:
            if not isinstance(action, dict) or action.get("type") not in {"priority_bump", "reassign", "notify"}:
                raise PydanticCustomError(
                    "value_error", "Each action must be an object with type priority_bump|reassign|notify"
                )
        return v


class EscalationRuleOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    trigger: dict
    conditions: dict
    actions: list
    is_active: bool
    sort_order: int
    created_at: datetime
    updated_at: datetime


class EscalationEventOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    rule_id: uuid.UUID
    ticket_id: uuid.UUID
    action_taken: dict
    status: str
    created_at: datetime
    updated_at: datetime


class TicketSlaOut(BaseModel):
    ticket_id: uuid.UUID
    organization_id: uuid.UUID
    number: str
    status: str
    priority: str
    category: str
    sla_policy_id: uuid.UUID | None
    first_response_due_at: datetime | None
    resolution_due_at: datetime | None
    first_response_at: datetime | None
    resolved_at: datetime | None
    sla_breached: bool


# --- Serializers ------------------------------------------------------------


def _bh_out(row: BusinessHours) -> BusinessHoursOut:
    return BusinessHoursOut(
        id=row.id,
        organization_id=row.organization_id,
        name=row.name,
        timezone=row.timezone,
        schedule=row.schedule or {},
        holidays=row.holidays or [],
        is_default=row.is_default,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _policy_out(row: SlaPolicy) -> SlaPolicyOut:
    return SlaPolicyOut(
        id=row.id,
        organization_id=row.organization_id,
        name=row.name,
        description=row.description,
        applies_to=row.applies_to or {},
        response_minutes=row.response_minutes or {},
        resolution_minutes=row.resolution_minutes or {},
        business_hours_id=row.business_hours_id,
        is_default=row.is_default,
        is_active=row.is_active,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _breach_out(row: SlaBreach) -> SlaBreachOut:
    return SlaBreachOut(
        id=row.id,
        organization_id=row.organization_id,
        ticket_id=row.ticket_id,
        policy_id=row.policy_id,
        breach_type=row.breach_type,
        breached_at=row.breached_at,
        notified_at=row.notified_at,
        acknowledged_at=row.acknowledged_at,
        acknowledged_by_id=row.acknowledged_by_id,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _rule_out(row: EscalationRule) -> EscalationRuleOut:
    return EscalationRuleOut(
        id=row.id,
        organization_id=row.organization_id,
        name=row.name,
        trigger=row.trigger or {},
        conditions=row.conditions or {},
        actions=row.actions or [],
        is_active=row.is_active,
        sort_order=row.sort_order,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _ticket_sla_out(ticket: Ticket) -> TicketSlaOut:
    return TicketSlaOut(
        ticket_id=ticket.id,
        organization_id=ticket.organization_id,
        number=ticket.number,
        status=ticket.status,
        priority=ticket.priority,
        category=ticket.category,
        sla_policy_id=ticket.sla_policy_id,
        first_response_due_at=ticket.first_response_due_at,
        resolution_due_at=ticket.resolution_due_at,
        first_response_at=ticket.first_response_at,
        resolved_at=ticket.resolved_at,
        sla_breached=ticket.sla_breached,
    )


def _not_found(detail: str = "Not found") -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def _get_org_row(session: Session, model, row_id: uuid.UUID, org_id: uuid.UUID, detail: str):
    row = session.get(model, row_id)
    if row is None or row.organization_id != org_id:
        raise _not_found(detail)
    return row


def _clear_default(session: Session, model, org_id: uuid.UUID, except_id: uuid.UUID | None = None) -> None:
    rows = session.execute(select(model).where(model.organization_id == org_id, model.is_default.is_(True))).scalars()
    for row in rows:
        if except_id is None or row.id != except_id:
            row.is_default = False


def _audit(
    session: Session,
    principal: Principal,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict | None = None,
) -> None:
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


# --- Business hours ---------------------------------------------------------


@router.get("/business-hours", response_model=list[BusinessHoursOut])
def list_business_hours(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("sla:read"))
):
    rows = session.execute(
        select(BusinessHours)
        .where(BusinessHours.organization_id == principal.organization_id)
        .order_by(BusinessHours.created_at.asc())
    ).scalars()
    return [_bh_out(r) for r in rows]


@router.post("/business-hours", response_model=BusinessHoursOut, status_code=status.HTTP_201_CREATED)
def create_business_hours(
    body: BusinessHoursIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = BusinessHours(
        organization_id=principal.organization_id,
        name=body.name,
        timezone=body.timezone,
        schedule=body.schedule,
        holidays=body.holidays,
        is_default=body.is_default,
    )
    if row.is_default:
        _clear_default(session, BusinessHours, principal.organization_id)
    session.add(row)
    session.flush()
    _audit(session, principal, audit_mod.SLA_POLICY_CREATED, "business_hours", str(row.id), {"name": row.name})
    out = _bh_out(row)
    session.commit()
    return out


@router.get("/business-hours/{bh_id}", response_model=BusinessHoursOut)
def get_business_hours(
    bh_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:read")),
):
    row = _get_org_row(session, BusinessHours, bh_id, principal.organization_id, "Business hours not found")
    return _bh_out(row)


@router.patch("/business-hours/{bh_id}", response_model=BusinessHoursOut)
def update_business_hours(
    bh_id: uuid.UUID,
    body: BusinessHoursIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, BusinessHours, bh_id, principal.organization_id, "Business hours not found")
    row.name = body.name
    row.timezone = body.timezone
    row.schedule = body.schedule
    row.holidays = body.holidays
    if body.is_default and not row.is_default:
        _clear_default(session, BusinessHours, principal.organization_id, except_id=row.id)
    row.is_default = body.is_default
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "business_hours", str(row.id), {"name": row.name})
    session.flush()
    out = _bh_out(row)
    session.commit()
    return out


@router.delete("/business-hours/{bh_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_business_hours(
    bh_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, BusinessHours, bh_id, principal.organization_id, "Business hours not found")
    in_use = session.execute(
        select(SlaPolicy).where(SlaPolicy.business_hours_id == row.id).limit(1)
    ).scalar_one_or_none()
    if in_use is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Business hours are referenced by an SLA policy"
        )
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "business_hours", str(row.id), {"deleted": True})
    session.delete(row)
    session.commit()
    return None


@router.post("/business-hours/{bh_id}/set-default", response_model=BusinessHoursOut)
def set_default_business_hours(
    bh_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, BusinessHours, bh_id, principal.organization_id, "Business hours not found")
    _clear_default(session, BusinessHours, principal.organization_id, except_id=row.id)
    row.is_default = True
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "business_hours", str(row.id), {"is_default": True})
    session.flush()
    out = _bh_out(row)
    session.commit()
    return out


# --- SLA policies -----------------------------------------------------------


@router.get("/policies", response_model=list[SlaPolicyOut])
def list_policies(session: Session = Depends(get_db), principal: Principal = Depends(require_permission("sla:read"))):
    rows = session.execute(
        select(SlaPolicy)
        .where(SlaPolicy.organization_id == principal.organization_id)
        .order_by(SlaPolicy.created_at.asc())
    ).scalars()
    return [_policy_out(r) for r in rows]


@router.post("/policies", response_model=SlaPolicyOut, status_code=status.HTTP_201_CREATED)
def create_policy(
    body: SlaPolicyIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    if body.business_hours_id is not None:
        _get_org_row(
            session, BusinessHours, body.business_hours_id, principal.organization_id, "Business hours not found"
        )
    row = SlaPolicy(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        applies_to=body.applies_to,
        response_minutes=body.response_minutes,
        resolution_minutes=body.resolution_minutes,
        business_hours_id=body.business_hours_id,
        is_default=body.is_default,
        is_active=body.is_active,
    )
    if row.is_default:
        _clear_default(session, SlaPolicy, principal.organization_id)
    session.add(row)
    session.flush()
    _audit(session, principal, audit_mod.SLA_POLICY_CREATED, "sla_policy", str(row.id), {"name": row.name})
    out = _policy_out(row)
    session.commit()
    return out


@router.get("/policies/{policy_id}", response_model=SlaPolicyOut)
def get_policy(
    policy_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:read")),
):
    row = _get_org_row(session, SlaPolicy, policy_id, principal.organization_id, "SLA policy not found")
    return _policy_out(row)


@router.patch("/policies/{policy_id}", response_model=SlaPolicyOut)
def update_policy(
    policy_id: uuid.UUID,
    body: SlaPolicyIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, SlaPolicy, policy_id, principal.organization_id, "SLA policy not found")
    if body.business_hours_id is not None:
        _get_org_row(
            session, BusinessHours, body.business_hours_id, principal.organization_id, "Business hours not found"
        )
    row.name = body.name
    row.description = body.description
    row.applies_to = body.applies_to
    row.response_minutes = body.response_minutes
    row.resolution_minutes = body.resolution_minutes
    row.business_hours_id = body.business_hours_id
    row.is_active = body.is_active
    if body.is_default and not row.is_default:
        _clear_default(session, SlaPolicy, principal.organization_id, except_id=row.id)
    row.is_default = body.is_default
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "sla_policy", str(row.id), {"name": row.name})
    session.flush()
    out = _policy_out(row)
    session.commit()
    return out


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, SlaPolicy, policy_id, principal.organization_id, "SLA policy not found")
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "sla_policy", str(row.id), {"deleted": True})
    session.delete(row)
    session.commit()
    return None


@router.post("/policies/{policy_id}/set-default", response_model=SlaPolicyOut)
def set_default_policy(
    policy_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, SlaPolicy, policy_id, principal.organization_id, "SLA policy not found")
    _clear_default(session, SlaPolicy, principal.organization_id, except_id=row.id)
    row.is_default = True
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "sla_policy", str(row.id), {"is_default": True})
    session.flush()
    out = _policy_out(row)
    session.commit()
    return out


# --- Breaches ---------------------------------------------------------------


@router.get("/breaches", response_model=list[SlaBreachOut])
def list_breaches(
    status_filter: str | None = Query(default=None, alias="status"),
    ticket_id: uuid.UUID | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:read")),
):
    if status_filter is not None and status_filter not in VALID_BREACH_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid breach status")
    query = select(SlaBreach).where(SlaBreach.organization_id == principal.organization_id)
    if status_filter is not None:
        query = query.where(SlaBreach.status == status_filter)
    if ticket_id is not None:
        query = query.where(SlaBreach.ticket_id == ticket_id)
    rows = session.execute(query.order_by(SlaBreach.created_at.desc())).scalars()
    return [_breach_out(r) for r in rows]


@router.get("/breaches/{breach_id}", response_model=SlaBreachOut)
def get_breach(
    breach_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:read")),
):
    row = _get_org_row(session, SlaBreach, breach_id, principal.organization_id, "SLA breach not found")
    return _breach_out(row)


@router.post("/breaches/{breach_id}/acknowledge", response_model=SlaBreachOut)
def acknowledge_breach(
    breach_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, SlaBreach, breach_id, principal.organization_id, "SLA breach not found")
    if row.status == "open":
        row.status = "acknowledged"
        row.acknowledged_at = datetime.now(timezone.utc)
        row.acknowledged_by_id = principal.user_id
    _audit(
        session,
        principal,
        audit_mod.SLA_BREACH_ACKNOWLEDGED,
        "sla_breach",
        str(row.id),
        {"ticket_id": str(row.ticket_id), "breach_type": row.breach_type},
    )
    session.flush()
    out = _breach_out(row)
    session.commit()
    return out


# --- Escalation rules -------------------------------------------------------


@router.get("/escalation-rules", response_model=list[EscalationRuleOut])
def list_escalation_rules(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("sla:read"))
):
    rows = session.execute(
        select(EscalationRule)
        .where(EscalationRule.organization_id == principal.organization_id)
        .order_by(EscalationRule.sort_order.asc(), EscalationRule.created_at.asc())
    ).scalars()
    return [_rule_out(r) for r in rows]


@router.post("/escalation-rules", response_model=EscalationRuleOut, status_code=status.HTTP_201_CREATED)
def create_escalation_rule(
    body: EscalationRuleIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = EscalationRule(
        organization_id=principal.organization_id,
        name=body.name,
        trigger=body.trigger,
        conditions=body.conditions,
        actions=body.actions,
        is_active=body.is_active,
        sort_order=body.sort_order,
    )
    session.add(row)
    session.flush()
    _audit(session, principal, audit_mod.SLA_POLICY_CREATED, "escalation_rule", str(row.id), {"name": row.name})
    out = _rule_out(row)
    session.commit()
    return out


@router.get("/escalation-rules/{rule_id}", response_model=EscalationRuleOut)
def get_escalation_rule(
    rule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:read")),
):
    row = _get_org_row(session, EscalationRule, rule_id, principal.organization_id, "Escalation rule not found")
    return _rule_out(row)


@router.patch("/escalation-rules/{rule_id}", response_model=EscalationRuleOut)
def update_escalation_rule(
    rule_id: uuid.UUID,
    body: EscalationRuleIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, EscalationRule, rule_id, principal.organization_id, "Escalation rule not found")
    row.name = body.name
    row.trigger = body.trigger
    row.conditions = body.conditions
    row.actions = body.actions
    row.is_active = body.is_active
    row.sort_order = body.sort_order
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "escalation_rule", str(row.id), {"name": row.name})
    session.flush()
    out = _rule_out(row)
    session.commit()
    return out


@router.delete("/escalation-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_escalation_rule(
    rule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    row = _get_org_row(session, EscalationRule, rule_id, principal.organization_id, "Escalation rule not found")
    _audit(session, principal, audit_mod.SLA_POLICY_UPDATED, "escalation_rule", str(row.id), {"deleted": True})
    session.delete(row)
    session.commit()
    return None


@router.get("/escalation-rules/{rule_id}/events", response_model=list[EscalationEventOut])
def list_escalation_events(
    rule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:read")),
):
    rule = _get_org_row(session, EscalationRule, rule_id, principal.organization_id, "Escalation rule not found")
    rows = session.execute(
        select(EscalationEvent)
        .where(EscalationEvent.organization_id == principal.organization_id, EscalationEvent.rule_id == rule.id)
        .order_by(EscalationEvent.created_at.desc())
    ).scalars()
    return [
        EscalationEventOut(
            id=r.id,
            organization_id=r.organization_id,
            rule_id=r.rule_id,
            ticket_id=r.ticket_id,
            action_taken=r.action_taken or {},
            status=r.status,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]


# --- Per-ticket SLA state ---------------------------------------------------


@router.get("/tickets/{ticket_id}", response_model=TicketSlaOut)
def get_ticket_sla(
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:read")),
):
    ticket = _get_org_row(session, Ticket, ticket_id, principal.organization_id, "Ticket not found")
    return _ticket_sla_out(ticket)


@router.post("/tickets/{ticket_id}/recompute", response_model=TicketSlaOut)
def recompute_ticket_sla(
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("sla:manage")),
):
    ticket = _get_org_row(session, Ticket, ticket_id, principal.organization_id, "Ticket not found")
    sla_service.stamp_sla_state(session, principal.organization_id, ticket)
    _audit(
        session,
        principal,
        audit_mod.SLA_POLICY_UPDATED,
        "ticket",
        str(ticket.id),
        {"sla_recomputed": True, "sla_policy_id": str(ticket.sla_policy_id) if ticket.sla_policy_id else None},
    )
    session.flush()
    out = _ticket_sla_out(ticket)
    session.commit()
    return out
