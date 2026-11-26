"""Tickets — Phase 1 tenant-isolation proof domain.

Minimal CRUD backed by the RLS-scoped ``tickets`` table. Phase 2 extends
this module (SLA, comments, attachments, workflow). Ticket numbers are
per-organization (INC-000001, ...) via a row-locked counter.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.ticket import Ticket, TicketCounter
from app.schemas import TicketCreate, TicketOut, TicketUpdate

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
    # Build the response BEFORE commit: the RLS context is SET LOCAL to
    # this transaction and dies at commit, so any attribute that needs a
    # refresh after commit (e.g. server-computed updated_at) would fail.
    out = _ticket_out(ticket)
    session.commit()
    return out


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
    # Build the response before commit for the same reason as create.
    session.flush()
    out = _ticket_out(ticket)
    session.commit()
    return out
