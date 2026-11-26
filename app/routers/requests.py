"""Service requests — Phase 2 ITSM engine.

Lifecycle: submitted -> in_progress -> pending_approval -> approved
-> fulfilled, with rejected / cancelled as terminal states. Approve
and fulfill are separate permission-gated actions; PATCH covers
field edits and the remaining status moves.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.itsm import CatalogItem, ServiceRequest
from app.services.itsm_service import get_org_row, next_request_number

router = APIRouter(prefix="/api/v1/requests", tags=["requests"])

VALID_STATUSES = {"submitted", "in_progress", "pending_approval", "approved", "fulfilled", "rejected", "cancelled"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}
# Allowed PATCH status moves (approve / fulfill have their own endpoints).
TRANSITIONS: dict[str, set[str]] = {
    "submitted": {"in_progress", "pending_approval", "rejected", "cancelled"},
    "in_progress": {"pending_approval", "approved", "fulfilled", "rejected", "cancelled"},
    "pending_approval": {"approved", "rejected", "cancelled"},
    "approved": {"fulfilled", "cancelled"},
    "fulfilled": set(),
    "rejected": set(),
    "cancelled": set(),
}


class RequestCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    priority: str = "medium"
    catalog_item_id: uuid.UUID | None = None
    assignee_id: uuid.UUID | None = None
    form_data: dict = {}


class RequestUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    description: str | None = None
    priority: str | None = None
    status: str | None = None
    assignee_id: uuid.UUID | None = None
    form_data: dict | None = None


class RequestOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    number: str
    title: str
    description: str
    status: str
    priority: str
    catalog_item_id: uuid.UUID | None
    requester_id: uuid.UUID | None
    assignee_id: uuid.UUID | None
    approved_by_id: uuid.UUID | None
    approved_at: datetime | None
    fulfilled_at: datetime | None
    form_data: dict
    created_at: datetime
    updated_at: datetime


def _out(r: ServiceRequest) -> RequestOut:
    return RequestOut(
        id=r.id,
        organization_id=r.organization_id,
        number=r.number,
        title=r.title,
        description=r.description,
        status=r.status,
        priority=r.priority,
        catalog_item_id=r.catalog_item_id,
        requester_id=r.requester_id,
        assignee_id=r.assignee_id,
        approved_by_id=r.approved_by_id,
        approved_at=r.approved_at,
        fulfilled_at=r.fulfilled_at,
        form_data=r.form_data or {},
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _check_catalog_item(session: Session, principal: Principal, catalog_item_id: uuid.UUID | None) -> None:
    if catalog_item_id is None:
        return
    item = session.get(CatalogItem, catalog_item_id)
    if item is None or item.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Catalog item not found")


@router.get("", response_model=list[RequestOut])
def list_requests(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("requests:read"))
):
    rows = session.execute(
        select(ServiceRequest)
        .where(ServiceRequest.organization_id == principal.organization_id)
        .order_by(ServiceRequest.created_at.desc())
    ).scalars()
    return [_out(r) for r in rows]


@router.post("", response_model=RequestOut, status_code=status.HTTP_201_CREATED)
def create_request(
    body: RequestCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("requests:create")),
):
    if body.priority not in VALID_PRIORITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
    _check_catalog_item(session, principal, body.catalog_item_id)
    req = ServiceRequest(
        organization_id=principal.organization_id,
        number=next_request_number(session, principal.organization_id),
        title=body.title,
        description=body.description,
        priority=body.priority,
        catalog_item_id=body.catalog_item_id,
        requester_id=principal.user_id,
        assignee_id=body.assignee_id,
        form_data=body.form_data or {},
        status="submitted",
    )
    session.add(req)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.REQUEST_CREATED,
        resource_type="request",
        resource_id=str(req.id),
        outcome="success",
        metadata={"number": req.number},
    )
    out = _out(req)
    session.commit()
    return out


@router.get("/{request_id}", response_model=RequestOut)
def get_request(
    request_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("requests:read")),
):
    return _out(get_org_row(session, ServiceRequest, request_id, principal.organization_id))


@router.patch("/{request_id}", response_model=RequestOut)
def update_request(
    request_id: uuid.UUID,
    body: RequestUpdate,
    session: Session = Depends(get_db),
    # No requests:update code exists in the catalog; edits are gated on
    # requests:create (the same roles that may file a request may edit it).
    principal: Principal = Depends(require_permission("requests:create")),
):
    req = get_org_row(session, ServiceRequest, request_id, principal.organization_id)
    if body.status is not None:
        if body.status not in VALID_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        if body.status != req.status and body.status not in TRANSITIONS.get(req.status, set()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot move request from {req.status} to {body.status}",
            )
        req.status = body.status
    if body.priority is not None:
        if body.priority not in VALID_PRIORITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
        req.priority = body.priority
    if body.title is not None:
        req.title = body.title
    if body.description is not None:
        req.description = body.description
    if body.assignee_id is not None:
        req.assignee_id = body.assignee_id
    if body.form_data is not None:
        req.form_data = body.form_data
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.REQUEST_UPDATED,
        resource_type="request",
        resource_id=str(req.id),
        outcome="success",
        metadata={"status": req.status},
    )
    session.flush()
    out = _out(req)
    session.commit()
    return out


@router.post("/{request_id}/approve", response_model=RequestOut)
def approve_request(
    request_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("requests:approve")),
):
    req = get_org_row(session, ServiceRequest, request_id, principal.organization_id)
    if req.status not in {"submitted", "in_progress", "pending_approval"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot approve a request in status {req.status}"
        )
    req.status = "approved"
    req.approved_by_id = principal.user_id
    req.approved_at = datetime.now(timezone.utc)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.REQUEST_APPROVED,
        resource_type="request",
        resource_id=str(req.id),
        outcome="success",
        metadata={"number": req.number},
    )
    session.flush()
    out = _out(req)
    session.commit()
    return out


@router.post("/{request_id}/fulfill", response_model=RequestOut)
def fulfill_request(
    request_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("requests:fulfill")),
):
    req = get_org_row(session, ServiceRequest, request_id, principal.organization_id)
    if req.status not in {"approved", "in_progress"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot fulfill a request in status {req.status}"
        )
    req.status = "fulfilled"
    req.fulfilled_at = datetime.now(timezone.utc)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.REQUEST_FULFILLED,
        resource_type="request",
        resource_id=str(req.id),
        outcome="success",
        metadata={"number": req.number},
    )
    session.flush()
    out = _out(req)
    session.commit()
    return out


@router.post("/{request_id}/cancel", response_model=RequestOut)
def cancel_request(
    request_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("requests:create")),
):
    req = get_org_row(session, ServiceRequest, request_id, principal.organization_id)
    if req.status in {"fulfilled", "rejected", "cancelled"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot cancel a request in status {req.status}"
        )
    req.status = "cancelled"
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.REQUEST_UPDATED,
        resource_type="request",
        resource_id=str(req.id),
        outcome="success",
        metadata={"status": "cancelled"},
    )
    session.flush()
    out = _out(req)
    session.commit()
    return out
