"""Employee self-service portal.

A SEPARATE session type from the org domain: portal endpoints accept
only ``portal_access`` JWTs (60 minutes) backed by a ``portal_sessions``
row (token hash only, unexpired + unrevoked). An org ``access`` token
is rejected here, and a portal token is rejected on every org endpoint
(the JWT ``type`` claim is checked on decode in both directions).

Own-records-only scoping: a portal user sees ONLY their own tickets /
requests / notifications. Any other user's record — same org or
another — is a 404.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.database import as_uuid, set_rls_context
from app.deps import Forbidden, Unauthorized, get_bearer_token, get_db
from app.models.email_portal import PortalSession
from app.models.itsm import CatalogItem, KnowledgeArticle, Notification, ServiceRequest
from app.models.platform import Membership, Organization
from app.models.ticket import Ticket
from app.security import decode_local_token
from app.services.portal_service import (
    PortalPrincipal,
    authenticate_portal_user,
    issue_portal_access_token,
    load_portal_permissions,
    next_request_number,
    next_ticket_number,
    org_branding,
    portal_token_hash,
    user_profile,
)

router = APIRouter(prefix="/api/v1/portal", tags=["portal"])

UTC = timezone.utc
_VALID_PRIORITIES = {"low", "medium", "high", "critical"}


# --- Schemas (local: app/schemas.py is owned by another workstream) ------


class PortalLoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=1)
    organization_id: uuid.UUID | None = None


class PortalTicketCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    priority: str = "medium"
    category: str = "General"


class PortalTicketOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    number: str
    title: str
    description: str
    status: str
    priority: str
    category: str
    requester_id: uuid.UUID | None
    assignee_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class PortalRequestCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    priority: str = "medium"
    catalog_item_id: uuid.UUID | None = None
    form_data: dict = Field(default_factory=dict)


class PortalRequestOut(BaseModel):
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
    created_at: datetime
    updated_at: datetime


class CatalogOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    status: str
    approval_required: bool
    category_id: uuid.UUID | None


class KnowledgeOut(BaseModel):
    id: uuid.UUID
    title: str
    slug: str
    body: str
    status: str
    category: str
    tags: list


class NotificationOut(BaseModel):
    id: uuid.UUID
    type: str
    title: str
    body: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    read_at: datetime | None
    created_at: datetime


# --- Portal authentication -------------------------------------------------


def get_portal_principal(request: Request, session: Session = Depends(get_db)) -> PortalPrincipal:
    """Authenticate a ``portal_access`` token + portal_sessions row."""
    token = get_bearer_token(request)
    try:
        claims = decode_local_token(token, expected_type="portal_access")
    except jwt.ExpiredSignatureError:
        raise Unauthorized("Session expired")
    except jwt.InvalidTokenError:
        raise Unauthorized("Invalid token")
    try:
        user_id = uuid.UUID(claims.sub)
        org_id = uuid.UUID(claims.org) if claims.org else None
    except ValueError:
        raise Unauthorized("Invalid token subject")
    if org_id is None:
        raise Unauthorized("Portal token has no organization")

    # Scope BEFORE touching portal_sessions: its RLS policy is org-scoped.
    set_rls_context(session, org_id, user_id)
    row = session.execute(
        select(PortalSession).where(
            PortalSession.token_hash == portal_token_hash(token),
            PortalSession.organization_id == org_id,
            PortalSession.user_id == user_id,
            PortalSession.expires_at > datetime.now(UTC),
            PortalSession.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if row is None:
        raise Unauthorized("Invalid or expired portal session")
    org = session.get(Organization, org_id)
    permissions = load_portal_permissions(session, user_id, org_id)
    return PortalPrincipal(
        user_id=user_id,
        email=claims.email,
        organization_id=org_id,
        organization_slug=org.slug if org else "",
        session_id=row.id,
        permissions=permissions,
    )


def require_portal_permission(permission: str):
    def _check(principal: PortalPrincipal = Depends(get_portal_principal)) -> PortalPrincipal:
        if not principal.has(permission):
            raise Forbidden(f"Missing permission: {permission}")
        return principal

    return _check


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


# --- Auth ------------------------------------------------------------------


@router.post("/auth/login")
def portal_login(request: Request, body: PortalLoginRequest, session: Session = Depends(get_db)):
    try:
        user, membership = authenticate_portal_user(session, body.email, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    org_id = membership.organization_id
    if body.organization_id is not None:
        chosen = session.execute(
            select(Membership).where(
                Membership.user_id == as_uuid(user["id"]),
                Membership.organization_id == body.organization_id,
                Membership.status == "active",
            )
        ).scalar_one_or_none()
        if chosen is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="No active membership in this organization"
            )
        org_id = body.organization_id
    user_id = as_uuid(user["id"])
    set_rls_context(session, org_id, user_id)
    access_token = issue_portal_access_token(user_id, org_id, user["email"])
    session_row = PortalSession(
        organization_id=org_id,
        user_id=user_id,
        # The stored hash is of the JWT itself: get_portal_principal
        # looks the session up by hashing the presented bearer token.
        token_hash=portal_token_hash(access_token),
        expires_at=datetime.now(UTC) + timedelta(minutes=60),
        user_agent=request.headers.get("User-Agent"),
        ip_address=_client_ip(request),
        branding_snapshot=org_branding(session, org_id),
    )
    session.add(session_row)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=user_id,
        action=audit_mod.PORTAL_LOGIN,
        resource_type="portal_session",
        resource_id=str(session_row.id),
        outcome="success",
    )
    session.commit()
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "user_id": str(user_id),
        "organization_id": str(org_id),
    }


@router.post("/auth/logout")
def portal_logout(session: Session = Depends(get_db), principal: PortalPrincipal = Depends(get_portal_principal)):
    row = session.get(PortalSession, principal.session_id)
    if row is not None:
        row.revoked_at = datetime.now(UTC)
    session.commit()
    return {"status": "ok"}


# --- Me / profile ----------------------------------------------------------


@router.get("/me")
def portal_me(
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    profile = user_profile(session, principal.user_id)
    return {
        "user": profile,
        "organization_id": str(principal.organization_id),
        "organization_slug": principal.organization_slug,
        "branding": org_branding(session, principal.organization_id),
        "permissions": sorted(principal.permissions),
    }


# --- Tickets (own only) ----------------------------------------------------


def _ticket_out(t: Ticket) -> PortalTicketOut:
    return PortalTicketOut(
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


@router.get("/tickets", response_model=list[PortalTicketOut])
def portal_list_tickets(
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    rows = session.execute(
        select(Ticket)
        .where(Ticket.organization_id == principal.organization_id, Ticket.requester_id == principal.user_id)
        .order_by(Ticket.created_at.desc())
    ).scalars()
    return [_ticket_out(t) for t in rows]


@router.post("/tickets", response_model=PortalTicketOut, status_code=status.HTTP_201_CREATED)
def portal_create_ticket(
    body: PortalTicketCreate,
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:submit")),
):
    if body.priority not in _VALID_PRIORITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
    ticket = Ticket(
        organization_id=principal.organization_id,
        number=next_ticket_number(session, principal.organization_id),
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
        metadata={"number": ticket.number, "via": "portal"},
    )
    out = _ticket_out(ticket)
    session.commit()
    return out


@router.get("/tickets/{ticket_id}", response_model=PortalTicketOut)
def portal_get_ticket(
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    ticket = session.get(Ticket, ticket_id)
    if (
        ticket is None
        or ticket.organization_id != principal.organization_id
        or ticket.requester_id != principal.user_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")
    return _ticket_out(ticket)


# --- Service requests (own only; approve = assigned approver) -------------


def _request_out(r: ServiceRequest) -> PortalRequestOut:
    return PortalRequestOut(
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
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


@router.get("/requests", response_model=list[PortalRequestOut])
def portal_list_requests(
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    rows = session.execute(
        select(ServiceRequest)
        .where(
            ServiceRequest.organization_id == principal.organization_id,
            ServiceRequest.requester_id == principal.user_id,
        )
        .order_by(ServiceRequest.created_at.desc())
    ).scalars()
    return [_request_out(r) for r in rows]


@router.post("/requests", response_model=PortalRequestOut, status_code=status.HTTP_201_CREATED)
def portal_create_request(
    body: PortalRequestCreate,
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:submit")),
):
    if body.priority not in _VALID_PRIORITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
    if body.catalog_item_id is not None:
        item = session.get(CatalogItem, body.catalog_item_id)
        if item is None or item.organization_id != principal.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found")
    request_row = ServiceRequest(
        organization_id=principal.organization_id,
        number=next_request_number(session, principal.organization_id),
        title=body.title,
        description=body.description,
        priority=body.priority,
        catalog_item_id=body.catalog_item_id,
        requester_id=principal.user_id,
        status="submitted",
        form_data=body.form_data,
    )
    session.add(request_row)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.REQUEST_CREATED,
        resource_type="request",
        resource_id=str(request_row.id),
        outcome="success",
        metadata={"number": request_row.number, "via": "portal"},
    )
    out = _request_out(request_row)
    session.commit()
    return out


@router.get("/requests/{request_id}", response_model=PortalRequestOut)
def portal_get_request(
    request_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    request_row = session.get(ServiceRequest, request_id)
    if (
        request_row is None
        or request_row.organization_id != principal.organization_id
        or request_row.requester_id != principal.user_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    return _request_out(request_row)


@router.post("/requests/{request_id}/approve", response_model=PortalRequestOut)
def portal_approve_request(
    request_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:approve")),
):
    """Approve a request. Only the assigned approver (``assignee_id``)
    may approve; anyone else gets 403, and a request that is not
    awaiting approval gets 400."""
    request_row = session.get(ServiceRequest, request_id)
    if request_row is None or request_row.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    if request_row.assignee_id != principal.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Only the assigned approver may approve this request"
        )
    if request_row.status not in ("submitted", "pending_approval"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request is not awaiting approval")
    request_row.status = "approved"
    request_row.approved_by_id = principal.user_id
    request_row.approved_at = datetime.now(UTC)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.REQUEST_APPROVED,
        resource_type="request",
        resource_id=str(request_row.id),
        outcome="success",
        metadata={"number": request_row.number, "via": "portal"},
    )
    session.flush()
    out = _request_out(request_row)
    session.commit()
    return out


# --- Catalog / knowledge (published only) ----------------------------------


@router.get("/catalog", response_model=list[CatalogOut])
def portal_catalog(
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    rows = session.execute(
        select(CatalogItem)
        .where(CatalogItem.organization_id == principal.organization_id, CatalogItem.status == "published")
        .order_by(CatalogItem.sort_order, CatalogItem.name)
    ).scalars()
    return [
        CatalogOut(
            id=i.id,
            name=i.name,
            description=i.description,
            status=i.status,
            approval_required=i.approval_required,
            category_id=i.category_id,
        )
        for i in rows
    ]


@router.get("/knowledge", response_model=list[KnowledgeOut])
def portal_knowledge(
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    rows = session.execute(
        select(KnowledgeArticle)
        .where(
            KnowledgeArticle.organization_id == principal.organization_id,
            KnowledgeArticle.status == "published",
        )
        .order_by(KnowledgeArticle.created_at.desc())
    ).scalars()
    return [
        KnowledgeOut(
            id=a.id,
            title=a.title,
            slug=a.slug,
            body=a.body,
            status=a.status,
            category=a.category,
            tags=a.tags or [],
        )
        for a in rows
    ]


# --- Notifications (own only) ----------------------------------------------


@router.get("/notifications", response_model=list[NotificationOut])
def portal_notifications(
    session: Session = Depends(get_db),
    principal: PortalPrincipal = Depends(require_portal_permission("portal:read")),
):
    rows = session.execute(
        select(Notification)
        .where(
            Notification.organization_id == principal.organization_id,
            Notification.user_id == principal.user_id,
        )
        .order_by(Notification.created_at.desc())
    ).scalars()
    return [
        NotificationOut(
            id=n.id,
            type=n.type,
            title=n.title,
            body=n.body,
            resource_type=n.resource_type,
            resource_id=n.resource_id,
            read_at=n.read_at,
            created_at=n.created_at,
        )
        for n in rows
    ]
