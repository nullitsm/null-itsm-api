"""Webhook routes: subscription CRUD, deliveries, test + retry.

Permissions: ``webhooks:read`` / ``webhooks:manage``. Cross-org ids are
404, never 403. The signing secret is returned exactly once, in the
create response; it is never returned again and never logged.
Audit actions use the centralized constants in ``app/audit.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.integrations import Webhook, WebhookDelivery
from app.services import webhook_service
from app.services.identity_service import SecretStorageError
from app.services.webhook_service import WebhookError

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    event_type: str
    target_url: str = Field(min_length=1, max_length=2048)
    secret: str | None = Field(default=None, min_length=8, max_length=256)


class WebhookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    target_url: str | None = Field(default=None, min_length=1, max_length=2048)
    secret: str | None = Field(default=None, min_length=8, max_length=256)
    is_active: bool | None = None


class WebhookOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    event_type: str
    target_url: str
    is_active: bool
    has_secret: bool
    created_at: datetime
    updated_at: datetime
    # Present ONLY in the create response: the signing secret, shown once.
    secret: str | None = None


class DeliveryOut(BaseModel):
    id: uuid.UUID
    webhook_id: uuid.UUID
    event_type: str
    payload: dict
    attempt_number: int
    status: str
    http_status: int | None
    response_snippet: str | None
    error: str | None
    attempted_at: datetime
    next_retry_at: datetime | None


class TestDeliveryIn(BaseModel):
    payload: dict = Field(default_factory=dict)


# --- Helpers ----------------------------------------------------------------


def _webhook_out(w: Webhook, secret: str | None = None) -> WebhookOut:
    return WebhookOut(
        id=w.id,
        organization_id=w.organization_id,
        name=w.name,
        event_type=w.event_type,
        target_url=w.target_url,
        is_active=w.is_active,
        has_secret=bool(w.secret_encrypted),
        created_at=w.created_at,
        updated_at=w.updated_at,
        secret=secret,
    )


def _delivery_out(d: WebhookDelivery) -> DeliveryOut:
    return DeliveryOut(
        id=d.id,
        webhook_id=d.webhook_id,
        event_type=d.event_type,
        payload=d.payload or {},
        attempt_number=d.attempt_number,
        status=d.status,
        http_status=d.http_status,
        response_snippet=d.response_snippet,
        error=d.error,
        attempted_at=d.attempted_at,
        next_retry_at=d.next_retry_at,
    )


def _get_webhook(session: Session, org_id: uuid.UUID, webhook_id: uuid.UUID) -> Webhook:
    webhook = session.get(Webhook, webhook_id)
    if webhook is None or webhook.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return webhook


def _audit(session: Session, principal: Principal, action: str, resource_id: str, metadata: dict | None = None):
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type="webhook",
        resource_id=resource_id,
        outcome="success",
        metadata=metadata or {},
    )


# --- CRUD -------------------------------------------------------------------


@router.get("", response_model=list[WebhookOut])
def list_webhooks(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("webhooks:read"))
):
    rows = (
        session.execute(
            select(Webhook).where(Webhook.organization_id == principal.organization_id).order_by(Webhook.created_at)
        )
        .scalars()
        .all()
    )
    return [_webhook_out(w) for w in rows]


@router.post("", response_model=WebhookOut, status_code=status.HTTP_201_CREATED)
def create_webhook(
    body: WebhookCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:manage")),
):
    try:
        webhook, raw_secret = webhook_service.create_webhook(
            session,
            organization_id=principal.organization_id,
            name=body.name,
            event_type=body.event_type,
            target_url=body.target_url,
            secret=body.secret,
            created_by_id=principal.user_id,
        )
    except WebhookError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except SecretStorageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A webhook with this name already exists"
        )
    _audit(
        session,
        principal,
        audit_mod.WEBHOOK_CREATED,
        str(webhook.id),
        {"name": body.name, "event_type": body.event_type},
    )
    out = _webhook_out(webhook, secret=raw_secret)
    session.commit()
    return out


@router.get("/deliveries", response_model=list[DeliveryOut])
def list_all_deliveries(
    event_type: str | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:read")),
):
    query = select(WebhookDelivery).where(WebhookDelivery.organization_id == principal.organization_id)
    if event_type is not None:
        query = query.where(WebhookDelivery.event_type == event_type)
    rows = session.execute(query.order_by(WebhookDelivery.attempted_at.desc())).scalars().all()
    return [_delivery_out(d) for d in rows]


@router.get("/{webhook_id}", response_model=WebhookOut)
def get_webhook(
    webhook_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:read")),
):
    return _webhook_out(_get_webhook(session, principal.organization_id, webhook_id))


@router.patch("/{webhook_id}", response_model=WebhookOut)
def update_webhook(
    webhook_id: uuid.UUID,
    body: WebhookUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:manage")),
):
    webhook = _get_webhook(session, principal.organization_id, webhook_id)
    if body.name is not None:
        webhook.name = body.name
    if body.target_url is not None:
        try:
            webhook_service.validate_target_url(body.target_url)
        except WebhookError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        webhook.target_url = body.target_url
    if body.secret is not None:
        try:
            from app.services.identity_service import encrypt_secret

            webhook.secret_encrypted = encrypt_secret(body.secret)
        except SecretStorageError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    if body.is_active is not None:
        webhook.is_active = body.is_active
    session.flush()
    _audit(session, principal, audit_mod.WEBHOOK_UPDATED, str(webhook.id), {"name": webhook.name})
    out = _webhook_out(webhook)
    session.commit()
    return out


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(
    webhook_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:manage")),
):
    webhook = _get_webhook(session, principal.organization_id, webhook_id)
    session.delete(webhook)
    session.flush()
    _audit(session, principal, audit_mod.WEBHOOK_DELETED, str(webhook.id), {"name": webhook.name})
    session.commit()
    return None


# --- Deliveries -------------------------------------------------------------


@router.get("/{webhook_id}/deliveries", response_model=list[DeliveryOut])
def list_deliveries(
    webhook_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:read")),
):
    webhook = _get_webhook(session, principal.organization_id, webhook_id)
    rows = (
        session.execute(
            select(WebhookDelivery)
            .where(WebhookDelivery.webhook_id == webhook.id)
            .order_by(WebhookDelivery.attempted_at.desc())
        )
        .scalars()
        .all()
    )
    return [_delivery_out(d) for d in rows]


@router.post("/{webhook_id}/test", response_model=list[DeliveryOut])
def test_webhook(
    webhook_id: uuid.UUID,
    body: TestDeliveryIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:manage")),
):
    """Send a real test delivery to this webhook (its own event type)."""
    webhook = _get_webhook(session, principal.organization_id, webhook_id)
    if not webhook.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook is inactive")
    attempts = webhook_service.deliver_webhook(
        session, webhook, webhook.event_type, body.payload or {"test": True}, backoff_seconds=(0, 0)
    )
    session.flush()
    _audit(session, principal, audit_mod.WEBHOOK_DELIVERED, str(webhook.id), {"attempts": len(attempts)})
    out = [_delivery_out(d) for d in attempts]
    session.commit()
    return out


@router.post("/{webhook_id}/deliveries/{delivery_id}/retry", response_model=list[DeliveryOut])
def retry_delivery(
    webhook_id: uuid.UUID,
    delivery_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("webhooks:manage")),
):
    """Re-attempt a recorded delivery with its stored payload."""
    webhook = _get_webhook(session, principal.organization_id, webhook_id)
    delivery = session.get(WebhookDelivery, delivery_id)
    if delivery is None or delivery.webhook_id != webhook.id or delivery.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    attempts = webhook_service.deliver_webhook(
        session, webhook, delivery.event_type, delivery.payload or {}, backoff_seconds=(0, 0)
    )
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.WEBHOOK_DELIVERED,
        str(webhook.id),
        {"retried_delivery_id": str(delivery.id), "attempts": len(attempts)},
    )
    out = [_delivery_out(d) for d in attempts]
    session.commit()
    return out
