"""Integration routes: provider registry, CRUD, credentials, test-connection.

Permissions: ``integrations:read`` / ``integrations:manage``. Cross-org
ids are 404, never 403. Credential VALUES are never returned by any
endpoint — only key names. An integration's ``status`` is
``disconnected`` until a real test-connection call succeeds; the API
never claims otherwise.
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
from app.models.integrations import Integration
from app.services import integration_service
from app.services.identity_service import SecretStorageError

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class ProviderOut(BaseModel):
    slug: str
    label: str
    description: str


class IntegrationCreate(BaseModel):
    provider: str
    name: str = Field(min_length=1, max_length=100)
    config: dict = Field(default_factory=dict)


class IntegrationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    config: dict | None = None


class IntegrationOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    provider: str
    name: str
    config: dict
    status: str
    last_tested_at: datetime | None
    last_test_result: str
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class CredentialCreate(BaseModel):
    key_name: str = Field(min_length=1, max_length=100)
    value: str = Field(min_length=1)


class CredentialOut(BaseModel):
    key_name: str


class TestConnectionOut(BaseModel):
    id: uuid.UUID
    provider: str
    status: str
    last_tested_at: datetime | None
    last_test_result: str
    last_error: str | None


# --- Helpers ----------------------------------------------------------------


def _integration_out(i: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=i.id,
        organization_id=i.organization_id,
        provider=i.provider,
        name=i.name,
        config=i.config or {},
        status=i.status,
        last_tested_at=i.last_tested_at,
        last_test_result=i.last_test_result,
        last_error=i.last_error,
        created_at=i.created_at,
        updated_at=i.updated_at,
    )


def _get_integration(session: Session, org_id: uuid.UUID, integration_id: uuid.UUID) -> Integration:
    integration = session.get(Integration, integration_id)
    if integration is None or integration.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    return integration


def _audit(session: Session, principal: Principal, action: str, resource_id: str, metadata: dict | None = None):
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type="integration",
        resource_id=resource_id,
        outcome="success",
        metadata=metadata or {},
    )


# --- Registry ---------------------------------------------------------------


@router.get("/providers", response_model=list[ProviderOut])
def list_providers(principal: Principal = Depends(require_permission("integrations:read"))):
    return [ProviderOut(**p) for p in integration_service.list_providers()]


# --- CRUD -------------------------------------------------------------------


@router.get("", response_model=list[IntegrationOut])
def list_integrations(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("integrations:read"))
):
    rows = (
        session.execute(
            select(Integration)
            .where(Integration.organization_id == principal.organization_id)
            .order_by(Integration.created_at)
        )
        .scalars()
        .all()
    )
    return [_integration_out(i) for i in rows]


@router.post("", response_model=IntegrationOut, status_code=status.HTTP_201_CREATED)
def create_integration(
    body: IntegrationCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("integrations:manage")),
):
    try:
        integration_service.validate_provider(body.provider)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    integration = Integration(
        organization_id=principal.organization_id,
        provider=body.provider,
        name=body.name,
        config=body.config or {},
        status=integration_service.STATUS_DISCONNECTED,
        created_by_id=principal.user_id,
    )
    session.add(integration)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An integration with this provider and name already exists",
        )
    _audit(
        session,
        principal,
        audit_mod.INTEGRATION_CREATED,
        str(integration.id),
        {"provider": body.provider, "name": body.name},
    )
    out = _integration_out(integration)
    session.commit()
    return out


@router.get("/{integration_id}", response_model=IntegrationOut)
def get_integration(
    integration_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("integrations:read")),
):
    return _integration_out(_get_integration(session, principal.organization_id, integration_id))


@router.patch("/{integration_id}", response_model=IntegrationOut)
def update_integration(
    integration_id: uuid.UUID,
    body: IntegrationUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("integrations:manage")),
):
    integration = _get_integration(session, principal.organization_id, integration_id)
    if body.name is not None:
        integration.name = body.name
    if body.config is not None:
        integration.config = body.config
    session.flush()
    _audit(session, principal, audit_mod.INTEGRATION_UPDATED, str(integration.id), {"name": integration.name})
    out = _integration_out(integration)
    session.commit()
    return out


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(
    integration_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("integrations:manage")),
):
    integration = _get_integration(session, principal.organization_id, integration_id)
    session.delete(integration)
    session.flush()
    _audit(session, principal, audit_mod.INTEGRATION_DELETED, str(integration.id), {"name": integration.name})
    session.commit()
    return None


# --- Credentials ------------------------------------------------------------


@router.get("/{integration_id}/credentials", response_model=list[CredentialOut])
def list_credentials(
    integration_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("integrations:read")),
):
    integration = _get_integration(session, principal.organization_id, integration_id)
    return [CredentialOut(key_name=name) for name in integration_service.list_credential_names(session, integration)]


@router.post("/{integration_id}/credentials", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
def set_credential(
    integration_id: uuid.UUID,
    body: CredentialCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("integrations:manage")),
):
    integration = _get_integration(session, principal.organization_id, integration_id)
    try:
        integration_service.set_credential(session, integration, body.key_name, body.value)
    except SecretStorageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    _audit(
        session,
        principal,
        audit_mod.INTEGRATION_CREDENTIAL_SET,
        str(integration.id),
        {"provider": integration.provider, "key_name": body.key_name},
    )
    out = CredentialOut(key_name=body.key_name)
    session.commit()
    return out


# --- Test connection --------------------------------------------------------


@router.post("/{integration_id}/test-connection", response_model=TestConnectionOut)
def test_connection(
    integration_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("integrations:manage")),
):
    """Perform a real connection check; the recorded status is the honest
    outcome (connected only on a verified successful call)."""
    integration = _get_integration(session, principal.organization_id, integration_id)
    integration_service.test_connection(session, integration)
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.INTEGRATION_TESTED,
        str(integration.id),
        {"provider": integration.provider, "result": integration.last_test_result},
    )
    out = TestConnectionOut(
        id=integration.id,
        provider=integration.provider,
        status=integration.status,
        last_tested_at=integration.last_tested_at,
        last_test_result=integration.last_test_result,
        last_error=integration.last_error,
    )
    session.commit()
    return out
