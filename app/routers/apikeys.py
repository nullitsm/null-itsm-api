"""API-key routes (developer portal) + the API-key auth dependency.

Permissions: ``apikeys:read`` / ``apikeys:manage``. Cross-org ids are 404,
never 403. The raw key is returned exactly once, in the create response;
list/get responses carry only the display prefix. Revocation is DELETE.

``get_api_key_principal`` authenticates a request by its ``X-Api-Key``
header against the SHA-256-hashed store and resolves org + scopes. The
coordinator wires it into the main dependency chain at integration — it
is NOT used by the management routes below (those use bearer auth).
Audit actions use the centralized constants in ``app/audit.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, Unauthorized, get_db, require_permission
from app.models.integrations import ApiKey
from app.services import apikey_service
from app.services.apikey_service import ApiKeyAuthError, ApiKeyError, ApiKeyPrincipal, revoke_api_key

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class ApiKeyOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    updated_at: datetime
    # Present ONLY in the create response: the raw key, shown once.
    key: str | None = None


# --- Helpers ----------------------------------------------------------------


def _api_key_out(k: ApiKey, raw_key: str | None = None) -> ApiKeyOut:
    return ApiKeyOut(
        id=k.id,
        organization_id=k.organization_id,
        name=k.name,
        key_prefix=k.key_prefix,
        scopes=list(k.scopes or []),
        expires_at=k.expires_at,
        revoked_at=k.revoked_at,
        last_used_at=k.last_used_at,
        created_at=k.created_at,
        updated_at=k.updated_at,
        key=raw_key,
    )


def _get_api_key(session: Session, org_id: uuid.UUID, key_id: uuid.UUID) -> ApiKey:
    key = session.get(ApiKey, key_id)
    if key is None or key.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    return key


def _audit(session: Session, principal: Principal, action: str, resource_id: str, metadata: dict | None = None):
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type="api_key",
        resource_id=resource_id,
        outcome="success",
        metadata=metadata or {},
    )


# --- API-key auth dependency -------------------------------------------------
# Wired into the main dependency chain by the coordinator at integration.
# It authenticates by X-Api-Key against the hashed store, resolves the
# org + scopes, stamps last_used_at, and RLS-scopes the session to the
# key's org (see apikey_service.authenticate_api_key).


def get_api_key_principal(
    request: Request,
    session: Session = Depends(get_db),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
) -> ApiKeyPrincipal:
    if not x_api_key:
        raise Unauthorized("Missing API key")
    try:
        return apikey_service.authenticate_api_key(session, x_api_key)
    except ApiKeyAuthError as exc:
        raise Unauthorized(str(exc))


# --- Management routes (bearer auth) ----------------------------------------


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("apikeys:read"))
):
    rows = (
        session.execute(
            select(ApiKey).where(ApiKey.organization_id == principal.organization_id).order_by(ApiKey.created_at)
        )
        .scalars()
        .all()
    )
    return [_api_key_out(k) for k in rows]


@router.post("", response_model=ApiKeyOut, status_code=status.HTTP_201_CREATED)
def create_api_key(
    body: ApiKeyCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("apikeys:manage")),
):
    try:
        key, raw_key = apikey_service.create_api_key(
            session,
            organization_id=principal.organization_id,
            name=body.name,
            scopes=body.scopes,
            expires_at=body.expires_at,
            created_by_id=principal.user_id,
        )
    except ApiKeyError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    _audit(session, principal, audit_mod.APIKEY_CREATED, str(key.id), {"name": body.name, "scopes": body.scopes})
    out = _api_key_out(key, raw_key=raw_key)
    session.commit()
    return out


@router.get("/{key_id}", response_model=ApiKeyOut)
def get_api_key(
    key_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("apikeys:read")),
):
    return _api_key_out(_get_api_key(session, principal.organization_id, key_id))


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_api_key(
    key_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("apikeys:manage")),
):
    """Revoke an API key (the row is kept for audit; the key stops working)."""
    key = _get_api_key(session, principal.organization_id, key_id)
    revoke_api_key(session, key)
    _audit(session, principal, audit_mod.APIKEY_REVOKED, str(key.id), {"name": key.name})
    session.commit()
    return None
