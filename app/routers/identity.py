"""Identity routes: IdPs (SAML/OIDC), SAML ACS + SP metadata, OIDC
discovery, SCIM v2 provisioning, directory sync, access certification,
temporary access, service accounts, API credentials.

Permissions: ``identity:read`` / ``identity:manage`` for the JWT
endpoints. The SCIM v2 endpoints authenticate with a SCIM bearer token
instead (resolved by SHA-256 hash through the SECURITY DEFINER function
in migration 0007); the SAML ACS endpoint is unauthenticated by design
(the IdP posts to it) and resolves its provider through the controlled
lookup function — it validates the assertion and reports the subject,
but mints no session (SSO session issuance is not part of this scope).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.database import set_rls_context
from app.deps import Principal, get_bearer_token, get_db, require_permission
from app.models.identity_assets import (
    AccessCertification,
    ApiCredential,
    CertificationItem,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectorySyncRun,
    IdentityProvider,
    ScimToken,
    ServiceAccount,
    TemporaryAccessGrant,
)
from app.models.platform import Membership, User
from app.models.rbac import Role
from app.security import new_opaque_token
from app.services import identity_service
from app.services.saml_service import SamlValidationError, build_sp_metadata, get_saml_validator, saml_lib_available

UTC = timezone.utc

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class IdPCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    type: str = Field(pattern="^(saml|oidc)$")
    saml_entity_id: str | None = None
    saml_sso_url: str | None = None
    saml_certificate: str | None = None
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    is_default: bool = False


class IdPUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    saml_entity_id: str | None = None
    saml_sso_url: str | None = None
    saml_certificate: str | None = None
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    is_default: bool | None = None


class IdPOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    type: str
    status: str
    saml_entity_id: str | None
    saml_sso_url: str | None
    oidc_issuer: str | None
    oidc_client_id: str | None
    is_default: bool
    has_client_secret: bool
    has_certificate: bool
    created_at: datetime
    updated_at: datetime


class ScimTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=lambda: ["users:read", "users:write"])
    expires_at: datetime | None = None


class ScimTokenOut(BaseModel):
    id: uuid.UUID
    name: str
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    token: str | None = None  # raw token, present ONLY at creation


class DirectorySyncCreate(BaseModel):
    provider_id: uuid.UUID | None = None
    source: str = Field(pattern="^(entra|ad|ldap|scim)$")


class DirectorySyncRunOut(BaseModel):
    id: uuid.UUID
    provider_id: uuid.UUID | None
    source: str
    status: str
    users_created: int
    users_updated: int
    users_deprovisioned: int
    groups_synced: int
    error: str | None
    completed_at: datetime | None
    created_at: datetime


class DirectoryGroupCreate(BaseModel):
    provider_id: uuid.UUID | None = None
    external_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    role_id: uuid.UUID | None = None


class DirectoryGroupOut(BaseModel):
    id: uuid.UUID
    provider_id: uuid.UUID | None
    external_id: str
    name: str
    member_count: int
    role_id: uuid.UUID | None
    last_synced_at: datetime | None
    created_at: datetime


class CertificationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    reviewer_id: uuid.UUID | None = None
    scope: dict = Field(default_factory=dict)
    due_at: datetime | None = None


class CertificationOut(BaseModel):
    id: uuid.UUID
    name: str
    reviewer_id: uuid.UUID | None
    status: str
    scope: dict
    due_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class CertificationItemOut(BaseModel):
    id: uuid.UUID
    certification_id: uuid.UUID
    user_id: uuid.UUID
    role_id: uuid.UUID | None
    decision: str
    decided_by_id: uuid.UUID | None
    decided_at: datetime | None
    created_at: datetime


class CertificationDecision(BaseModel):
    decision: str = Field(pattern="^(approved|revoked)$")


class TempGrantCreate(BaseModel):
    user_id: uuid.UUID
    role_id: uuid.UUID
    reason: str = ""
    expires_at: datetime


class TempGrantOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    role_id: uuid.UUID
    granted_by_id: uuid.UUID | None
    reason: str
    expires_at: datetime
    revoked_at: datetime | None
    status: str
    created_at: datetime


class ServiceAccountCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = ""
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class ServiceAccountOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    credential: str | None = None  # raw secret, present ONLY at creation/rotation


class ApiCredentialCreate(BaseModel):
    user_id: uuid.UUID
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class ApiCredentialOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    credential: str | None = None  # raw credential, present ONLY at creation/rotation


class ApiCredentialVerify(BaseModel):
    credential: str = Field(min_length=1)


# --- Helpers ----------------------------------------------------------------


def _idp_out(p: IdentityProvider) -> IdPOut:
    return IdPOut(
        id=p.id,
        organization_id=p.organization_id,
        name=p.name,
        type=p.type,
        status=p.status,
        saml_entity_id=p.saml_entity_id,
        saml_sso_url=p.saml_sso_url,
        oidc_issuer=p.oidc_issuer,
        oidc_client_id=p.oidc_client_id,
        is_default=p.is_default,
        has_client_secret=bool(p.oidc_client_secret_encrypted),
        has_certificate=bool(p.saml_certificate),
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


def _get_provider(session: Session, org_id: uuid.UUID, provider_id: uuid.UUID) -> IdentityProvider:
    provider = session.get(IdentityProvider, provider_id)
    if provider is None or provider.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity provider not found")
    return provider


def _get_provider_public(session: Session, provider_id: uuid.UUID) -> dict:
    """Unauthenticated provider lookup for the ACS endpoint.

    Uses the controlled SECURITY DEFINER function (migration 0007):
    the IdP posts with no session, so the provider row must be resolved
    before any RLS context exists. Returns the public SAML config only.
    """
    row = (
        session.execute(text("SELECT * FROM auth_get_identity_provider_by_id(:id)"), {"id": str(provider_id)})
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity provider not found")
    return dict(row)


def _provider_from_public_row(row: dict) -> IdentityProvider:
    """Rebuild a transient IdentityProvider from the ACS lookup row."""
    return IdentityProvider(
        id=row["id"],
        organization_id=row["organization_id"],
        name=row["name"],
        type=row["type"],
        status=row["status"],
        saml_entity_id=row["saml_entity_id"],
        saml_sso_url=row["saml_sso_url"],
        saml_certificate=row["saml_certificate"],
        oidc_issuer=row["oidc_issuer"],
        oidc_client_id=row["oidc_client_id"],
        is_default=row["is_default"],
    )


# --- Identity providers -----------------------------------------------------


@router.get("/providers", response_model=list[IdPOut])
def list_providers(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:read"))
):
    rows = session.execute(
        select(IdentityProvider)
        .where(IdentityProvider.organization_id == principal.organization_id)
        .order_by(IdentityProvider.created_at)
    ).scalars()
    return [_idp_out(p) for p in rows]


@router.post("/providers", response_model=IdPOut, status_code=status.HTTP_201_CREATED)
def create_provider(
    body: IdPCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    encrypted_secret = None
    if body.oidc_client_secret:
        try:
            encrypted_secret = identity_service.encrypt_secret(body.oidc_client_secret)
        except identity_service.SecretStorageError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    provider = IdentityProvider(
        organization_id=principal.organization_id,
        name=body.name,
        type=body.type,
        saml_entity_id=body.saml_entity_id,
        saml_sso_url=body.saml_sso_url,
        saml_certificate=body.saml_certificate,
        oidc_issuer=body.oidc_issuer,
        oidc_client_id=body.oidc_client_id,
        oidc_client_secret_encrypted=encrypted_secret,
        is_default=body.is_default,
        created_by_id=principal.user_id,
    )
    if body.is_default:
        others = (
            session.execute(
                select(IdentityProvider).where(
                    IdentityProvider.organization_id == principal.organization_id, IdentityProvider.is_default.is_(True)
                )
            )
            .scalars()
            .all()
        )
        for other in others:
            other.is_default = False
    session.add(provider)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.IDP_CREATED,
        resource_type="identity_provider",
        resource_id=str(provider.id),
        outcome="success",
        metadata={"name": body.name, "type": body.type},
    )
    out = _idp_out(provider)
    session.commit()
    return out


@router.get("/providers/{provider_id}", response_model=IdPOut)
def get_provider(
    provider_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:read")),
):
    return _idp_out(_get_provider(session, principal.organization_id, provider_id))


@router.patch("/providers/{provider_id}", response_model=IdPOut)
def update_provider(
    provider_id: uuid.UUID,
    body: IdPUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    provider = _get_provider(session, principal.organization_id, provider_id)
    if body.name is not None:
        provider.name = body.name
    if body.status is not None:
        if body.status not in ("active", "inactive"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        provider.status = body.status
    for field in ("saml_entity_id", "saml_sso_url", "saml_certificate", "oidc_issuer", "oidc_client_id"):
        value = getattr(body, field)
        if value is not None:
            setattr(provider, field, value)
    if body.oidc_client_secret is not None:
        try:
            provider.oidc_client_secret_encrypted = identity_service.encrypt_secret(body.oidc_client_secret)
        except identity_service.SecretStorageError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    if body.is_default is not None:
        if body.is_default:
            others = (
                session.execute(
                    select(IdentityProvider).where(
                        IdentityProvider.organization_id == principal.organization_id,
                        IdentityProvider.is_default.is_(True),
                        IdentityProvider.id != provider.id,
                    )
                )
                .scalars()
                .all()
            )
            for other in others:
                other.is_default = False
        provider.is_default = body.is_default
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.IDP_UPDATED,
        resource_type="identity_provider",
        resource_id=str(provider.id),
        outcome="success",
    )
    out = _idp_out(provider)
    session.commit()
    return out


@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(
    provider_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    provider = _get_provider(session, principal.organization_id, provider_id)
    session.delete(provider)
    session.commit()
    return None


@router.post("/providers/{provider_id}/set-default", response_model=IdPOut)
def set_default_provider(
    provider_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    provider = _get_provider(session, principal.organization_id, provider_id)
    others = (
        session.execute(
            select(IdentityProvider).where(
                IdentityProvider.organization_id == principal.organization_id,
                IdentityProvider.is_default.is_(True),
                IdentityProvider.id != provider.id,
            )
        )
        .scalars()
        .all()
    )
    for other in others:
        other.is_default = False
    provider.is_default = True
    session.flush()
    out = _idp_out(provider)
    session.commit()
    return out


@router.get("/providers/{provider_id}/metadata")
def get_sp_metadata(
    provider_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:read")),
):
    provider = _get_provider(session, principal.organization_id, provider_id)
    if provider.type != "saml":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SP metadata is only for SAML providers")
    import os

    base_url = os.environ.get("NULL_PUBLIC_BASE_URL") or str(request.base_url).rstrip("/")
    xml = build_sp_metadata(provider, principal.organization_id, base_url)
    return Response(content=xml, media_type="application/xml")


@router.post("/providers/{provider_id}/acs")
async def saml_acs(provider_id: uuid.UUID, request: Request, session: Session = Depends(get_db)):
    """SAML Assertion Consumer Service (unauthenticated — the IdP posts).

    Validates the assertion with python3-saml and returns the validated
    subject. Mints NO session: SSO session issuance is out of scope, and
    an unvalidated assertion is never accepted as a login.
    """
    row = _get_provider_public(session, provider_id)
    provider = _provider_from_public_row(row)
    if provider.type != "saml":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provider is not a SAML provider")
    if provider.status != "active":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Identity provider is inactive")
    saml_response = None
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        saml_response = form.get("SAMLResponse")
    else:
        try:
            payload = await request.json()
            saml_response = payload.get("SAMLResponse") if isinstance(payload, dict) else None
        except Exception:
            saml_response = None
    if not saml_response:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing SAMLResponse")
    if not saml_lib_available():
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SAML assertion validation requires python3-saml (not installed)",
        )
    import os

    base_url = os.environ.get("NULL_PUBLIC_BASE_URL") or str(request.base_url).rstrip("/")
    acs_url = f"{base_url}/api/v1/identity/providers/{provider_id}/acs"
    try:
        result = get_saml_validator().validate(str(saml_response), provider, acs_url)
    except SamlValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {
        "validated": True,
        "provider_id": str(provider.id),
        "organization_id": str(provider.organization_id),
        "name_id": result.get("name_id"),
        "email": result.get("email"),
        "attributes": result.get("attributes", {}),
    }


# --- OIDC discovery ---------------------------------------------------------


@router.get("/providers/{provider_id}/discover")
def discover_provider(
    provider_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:read")),
):
    provider = _get_provider(session, principal.organization_id, provider_id)
    if provider.type != "oidc" or not provider.oidc_issuer:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provider has no OIDC issuer configured")
    try:
        return identity_service.discover_oidc(provider.oidc_issuer)
    except identity_service.OidcDiscoveryError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


# --- SCIM tokens ------------------------------------------------------------


def _scim_token_out(row: ScimToken, raw: str | None = None) -> ScimTokenOut:
    return ScimTokenOut(
        id=row.id,
        name=row.name,
        scopes=list(row.scopes or []),
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
        created_at=row.created_at,
        token=raw,
    )


@router.get("/scim-tokens", response_model=list[ScimTokenOut])
def list_scim_tokens(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:manage"))
):
    rows = session.execute(
        select(ScimToken).where(ScimToken.organization_id == principal.organization_id).order_by(ScimToken.created_at)
    ).scalars()
    return [_scim_token_out(r) for r in rows]


@router.post("/scim-tokens", response_model=ScimTokenOut, status_code=status.HTTP_201_CREATED)
def create_scim_token(
    body: ScimTokenCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    raw = new_opaque_token()
    row = ScimToken(
        organization_id=principal.organization_id,
        name=body.name,
        token_hash=identity_service.hash_secret(raw),
        scopes=body.scopes,
        expires_at=body.expires_at,
        created_by_id=principal.user_id,
    )
    session.add(row)
    session.flush()
    out = _scim_token_out(row, raw=raw)  # raw token shown ONLY here
    session.commit()
    return out


@router.post("/scim-tokens/{token_id}/revoke", response_model=ScimTokenOut)
def revoke_scim_token(
    token_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    row = session.get(ScimToken, token_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SCIM token not found")
    row.revoked_at = datetime.now(UTC)
    session.flush()
    out = _scim_token_out(row)
    session.commit()
    return out


# --- SCIM v2 ---------------------------------------------------------------
# Auth: Authorization: Bearer <raw SCIM token>. The token IS the
# credential: resolved by SHA-256 hash through the SECURITY DEFINER
# function, then the session is RLS-scoped to the token's org. A
# wrong/expired/revoked token is 401; a token from org A can never touch
# org B (its RLS context is org A).


def _scim_principal(request: Request, session: Session = Depends(get_db)) -> dict:
    raw = get_bearer_token(request)
    try:
        row = identity_service.resolve_scim_token(session, raw)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid SCIM token")
    org_id = uuid.UUID(str(row["organization_id"]))
    actor_id = uuid.UUID(str(row["created_by_id"])) if row.get("created_by_id") else None
    set_rls_context(session, org_id, actor_id)
    token_row = session.get(ScimToken, uuid.UUID(str(row["id"])))
    if token_row is not None:
        token_row.last_used_at = datetime.now(UTC)
        session.flush()
    return {"org_id": org_id, "actor_id": actor_id, "token": row}


_SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
_SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def _scim_error(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"schemas": [_SCIM_ERROR_SCHEMA], "status": str(status_code), "detail": detail},
    )


def _scim_user_resource(session: Session, org_id: uuid.UUID, row: dict) -> dict:
    """Build a SCIM User resource from a scim_* function row.

    Rows come from the 0007 SECURITY DEFINER functions (any membership
    status), NOT from the ORM: the org users SELECT policy hides invited
    members, so an ORM load would 404 a user SCIM just provisioned.
    """
    user_id = uuid.UUID(str(row["id"]))
    full_name = row.get("full_name") or ""
    parts = full_name.split(" ", 1)
    group_rows = (
        session.execute(
            select(DirectoryGroup)
            .join(
                DirectoryGroupMembership,
                DirectoryGroupMembership.group_id == DirectoryGroup.id,
            )
            .where(
                DirectoryGroupMembership.organization_id == org_id,
                DirectoryGroupMembership.user_id == user_id,
            )
        )
        .scalars()
        .all()
    )
    return {
        "schemas": [_SCIM_USER_SCHEMA],
        "id": str(user_id),
        "userName": row["email"],
        "name": {
            "formatted": full_name,
            "givenName": parts[0] if parts else "",
            "familyName": parts[1] if len(parts) > 1 else "",
        },
        "emails": [{"value": row["email"], "primary": True}],
        "active": row.get("membership_status") != "suspended",
        "groups": [{"value": str(g.id), "display": g.name} for g in group_rows],
        "meta": {"resourceType": "User"},
    }


def _scim_user_row(session: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> dict | None:
    """The function row for one org member, or None (SCIM 404)."""
    return identity_service.scim_get_org_user(session, org_id, user_id)


class _ScimNotFound(Exception):
    """Internal control-flow: the SCIM resource does not exist in this org."""


def _update_scim_user_name(
    session: Session, org_id: uuid.UUID, actor_id: uuid.UUID | None, user_id: uuid.UUID, full_name: str
) -> None:
    """Update a SCIM user's name through the ORM.

    The users UPDATE policy only passes for the row's own id, so the RLS
    user context is switched to the target user for the update (same rule
    the seed fixtures follow for user creation), then restored.
    """
    set_rls_context(session, org_id, user_id)
    try:
        user = session.get(User, user_id)
        if user is None:
            raise _ScimNotFound
        user.full_name = full_name
        session.flush()
    finally:
        set_rls_context(session, org_id, actor_id)


def _scim_group_resource(session: Session, org_id: uuid.UUID, group: DirectoryGroup) -> dict:
    member_ids = [
        r[0]
        for r in session.execute(
            select(DirectoryGroupMembership.user_id).where(
                DirectoryGroupMembership.organization_id == org_id,
                DirectoryGroupMembership.group_id == group.id,
            )
        ).all()
    ]
    # Member emails come from the SCIM function rows: the ORM join would
    # hide invited members (same RLS rule as _scim_user_resource).
    by_id = {uuid.UUID(str(r["id"])): r for r in identity_service.scim_list_org_users(session, org_id)}
    return {
        "schemas": [_SCIM_GROUP_SCHEMA],
        "id": str(group.id),
        "displayName": group.name,
        "members": [{"value": str(uid), "display": by_id[uid]["email"]} for uid in member_ids if uid in by_id],
        "meta": {"resourceType": "Group"},
    }


def _scim_list(resources: list[dict], start_index: int, count: int, total: int) -> dict:
    return {
        "schemas": [_SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


_FILTER_RE = re.compile(r'^\s*([\w.]+)\s+eq\s+"([^"]*)"\s*$')


def _parse_scim_filter(filter_value: str | None) -> tuple[str, str] | None:
    if not filter_value:
        return None
    match = _FILTER_RE.match(filter_value)
    if not match:
        return None
    return match.group(1), match.group(2)


def _resolve_scim_group_ref(session: Session, org_id: uuid.UUID, ref: str) -> DirectoryGroup | None:
    try:
        group_id = uuid.UUID(ref)
    except ValueError:
        group_id = None
    if group_id is not None:
        group = session.get(DirectoryGroup, group_id)
        if group is not None and group.organization_id == org_id:
            return group
    return session.execute(
        select(DirectoryGroup).where(DirectoryGroup.organization_id == org_id, DirectoryGroup.external_id == ref)
    ).scalar_one_or_none()


def _sync_scim_group_members(session: Session, org_id: uuid.UUID, group: DirectoryGroup) -> None:
    count = session.execute(
        select(DirectoryGroupMembership).where(
            DirectoryGroupMembership.organization_id == org_id,
            DirectoryGroupMembership.group_id == group.id,
        )
    ).scalars()
    group.member_count = len(list(count))
    group.last_synced_at = datetime.now(UTC)
    session.flush()


@router.get("/scim/v2/Users")
def scim_list_users(
    request: Request,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    params = request.query_params
    start_index = max(1, int(params.get("startIndex", "1") or "1"))
    count = min(1000, max(1, int(params.get("count", "100") or "100")))
    rows = identity_service.scim_list_org_users(session, scim["org_id"])
    parsed = _parse_scim_filter(params.get("filter"))
    if parsed:
        attr, value = parsed
        if attr == "userName":
            rows = [r for r in rows if r["email"] == value]
        elif attr == "active":
            want_active = value.lower() == "true"
            rows = [r for r in rows if (r.get("membership_status") != "suspended") == want_active]
        else:
            return _scim_error(400, f"Unsupported SCIM filter attribute: {attr}")
    total = len(rows)
    page = rows[start_index - 1 : start_index - 1 + count]
    return _scim_list([_scim_user_resource(session, scim["org_id"], r) for r in page], start_index, count, total)


@router.post("/scim/v2/Users", status_code=status.HTTP_201_CREATED)
def scim_create_user(
    body: dict,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    org_id = scim["org_id"]
    user_name = body.get("userName")
    emails = body.get("emails") or []
    email = (emails[0].get("value") if emails and isinstance(emails[0], dict) else None) or user_name
    if not email:
        return _scim_error(400, "userName (or emails[0].value) is required")
    name = body.get("name") or {}
    full_name = (
        name.get("formatted") or " ".join(p for p in (name.get("givenName"), name.get("familyName")) if p) or email
    )
    existing = identity_service.find_user_by_email(session, email)
    if existing is not None:
        existing_membership = session.execute(
            select(Membership).where(
                Membership.organization_id == org_id, Membership.user_id == uuid.UUID(str(existing["id"]))
            )
        ).scalar_one_or_none()
        if existing_membership is not None:
            return _scim_error(409, f"User {email} already exists in this organization")
    active = bool(body.get("active", True))
    user, membership, _ = identity_service.provision_scim_user(
        session, org_id, scim["actor_id"], email, full_name, active=active
    )
    for ref in body.get("groups") or []:
        group = _resolve_scim_group_ref(session, org_id, str(ref.get("value", "")))
        if group is not None:
            session.add(
                DirectoryGroupMembership(
                    organization_id=org_id,
                    group_id=group.id,
                    user_id=user.id,
                    external_user_id=str(ref.get("value", "")),
                )
            )
            session.flush()
            _sync_scim_group_members(session, org_id, group)
    identity_service.sync_all_group_role_mappings(session, org_id)
    session.flush()
    row = {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "membership_status": membership.status if membership is not None else "invited",
    }
    resource = _scim_user_resource(session, org_id, row)
    session.commit()
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=resource)


@router.get("/scim/v2/Users/{user_id}")
def scim_get_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    row = _scim_user_row(session, scim["org_id"], user_id)
    if row is None:
        return _scim_error(404, "User not found")
    return _scim_user_resource(session, scim["org_id"], row)


@router.put("/scim/v2/Users/{user_id}")
def scim_replace_user(
    user_id: uuid.UUID,
    body: dict,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    org_id = scim["org_id"]
    row = _scim_user_row(session, org_id, user_id)
    if row is None:
        return _scim_error(404, "User not found")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        return _scim_error(404, "User not found")
    name = body.get("name") or {}
    full_name = name.get("formatted") or " ".join(p for p in (name.get("givenName"), name.get("familyName")) if p)
    if full_name:
        try:
            _update_scim_user_name(session, org_id, scim["actor_id"], user_id, full_name)
        except _ScimNotFound:
            return _scim_error(404, "User not found")
        row["full_name"] = full_name
    if "active" in body:
        membership.status = "active" if body["active"] else "suspended"
        row["membership_status"] = membership.status
    session.flush()
    resource = _scim_user_resource(session, org_id, row)
    session.commit()
    return resource


@router.patch("/scim/v2/Users/{user_id}")
def scim_patch_user(
    user_id: uuid.UUID,
    body: dict,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    org_id = scim["org_id"]
    row = _scim_user_row(session, org_id, user_id)
    if row is None:
        return _scim_error(404, "User not found")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        return _scim_error(404, "User not found")
    for op in body.get("Operations") or []:
        operation = (op.get("op") or "").lower()
        path = op.get("path") or ""
        value = op.get("value")
        if path == "active" and operation in ("replace", "add"):
            membership.status = "active" if value else "suspended"
            row["membership_status"] = membership.status
        elif path.startswith("name.formatted") and operation == "replace":
            try:
                _update_scim_user_name(session, org_id, scim["actor_id"], user_id, str(value))
            except _ScimNotFound:
                return _scim_error(404, "User not found")
            row["full_name"] = str(value)
        elif path == "groups" and isinstance(value, list):
            for ref in value:
                group = _resolve_scim_group_ref(session, org_id, str(ref.get("value", "")))
                if group is None:
                    continue
                if operation == "add":
                    exists = session.execute(
                        select(DirectoryGroupMembership).where(
                            DirectoryGroupMembership.group_id == group.id,
                            DirectoryGroupMembership.user_id == user_id,
                        )
                    ).scalar_one_or_none()
                    if exists is None:
                        session.add(
                            DirectoryGroupMembership(organization_id=org_id, group_id=group.id, user_id=user_id)
                        )
                elif operation == "remove":
                    from sqlalchemy import delete as _delete

                    session.execute(
                        _delete(DirectoryGroupMembership).where(
                            DirectoryGroupMembership.group_id == group.id,
                            DirectoryGroupMembership.user_id == user_id,
                        )
                    )
                session.flush()
                _sync_scim_group_members(session, org_id, group)
    identity_service.sync_all_group_role_mappings(session, org_id)
    session.flush()
    resource = _scim_user_resource(session, org_id, row)
    session.commit()
    return resource


@router.delete("/scim/v2/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def scim_delete_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    org_id = scim["org_id"]
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        return _scim_error(404, "User not found")
    identity_service.deactivate_scim_user(session, org_id, user_id)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/scim/v2/Groups")
def scim_list_groups(
    request: Request,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    params = request.query_params
    start_index = max(1, int(params.get("startIndex", "1") or "1"))
    count = min(1000, max(1, int(params.get("count", "100") or "100")))
    query = select(DirectoryGroup).where(DirectoryGroup.organization_id == scim["org_id"])
    parsed = _parse_scim_filter(params.get("filter"))
    if parsed:
        attr, value = parsed
        if attr == "displayName":
            query = query.where(DirectoryGroup.name == value)
        else:
            return _scim_error(400, f"Unsupported SCIM filter attribute: {attr}")
    total = len(session.execute(query).scalars().all())
    rows = session.execute(query.offset(start_index - 1).limit(count)).scalars().all()
    return _scim_list([_scim_group_resource(session, scim["org_id"], g) for g in rows], start_index, count, total)


@router.post("/scim/v2/Groups", status_code=status.HTTP_201_CREATED)
def scim_create_group(
    body: dict,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    org_id = scim["org_id"]
    display_name = body.get("displayName")
    if not display_name:
        return _scim_error(400, "displayName is required")
    external_id = body.get("externalId") or str(uuid.uuid4())
    existing = session.execute(
        select(DirectoryGroup).where(
            DirectoryGroup.organization_id == org_id, DirectoryGroup.external_id == external_id
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _scim_error(409, f"Group {display_name} already exists")
    group = DirectoryGroup(organization_id=org_id, external_id=external_id, name=display_name)
    session.add(group)
    session.flush()
    for member in body.get("members") or []:
        try:
            member_id = uuid.UUID(str(member.get("value", "")))
        except ValueError:
            continue
        # Membership check via the SCIM function: the ORM would hide
        # invited members (same RLS rule as _scim_user_resource).
        if identity_service.scim_get_org_user(session, org_id, member_id) is None:
            continue
        session.add(
            DirectoryGroupMembership(
                organization_id=org_id,
                group_id=group.id,
                user_id=member_id,
                external_user_id=str(member.get("value", "")),
            )
        )
    session.flush()
    _sync_scim_group_members(session, org_id, group)
    identity_service.sync_all_group_role_mappings(session, org_id)
    resource = _scim_group_resource(session, org_id, group)
    session.commit()
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=resource)


@router.get("/scim/v2/Groups/{group_id}")
def scim_get_group(
    group_id: uuid.UUID,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    group = session.get(DirectoryGroup, group_id)
    if group is None or group.organization_id != scim["org_id"]:
        return _scim_error(404, "Group not found")
    return _scim_group_resource(session, scim["org_id"], group)


@router.put("/scim/v2/Groups/{group_id}")
def scim_replace_group(
    group_id: uuid.UUID,
    body: dict,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    org_id = scim["org_id"]
    group = session.get(DirectoryGroup, group_id)
    if group is None or group.organization_id != org_id:
        return _scim_error(404, "Group not found")
    if body.get("displayName"):
        group.name = body["displayName"]
    from sqlalchemy import delete as _delete

    session.execute(_delete(DirectoryGroupMembership).where(DirectoryGroupMembership.group_id == group.id))
    for member in body.get("members") or []:
        try:
            member_id = uuid.UUID(str(member.get("value", "")))
        except ValueError:
            continue
        if identity_service.scim_get_org_user(session, org_id, member_id) is None:
            continue
        session.add(DirectoryGroupMembership(organization_id=org_id, group_id=group.id, user_id=member_id))
    session.flush()
    _sync_scim_group_members(session, org_id, group)
    identity_service.sync_all_group_role_mappings(session, org_id)
    resource = _scim_group_resource(session, org_id, group)
    session.commit()
    return resource


@router.patch("/scim/v2/Groups/{group_id}")
def scim_patch_group(
    group_id: uuid.UUID,
    body: dict,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    org_id = scim["org_id"]
    group = session.get(DirectoryGroup, group_id)
    if group is None or group.organization_id != org_id:
        return _scim_error(404, "Group not found")
    from sqlalchemy import delete as _delete

    for op in body.get("Operations") or []:
        operation = (op.get("op") or "").lower()
        path = op.get("path") or ""
        value = op.get("value")
        if path == "displayName" and operation == "replace":
            group.name = str(value)
        elif path == "members" and isinstance(value, list):
            for ref in value:
                try:
                    member_id = uuid.UUID(str(ref.get("value", "")))
                except ValueError:
                    continue
                if operation == "add":
                    exists = session.execute(
                        select(DirectoryGroupMembership).where(
                            DirectoryGroupMembership.group_id == group.id,
                            DirectoryGroupMembership.user_id == member_id,
                        )
                    ).scalar_one_or_none()
                    if exists is None and identity_service.scim_get_org_user(session, org_id, member_id) is not None:
                        session.add(
                            DirectoryGroupMembership(organization_id=org_id, group_id=group.id, user_id=member_id)
                        )
                elif operation == "remove":
                    session.execute(
                        _delete(DirectoryGroupMembership).where(
                            DirectoryGroupMembership.group_id == group.id,
                            DirectoryGroupMembership.user_id == member_id,
                        )
                    )
            session.flush()
            _sync_scim_group_members(session, org_id, group)
    identity_service.sync_all_group_role_mappings(session, org_id)
    session.flush()
    resource = _scim_group_resource(session, org_id, group)
    session.commit()
    return resource


@router.delete("/scim/v2/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def scim_delete_group(
    group_id: uuid.UUID,
    session: Session = Depends(get_db),
    scim: dict = Depends(_scim_principal),
):
    group = session.get(DirectoryGroup, group_id)
    if group is None or group.organization_id != scim["org_id"]:
        return _scim_error(404, "Group not found")
    session.delete(group)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Directory sync ---------------------------------------------------------


def _sync_run_out(run: DirectorySyncRun) -> DirectorySyncRunOut:
    return DirectorySyncRunOut(
        id=run.id,
        provider_id=run.provider_id,
        source=run.source,
        status=run.status,
        users_created=run.users_created,
        users_updated=run.users_updated,
        users_deprovisioned=run.users_deprovisioned,
        groups_synced=run.groups_synced,
        error=run.error,
        completed_at=run.completed_at,
        created_at=run.created_at,
    )


@router.post("/directory-sync", response_model=DirectorySyncRunOut, status_code=status.HTTP_201_CREATED)
def start_directory_sync(
    body: DirectorySyncCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    try:
        run = identity_service.run_directory_sync(
            session, principal.organization_id, body.provider_id, body.source, principal.user_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _sync_run_out(run)
    session.commit()
    return out


@router.get("/directory-sync/runs", response_model=list[DirectorySyncRunOut])
def list_directory_sync_runs(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:read"))
):
    rows = session.execute(
        select(DirectorySyncRun)
        .where(DirectorySyncRun.organization_id == principal.organization_id)
        .order_by(DirectorySyncRun.created_at.desc())
    ).scalars()
    return [_sync_run_out(r) for r in rows]


@router.get("/directory-sync/runs/{run_id}", response_model=DirectorySyncRunOut)
def get_directory_sync_run(
    run_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:read")),
):
    run = session.get(DirectorySyncRun, run_id)
    if run is None or run.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Directory sync run not found")
    return _sync_run_out(run)


# --- Directory groups (JWT-managed) -----------------------------------------


def _dir_group_out(g: DirectoryGroup) -> DirectoryGroupOut:
    return DirectoryGroupOut(
        id=g.id,
        provider_id=g.provider_id,
        external_id=g.external_id,
        name=g.name,
        member_count=g.member_count,
        role_id=g.role_id,
        last_synced_at=g.last_synced_at,
        created_at=g.created_at,
    )


@router.get("/directory-groups", response_model=list[DirectoryGroupOut])
def list_directory_groups(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:read"))
):
    rows = session.execute(
        select(DirectoryGroup)
        .where(DirectoryGroup.organization_id == principal.organization_id)
        .order_by(DirectoryGroup.created_at)
    ).scalars()
    return [_dir_group_out(g) for g in rows]


@router.post("/directory-groups", response_model=DirectoryGroupOut, status_code=status.HTTP_201_CREATED)
def create_directory_group(
    body: DirectoryGroupCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    if body.provider_id is not None:
        _get_provider(session, principal.organization_id, body.provider_id)
    if body.role_id is not None:
        role = session.get(Role, body.role_id)
        if role is None or role.organization_id != principal.organization_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role not found")
    group = DirectoryGroup(
        organization_id=principal.organization_id,
        provider_id=body.provider_id,
        external_id=body.external_id,
        name=body.name,
        role_id=body.role_id,
    )
    session.add(group)
    try:
        session.flush()
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Group already exists: {exc}")
    out = _dir_group_out(group)
    session.commit()
    return out


@router.patch("/directory-groups/{group_id}", response_model=DirectoryGroupOut)
def update_directory_group(
    group_id: uuid.UUID,
    body: DirectoryGroupCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    group = session.get(DirectoryGroup, group_id)
    if group is None or group.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Directory group not found")
    if body.role_id is not None:
        role = session.get(Role, body.role_id)
        if role is None or role.organization_id != principal.organization_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role not found")
        group.role_id = body.role_id
    if body.name:
        group.name = body.name
    session.flush()
    # Re-apply the mapping immediately: members gain/lose the role now.
    if group.role_id is not None:
        identity_service.apply_group_role_mapping(session, principal.organization_id, group.role_id)
    out = _dir_group_out(group)
    session.commit()
    return out


# --- Access certification ---------------------------------------------------


def _cert_out(c: AccessCertification) -> CertificationOut:
    return CertificationOut(
        id=c.id,
        name=c.name,
        reviewer_id=c.reviewer_id,
        status=c.status,
        scope=c.scope or {},
        due_at=c.due_at,
        completed_at=c.completed_at,
        created_at=c.created_at,
    )


def _cert_item_out(i: CertificationItem) -> CertificationItemOut:
    return CertificationItemOut(
        id=i.id,
        certification_id=i.certification_id,
        user_id=i.user_id,
        role_id=i.role_id,
        decision=i.decision,
        decided_by_id=i.decided_by_id,
        decided_at=i.decided_at,
        created_at=i.created_at,
    )


@router.get("/certifications", response_model=list[CertificationOut])
def list_certifications(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:read"))
):
    rows = session.execute(
        select(AccessCertification)
        .where(AccessCertification.organization_id == principal.organization_id)
        .order_by(AccessCertification.created_at.desc())
    ).scalars()
    return [_cert_out(c) for c in rows]


@router.post("/certifications", response_model=CertificationOut, status_code=status.HTTP_201_CREATED)
def create_certification(
    body: CertificationCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    reviewer_id = body.reviewer_id or principal.user_id
    cert = identity_service.create_certification(
        session, principal.organization_id, reviewer_id, body.name, body.scope, body.due_at
    )
    out = _cert_out(cert)
    session.commit()
    return out


@router.get("/certifications/{cert_id}", response_model=CertificationOut)
def get_certification(
    cert_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:read")),
):
    cert = session.get(AccessCertification, cert_id)
    if cert is None or cert.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certification not found")
    return _cert_out(cert)


@router.get("/certifications/{cert_id}/items", response_model=list[CertificationItemOut])
def list_certification_items(
    cert_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:read")),
):
    cert = session.get(AccessCertification, cert_id)
    if cert is None or cert.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certification not found")
    rows = session.execute(
        select(CertificationItem)
        .where(CertificationItem.certification_id == cert_id)
        .order_by(CertificationItem.created_at)
    ).scalars()
    return [_cert_item_out(i) for i in rows]


@router.post("/certifications/{cert_id}/items/{item_id}/decide", response_model=CertificationItemOut)
def decide_certification_item(
    cert_id: uuid.UUID,
    item_id: uuid.UUID,
    body: CertificationDecision,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    cert = session.get(AccessCertification, cert_id)
    if cert is None or cert.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certification not found")
    try:
        item = identity_service.decide_certification_item(
            session, principal.organization_id, item_id, body.decision, principal.user_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _cert_item_out(item)
    session.commit()
    return out


# --- Temporary access grants -------------------------------------------------


def _grant_out(g: TemporaryAccessGrant) -> TempGrantOut:
    return TempGrantOut(
        id=g.id,
        user_id=g.user_id,
        role_id=g.role_id,
        granted_by_id=g.granted_by_id,
        reason=g.reason,
        expires_at=g.expires_at,
        revoked_at=g.revoked_at,
        status=g.status,
        created_at=g.created_at,
    )


@router.get("/temp-grants", response_model=list[TempGrantOut])
def list_temp_grants(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:read"))
):
    rows = session.execute(
        select(TemporaryAccessGrant)
        .where(TemporaryAccessGrant.organization_id == principal.organization_id)
        .order_by(TemporaryAccessGrant.created_at.desc())
    ).scalars()
    return [_grant_out(g) for g in rows]


@router.post("/temp-grants", response_model=TempGrantOut, status_code=status.HTTP_201_CREATED)
def create_temp_grant(
    body: TempGrantCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    if body.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be in the future")
    try:
        grant = identity_service.create_temp_grant(
            session,
            principal.organization_id,
            body.user_id,
            body.role_id,
            principal.user_id,
            body.reason,
            body.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _grant_out(grant)
    session.commit()
    return out


@router.post("/temp-grants/{grant_id}/revoke", response_model=TempGrantOut)
def revoke_temp_grant(
    grant_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    try:
        grant = identity_service.revoke_temp_grant(session, principal.organization_id, grant_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _grant_out(grant)
    session.commit()
    return out


# --- Service accounts --------------------------------------------------------


def _service_account_out(row: ServiceAccount, raw: str | None = None) -> ServiceAccountOut:
    return ServiceAccountOut(
        id=row.id,
        name=row.name,
        description=row.description,
        scopes=list(row.scopes or []),
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
        created_at=row.created_at,
        credential=raw,
    )


@router.get("/service-accounts", response_model=list[ServiceAccountOut])
def list_service_accounts(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:read"))
):
    rows = session.execute(
        select(ServiceAccount)
        .where(ServiceAccount.organization_id == principal.organization_id)
        .order_by(ServiceAccount.created_at)
    ).scalars()
    return [_service_account_out(r) for r in rows]


@router.post("/service-accounts", response_model=ServiceAccountOut, status_code=status.HTTP_201_CREATED)
def create_service_account(
    body: ServiceAccountCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    row, raw = identity_service.create_service_account(
        session,
        principal.organization_id,
        body.name,
        body.description,
        body.scopes,
        body.expires_at,
        principal.user_id,
    )
    out = _service_account_out(row, raw=raw)  # raw secret shown ONLY here
    session.commit()
    return out


@router.post("/service-accounts/{account_id}/rotate", response_model=ServiceAccountOut)
def rotate_service_account(
    account_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    try:
        row, raw = identity_service.rotate_service_account(
            session, principal.organization_id, account_id, principal.user_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    out = _service_account_out(row, raw=raw)
    session.commit()
    return out


@router.post("/service-accounts/{account_id}/revoke", response_model=ServiceAccountOut)
def revoke_service_account(
    account_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    try:
        identity_service.revoke_service_account(session, principal.organization_id, account_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    row = session.get(ServiceAccount, account_id)
    out = _service_account_out(row)
    session.commit()
    return out


# --- API credentials ---------------------------------------------------------


def _api_credential_out(row: ApiCredential, raw: str | None = None) -> ApiCredentialOut:
    return ApiCredentialOut(
        id=row.id,
        user_id=row.user_id,
        name=row.name,
        scopes=list(row.scopes or []),
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
        created_at=row.created_at,
        credential=raw,
    )


@router.get("/api-credentials", response_model=list[ApiCredentialOut])
def list_api_credentials(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("identity:read"))
):
    rows = session.execute(
        select(ApiCredential)
        .where(ApiCredential.organization_id == principal.organization_id)
        .order_by(ApiCredential.created_at)
    ).scalars()
    return [_api_credential_out(r) for r in rows]


@router.post("/api-credentials", response_model=ApiCredentialOut, status_code=status.HTTP_201_CREATED)
def create_api_credential(
    body: ApiCredentialCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    user = session.get(User, body.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
    membership = session.execute(
        select(Membership).where(
            Membership.organization_id == principal.organization_id, Membership.user_id == body.user_id
        )
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is not a member of this organization")
    row, raw = identity_service.create_api_credential(
        session, principal.organization_id, body.user_id, body.name, body.scopes, body.expires_at
    )
    out = _api_credential_out(row, raw=raw)  # raw credential shown ONLY here
    session.commit()
    return out


@router.post("/api-credentials/verify")
def verify_api_credential(
    body: ApiCredentialVerify,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:read")),
):
    """Prove a credential: real hash match + unexpired + unrevoked.

    This endpoint only proves the credential; request-level API-key auth
    is Phase 4.
    """
    result = identity_service.verify_api_credential(session, principal.organization_id, body.credential)
    if result is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credential")
    session.commit()
    return {"valid": True, **result}


@router.post("/api-credentials/{credential_id}/rotate", response_model=ApiCredentialOut)
def rotate_api_credential(
    credential_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    try:
        row, raw = identity_service.rotate_api_credential(session, principal.organization_id, credential_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    out = _api_credential_out(row, raw=raw)
    session.commit()
    return out


@router.post("/api-credentials/{credential_id}/revoke", response_model=ApiCredentialOut)
def revoke_api_credential(
    credential_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("identity:manage")),
):
    try:
        identity_service.revoke_api_credential(session, principal.organization_id, credential_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    row = session.get(ApiCredential, credential_id)
    out = _api_credential_out(row)
    session.commit()
    return out
