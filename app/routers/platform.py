"""Platform administration routes: auth, admin directory, roles, tenants,
support grants, and platform audit — the SECOND administrative domain.

All endpoints live under ``/api/v1/platform`` and authenticate with a
platform access token (type ``platform_access``). An org access token
can never authenticate here, and a platform token can never
authenticate an org endpoint — the two domains share no identity.

Permission + MFA rule (enforced by ``require_platform_permission``):
every ``*:manage`` permission requires MFA (``mfa=true`` on the access
token); every ``*:read`` works with ``mfa=false``.

Conventions (mirroring the org routers): the response is built BEFORE
``session.commit()`` (the RLS context is SET LOCAL and dies at commit,
and server onupdate columns expire on flush), audit writes happen
before commit, and 404 never reveals whether a cross-domain resource
exists.
"""

import uuid

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import (
    PlatformPrincipal,
    Unauthorized,
    get_db,
    get_platform_principal,
    require_platform_permission,
)
from app.models.email import EmailDelivery
from app.models.platform_admin import PlatformUser
from app.models.registration import DevEmailOutbox
from app.permissions import PLATFORM_PERMISSIONS
from app.rate_limit import limiter
from app.schemas import (
    AssignPlatformRoleRequest,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MfaChallengeRequest,
    MfaEnrollResponse,
    MfaVerifyRequest,
    OutboxOut,
    PermissionOut,
    PlatformAuditLogOut,
    PlatformInvitationAcceptRequest,
    PlatformInvitationOut,
    PlatformInviteRequest,
    PlatformUserCreate,
    PlatformUserOut,
    RefreshRequest,
    RoleCreate,
    RoleOut,
    RolePermissionsUpdate,
    RoleUpdate,
    SupportGrantCreate,
    SupportGrantOut,
    TenantOut,
    TenantUserOut,
    TokenResponse,
)
from app.services import email as email_service
from app.services import platform_service

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _user_agent(request: Request) -> str | None:
    return request.headers.get("User-Agent")


def _to_login_response(result: platform_service.PlatformLoginResult) -> LoginResponse:
    return LoginResponse(
        status=result.status,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        mfa_token=result.mfa_token,
        user_id=result.platform_user_id,
    )


def _platform_user_out(session: Session, user: PlatformUser) -> PlatformUserOut:
    return PlatformUserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        source=user.source,
        review_status=user.review_status,
        roles=platform_service.platform_user_role_names(session, user.id),
        created_at=user.created_at,
    )


def _role_out(session: Session, role) -> RoleOut:
    return RoleOut(
        id=role.id,
        name=role.name,
        description=role.description,
        access_level=role.access_level,
        is_system=role.is_system,
        permissions=platform_service.platform_role_permission_codes(session, role.id),
    )


def _grant_out(grant) -> SupportGrantOut:
    return SupportGrantOut(
        id=grant.id,
        platform_user_id=grant.platform_user_id,
        organization_id=grant.organization_id,
        purpose=grant.purpose,
        status=grant.status,
        granted_by_id=grant.granted_by_id,
        approved_by_id=grant.approved_by_id,
        expires_at=grant.expires_at,
        created_at=grant.created_at,
    )


def _tenant_out(row: dict) -> TenantOut:
    return TenantOut(
        id=row["id"],
        name=row["name"],
        slug=row["slug"],
        is_active=row["is_active"],
        is_dev_fixture=row["is_dev_fixture"],
        created_at=row["created_at"],
    )


def _get_platform_user_or_404(session: Session, user_id: uuid.UUID) -> PlatformUser:
    user = platform_service.get_platform_user(session, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform user not found")
    return user


def _get_platform_role_or_404(session: Session, role_id: uuid.UUID):
    role = platform_service.get_platform_role(session, role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role


# --- Platform auth ----------------------------------------------------------


@router.post("/auth/login", response_model=LoginResponse)
@limiter.limit("10/minute")
def platform_login(request: Request, body: LoginRequest, session: Session = Depends(get_db)):
    try:
        result = platform_service.login_platform(
            session, body.email, body.password, _client_ip(request), _user_agent(request)
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    session.commit()
    return _to_login_response(result)


@router.post("/auth/mfa-challenge", response_model=LoginResponse)
@limiter.limit("10/minute")
def platform_mfa_challenge(request: Request, body: MfaChallengeRequest, session: Session = Depends(get_db)):
    try:
        result = platform_service.complete_platform_mfa(
            session, body.mfa_token, body.code, _client_ip(request), _user_agent(request)
        )
    except (ValueError, jwt.InvalidTokenError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    session.commit()
    return _to_login_response(result)


@router.post("/auth/refresh", response_model=TokenResponse)
def platform_refresh(request: Request, body: RefreshRequest, session: Session = Depends(get_db)):
    try:
        result = platform_service.refresh_platform(
            session, body.refresh_token, _client_ip(request), _user_agent(request)
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    session.commit()
    assert result.access_token and result.refresh_token
    return TokenResponse(access_token=result.access_token, refresh_token=result.refresh_token)


@router.post("/auth/logout")
def platform_logout(
    body: LogoutRequest,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(get_platform_principal),
):
    platform_service.logout_platform(session, body.refresh_token, principal.platform_user_id)
    session.commit()
    return {"status": "ok"}


@router.post("/auth/mfa-enroll", response_model=MfaEnrollResponse)
def platform_enroll_mfa(
    session: Session = Depends(get_db), principal: PlatformPrincipal = Depends(get_platform_principal)
):
    user = session.get(PlatformUser, principal.platform_user_id)
    if user is None:
        raise Unauthorized("Platform user not found")
    secret, uri = platform_service.enroll_platform_mfa(session, user)
    session.commit()
    return MfaEnrollResponse(secret=secret, otpauth_uri=uri)


@router.post("/auth/mfa-verify")
def platform_verify_mfa_enrollment(
    body: MfaVerifyRequest,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(get_platform_principal),
):
    user = session.get(PlatformUser, principal.platform_user_id)
    if user is None:
        raise Unauthorized("Platform user not found")
    if not platform_service.verify_platform_mfa_enrollment(session, user, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")
    session.commit()
    return {"status": "ok", "mfa_enabled": True}


@router.get("/auth/me")
def platform_me(principal: PlatformPrincipal = Depends(get_platform_principal)):
    return {
        "platform_user_id": str(principal.platform_user_id),
        "email": principal.email,
        "permissions": sorted(principal.permissions),
        "mfa": principal.mfa,
    }


@router.post("/auth/invitations/accept")
def accept_platform_invitation(
    body: PlatformInvitationAcceptRequest, session: Session = Depends(get_db)
):
    """Public platform-invitation acceptance: creates the platform
    administrator with the role fixed at invite time. Single-use,
    email-bound, 48h expiry. This never touches any organization."""
    try:
        user = platform_service.accept_platform_invitation(session, body.token, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return {"status": "ok", "platform_user_id": str(user.id), "email": user.email}


# --- Permission catalog ------------------------------------------------------


@router.get("/permissions", response_model=list[PermissionOut])
def platform_permission_catalog(
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:roles:read")),
):
    return [
        PermissionOut(code=code, module=module, description=description)
        for code, module, description in PLATFORM_PERMISSIONS
    ]


# --- Platform admin directory -------------------------------------------------


@router.get("/admins", response_model=list[PlatformUserOut])
def list_platform_admins(
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:read")),
):
    return [_platform_user_out(session, u) for u in platform_service.list_platform_users(session)]


@router.post("/admins", response_model=PlatformUserOut, status_code=status.HTTP_201_CREATED)
def create_platform_admin(
    body: PlatformUserCreate,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    try:
        user = platform_service.create_platform_user(session, principal, body.email, body.full_name, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _platform_user_out(session, user)
    session.commit()
    return out


# --- Platform invitations -----------------------------------------------------
# Invite internal NULL personnel into platform administration. This is a
# SEPARATE workflow from org invitations: different table, different
# roles, different authorization — an org invitation can never create a
# platform admin, and a platform invitation never touches an org.


def _platform_invitation_out(
    invitation, role_name: str = "", accept_url: str | None = None, delivery: dict | None = None
) -> PlatformInvitationOut:
    return PlatformInvitationOut(
        id=invitation.id,
        email=invitation.email,
        full_name=invitation.full_name,
        role_id=invitation.role_id,
        role_name=role_name,
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        accept_url=accept_url,
        delivery=delivery,
    )


def _delivery_row_dict(session: Session, result) -> dict | None:
    """Delivery dict for a just-completed send, from its recorded row."""
    if result is None or result.delivery_id is None:
        return None
    row = session.get(EmailDelivery, uuid.UUID(result.delivery_id))
    return email_service.delivery_to_dict(row)


def _accept_url_if_dev(accept_url: str | None) -> str | None:
    """The accept link is returned only in dev mode (no provider
    configured). When a provider is configured the email is the delivery
    channel and no link is exposed."""
    return accept_url if not email_service.email_delivery_configured() else None


@router.post("/admin-invitations", response_model=PlatformInvitationOut, status_code=status.HTTP_201_CREATED)
def invite_platform_admin(
    body: PlatformInviteRequest,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    role = _get_platform_role_or_404(session, body.role_id)
    try:
        invitation, _token, accept_url, delivery = platform_service.invite_platform_admin(
            session, principal, body.email, body.full_name, body.role_id
        )
    except email_service.EmailConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _platform_invitation_out(
        invitation,
        role_name=role.name,
        accept_url=_accept_url_if_dev(accept_url),
        delivery=_delivery_row_dict(session, delivery),
    )
    session.commit()
    return out


@router.get("/admin-invitations", response_model=list[PlatformInvitationOut])
def list_platform_invitations(
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    rows = platform_service.list_platform_invitations(session)
    out = []
    for row in rows:
        role = platform_service.get_platform_role(session, row.role_id)
        out.append(
            _platform_invitation_out(
                row,
                role_name=role.name if role else "",
                delivery=email_service.delivery_to_dict(
                    email_service.latest_delivery_for_invitation(session, platform_invitation_id=row.id)
                ),
            )
        )
    return out


@router.post("/admin-invitations/{invitation_id}/resend", response_model=PlatformInvitationOut)
def resend_platform_invitation(
    invitation_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    try:
        invitation, _token, accept_url, delivery = platform_service.resend_platform_invitation(
            session, principal, invitation_id
        )
    except email_service.EmailConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    role = platform_service.get_platform_role(session, invitation.role_id)
    out = _platform_invitation_out(
        invitation,
        role_name=role.name if role else "",
        accept_url=_accept_url_if_dev(accept_url),
        delivery=_delivery_row_dict(session, delivery),
    )
    session.commit()
    return out


@router.post("/admin-invitations/{invitation_id}/revoke")
def revoke_platform_invitation(
    invitation_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    try:
        platform_service.revoke_platform_invitation(session, principal, invitation_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    session.commit()
    return {"status": "ok"}


@router.get("/outbox", response_model=list[OutboxOut])
def list_platform_outbox(
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    """Read the platform dev outbox: every platform invitation email the
    backend would have sent (SMTP unconfigured in local dev)."""
    rows = session.execute(
        select(DevEmailOutbox)
        .where(DevEmailOutbox.scope == "platform")
        .order_by(DevEmailOutbox.created_at.desc())
    ).scalars()
    return [
        OutboxOut(
            id=r.id,
            organization_id=r.organization_id,
            scope=r.scope,
            to_email=r.to_email,
            subject=r.subject,
            body=r.body,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/admins/{user_id}", response_model=PlatformUserOut)
def get_platform_admin(
    user_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:read")),
):
    user = _get_platform_user_or_404(session, user_id)
    return _platform_user_out(session, user)


@router.patch("/admins/{user_id}/suspend", response_model=PlatformUserOut)
def suspend_platform_admin(
    user_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    user = _get_platform_user_or_404(session, user_id)
    try:
        platform_service.suspend_platform_user(session, principal, user)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _platform_user_out(session, user)
    session.commit()
    return out


@router.post("/admins/{user_id}/reactivate", response_model=PlatformUserOut)
def reactivate_platform_admin(
    user_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    user = _get_platform_user_or_404(session, user_id)
    platform_service.reactivate_platform_user(session, principal, user)
    session.flush()
    out = _platform_user_out(session, user)
    session.commit()
    return out


@router.post("/admins/{user_id}/roles", status_code=status.HTTP_201_CREATED)
def assign_platform_role(
    user_id: uuid.UUID,
    body: AssignPlatformRoleRequest,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    _get_platform_user_or_404(session, user_id)
    role = _get_platform_role_or_404(session, body.role_id)
    try:
        result = platform_service.assign_platform_role(session, principal, user_id, role)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return result


@router.delete("/admins/{user_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_platform_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:users:manage")),
):
    _get_platform_user_or_404(session, user_id)
    role = _get_platform_role_or_404(session, role_id)
    try:
        platform_service.revoke_platform_role(session, principal, user_id, role)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return None


# --- Platform roles ------------------------------------------------------------


@router.get("/roles", response_model=list[RoleOut])
def list_platform_roles(
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:roles:read")),
):
    return [_role_out(session, r) for r in platform_service.list_platform_roles(session)]


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_platform_role(
    body: RoleCreate,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:roles:manage")),
):
    try:
        role = platform_service.create_platform_role(
            session, principal, body.name, body.description, body.access_level, body.permission_codes
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _role_out(session, role)
    session.commit()
    return out


@router.get("/roles/{role_id}", response_model=RoleOut)
def get_platform_role(
    role_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:roles:read")),
):
    role = _get_platform_role_or_404(session, role_id)
    return _role_out(session, role)


@router.patch("/roles/{role_id}", response_model=RoleOut)
def update_platform_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:roles:manage")),
):
    role = _get_platform_role_or_404(session, role_id)
    try:
        role = platform_service.update_platform_role(session, principal, role, body.description, body.access_level)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _role_out(session, role)
    session.commit()
    return out


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_platform_role(
    role_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:roles:manage")),
):
    role = _get_platform_role_or_404(session, role_id)
    try:
        platform_service.delete_platform_role(session, principal, role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return None


@router.put("/roles/{role_id}/permissions", response_model=RoleOut)
def configure_platform_role_permissions(
    role_id: uuid.UUID,
    body: RolePermissionsUpdate,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:roles:manage")),
):
    role = _get_platform_role_or_404(session, role_id)
    try:
        role = platform_service.configure_platform_role_permissions(session, principal, role, body.permission_codes)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _role_out(session, role)
    session.commit()
    return out


# --- Tenants -------------------------------------------------------------------


@router.get("/tenants", response_model=list[TenantOut])
def list_tenants(
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:tenants:read")),
):
    return [_tenant_out(row) for row in platform_service.list_tenants(session)]


@router.get("/tenants/{org_id}", response_model=TenantOut)
def get_tenant(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:tenants:read")),
):
    row = platform_service.get_tenant(session, org_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    platform_service.write_platform_audit(
        session,
        actor_id=principal.platform_user_id,
        action=audit_mod.PLATFORM_TENANT_READ,
        resource_type="organization",
        resource_id=str(org_id),
        organization_id=org_id,
        outcome="success",
    )
    out = _tenant_out(row)
    session.commit()
    return out


@router.get("/tenants/{org_id}/users", response_model=list[TenantUserOut])
def list_tenant_users(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:support:read")),
):
    # The SECURITY DEFINER function enforces the support grant in the
    # database: with no active, unexpired grant it returns no rows —
    # deliberately indistinguishable from an organization with no users.
    rows = platform_service.list_tenant_users(session, principal.platform_user_id, org_id)
    # Every grant-gated tenant read is audited, whether or not it
    # returned rows.
    platform_service.write_platform_audit(
        session,
        actor_id=principal.platform_user_id,
        action=audit_mod.PLATFORM_TENANT_USERS_READ,
        resource_type="tenant_users",
        resource_id=str(org_id),
        organization_id=org_id,
        outcome="success",
        metadata={"returned": len(rows)},
    )
    out = [
        TenantUserOut(id=r["id"], email=r["email"], full_name=r["full_name"], is_active=r["is_active"]) for r in rows
    ]
    session.commit()
    return out


# --- Support grants --------------------------------------------------------------


@router.post("/support-grants", response_model=SupportGrantOut, status_code=status.HTTP_201_CREATED)
def request_support_grant(
    body: SupportGrantCreate,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:support:manage")),
):
    if platform_service.get_tenant(session, body.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    try:
        grant = platform_service.request_support_grant(
            session, principal, body.organization_id, body.purpose, body.expires_at
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _grant_out(grant)
    session.commit()
    return out


@router.get("/support-grants", response_model=list[SupportGrantOut])
def list_support_grants(
    status_filter: str | None = Query(default=None, alias="status"),
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:support:read")),
):
    return [_grant_out(g) for g in platform_service.list_support_grants(session, status_filter)]


@router.post("/support-grants/{grant_id}/approve", response_model=SupportGrantOut)
def approve_support_grant(
    grant_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:support:manage")),
):
    grant = platform_service.get_support_grant(session, grant_id)
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Support grant not found")
    try:
        grant = platform_service.approve_support_grant(session, principal, grant_id)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _grant_out(grant)
    session.commit()
    return out


@router.post("/support-grants/{grant_id}/revoke", response_model=SupportGrantOut)
def revoke_support_grant(
    grant_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:support:manage")),
):
    grant = platform_service.get_support_grant(session, grant_id)
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Support grant not found")
    try:
        grant = platform_service.revoke_support_grant(session, principal, grant_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _grant_out(grant)
    session.commit()
    return out


# --- Platform audit (read-only) ---------------------------------------------------


@router.get("/audit", response_model=list[PlatformAuditLogOut])
def list_platform_audit(
    action: str | None = Query(default=None),
    actor_id: uuid.UUID | None = Query(default=None),
    organization_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_db),
    principal: PlatformPrincipal = Depends(require_platform_permission("platform:audit:read")),
):
    rows = platform_service.list_platform_audit(session, action, actor_id, organization_id, limit, offset)
    return [
        PlatformAuditLogOut(
            id=r.id,
            actor_id=r.actor_id,
            organization_id=r.organization_id,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            outcome=r.outcome,
            metadata=r.meta,
            created_at=r.created_at,
        )
        for r in rows
    ]
