"""Authentication routes: login, MFA, refresh, logout, recovery, invitations.

Rate limiting: login / password-reset / invitation endpoints are limited
(slowapi, Redis-backed when available) to slow credential-stuffing.
"""

import uuid

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import as_uuid
from app.deps import Unauthorized, get_db, get_user_principal
from app.models.platform import User
from app.rate_limit import limiter
from app.schemas import (
    AcceptInvitationRequest,
    InvitationLookupOut,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MfaChallengeRequest,
    MfaEnrollResponse,
    MfaVerifyRequest,
    OrganizationRegisterOut,
    OrganizationRegisterRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    SelectOrganizationRequest,
    SwitchOrganizationRequest,
    TokenResponse,
)
from app.security import decode_local_token, hash_token
from app.services import auth_service, registration_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _user_agent(request: Request) -> str | None:
    return request.headers.get("User-Agent")


def _to_login_response(result: auth_service.LoginResult) -> LoginResponse:
    return LoginResponse(
        status=result.status,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        mfa_token=result.mfa_token,
        org_select_token=result.org_select_token,
        user_id=result.user_id,
        organizations=result.organizations,
    )


@router.post("/login", response_model=LoginResponse)
@limiter.limit("10/minute")
def login(request: Request, body: LoginRequest, session: Session = Depends(get_db)):
    try:
        result = auth_service.login(session, body.email, body.password, _client_ip(request), _user_agent(request))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    session.commit()
    return _to_login_response(result)


@router.post("/mfa/challenge", response_model=LoginResponse)
@limiter.limit("10/minute")
def mfa_challenge(request: Request, body: MfaChallengeRequest, session: Session = Depends(get_db)):
    try:
        result = auth_service.complete_mfa(
            session, body.mfa_token, body.code, _client_ip(request), _user_agent(request)
        )
    except (ValueError, jwt.InvalidTokenError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    session.commit()
    return _to_login_response(result)


@router.post("/select-organization", response_model=TokenResponse)
def select_organization(request: Request, body: SelectOrganizationRequest, session: Session = Depends(get_db)):
    """Finish a multi-org login: the org_select_token proves credentials."""
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise Unauthorized("Missing org_select_token")
    try:
        claims = decode_local_token(token, expected_type="org_select")
    except jwt.InvalidTokenError as exc:
        raise Unauthorized(str(exc))
    try:
        result = auth_service.select_organization(
            session, uuid.UUID(claims.sub), body.organization_id, _client_ip(request), _user_agent(request)
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    session.commit()
    assert result.access_token and result.refresh_token
    return TokenResponse(access_token=result.access_token, refresh_token=result.refresh_token)


@router.post("/switch-organization", response_model=TokenResponse)
def switch_organization(request: Request, body: SwitchOrganizationRequest, session: Session = Depends(get_db)):
    """Switch the active organization using a valid refresh token."""
    try:
        found = auth_service._lookup_session_by_token(session, body.refresh_token)
        if found is None:
            raise ValueError("Invalid or expired refresh token")
        result = auth_service.select_organization(
            session, as_uuid(found["user_id"]), body.organization_id, _client_ip(request), _user_agent(request)
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    session.commit()
    assert result.access_token and result.refresh_token
    return TokenResponse(access_token=result.access_token, refresh_token=result.refresh_token)


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, body: RefreshRequest, session: Session = Depends(get_db)):
    try:
        result = auth_service.refresh(session, body.refresh_token, _client_ip(request), _user_agent(request))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    session.commit()
    assert result.access_token and result.refresh_token
    return TokenResponse(access_token=result.access_token, refresh_token=result.refresh_token)


@router.post("/logout")
def logout(body: LogoutRequest, session: Session = Depends(get_db), principal=Depends(get_user_principal)):
    auth_service.logout(session, body.refresh_token, principal.user_id, principal.organization_id)
    session.commit()
    return {"status": "ok"}


@router.post("/password-reset/request")
@limiter.limit("5/minute")
def request_password_reset(request: Request, body: PasswordResetRequest, session: Session = Depends(get_db)):
    # Always returns success: no user enumeration.
    auth_service.request_password_reset(session, body.email)
    session.commit()
    return {"status": "ok", "detail": "If an account exists, a reset link was sent."}


@router.post("/password-reset/confirm")
def confirm_password_reset(body: PasswordResetConfirm, session: Session = Depends(get_db)):
    try:
        auth_service.reset_password(session, body.token, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return {"status": "ok"}


@router.post("/register", response_model=OrganizationRegisterOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register_organization(request: Request, body: OrganizationRegisterRequest, session: Session = Depends(get_db)):
    """Public organization registration. Creates the org, its first
    administrator, the owner membership, the Organization Administrator
    role grant, default settings + departments, and the onboarding
    record, then signs the admin in. Registration NEVER creates a
    platform administrator. The admin email must be new: an existing
    account signs in and creates another org via the authenticated
    endpoint instead."""
    from app.routers.organizations import _org_out

    try:
        org, admin = registration_service.register_organization(
            session,
            org_name=body.org_name,
            org_email=body.org_email,
            website=body.website,
            industry=body.industry,
            org_size=body.org_size,
            admin_name=body.admin_name,
            admin_email=body.admin_email,
            password=body.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    session.flush()
    result = auth_service.login(
        session, body.admin_email, body.password, _client_ip(request), _user_agent(request)
    )
    if result.status != "ok" or result.access_token is None or result.refresh_token is None:
        # A freshly registered admin has one membership and no MFA, so
        # login must return tokens; anything else is a server error.
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration completed but sign-in failed",
        )
    session.commit()
    login_response = _to_login_response(result)
    return OrganizationRegisterOut(
        organization=_org_out(org),
        user_id=admin.id,
        access_token=login_response.access_token,
        refresh_token=login_response.refresh_token,
    )


@router.get("/invitations/{token}", response_model=InvitationLookupOut)
def lookup_invitation(token: str, session: Session = Depends(get_db)):
    """Public invitation lookup for the accept page: org, pre-filled
    name/email (locked on the page), and assigned roles. The token hash
    is resolved through the SECURITY DEFINER function; no account data
    beyond the invitation itself is exposed."""
    from sqlalchemy import text

    row = (
        session.execute(
            text("SELECT * FROM auth_get_invitation_by_token(:h)"), {"h": hash_token(token)}
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")
    return InvitationLookupOut(
        organization_name=row["organization_name"],
        organization_slug=row["organization_slug"],
        email=row["email"],
        full_name=row["full_name"] or "",
        department=row["department"] or "",
        team=row["team"] or "",
        roles=list(row["roles"] or []),
        status=row["status"],
        expires_at=row["expires_at"],
    )


@router.post("/invitations/accept")
def accept_invitation(body: AcceptInvitationRequest, session: Session = Depends(get_db)):
    try:
        user, org = auth_service.accept_invitation(session, body.token, body.full_name, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return {"status": "ok", "user_id": str(user.id), "organization_id": str(org.id), "organization_slug": org.slug}


# --- MFA management (authenticated) ---------------------------------------


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
def enroll_mfa(session: Session = Depends(get_db), principal=Depends(get_user_principal)):
    user = session.get(User, principal.user_id)
    if user is None:
        raise Unauthorized("User not found")
    secret, uri = auth_service.enroll_mfa(session, user)
    session.commit()
    return MfaEnrollResponse(secret=secret, otpauth_uri=uri)


@router.post("/mfa/verify-enrollment")
def verify_mfa_enrollment(
    body: MfaVerifyRequest, session: Session = Depends(get_db), principal=Depends(get_user_principal)
):
    user = session.get(User, principal.user_id)
    if user is None:
        raise Unauthorized("User not found")
    if not auth_service.verify_mfa_enrollment(session, user, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")
    session.commit()
    return {"status": "ok", "mfa_enabled": True}


@router.post("/mfa/disable")
def disable_mfa(session: Session = Depends(get_db), principal=Depends(get_user_principal)):
    user = session.get(User, principal.user_id)
    if user is None:
        raise Unauthorized("User not found")
    auth_service.disable_mfa(session, user)
    session.commit()
    return {"status": "ok", "mfa_enabled": False}


@router.get("/me")
def me(principal=Depends(get_user_principal)):
    return {
        "user_id": str(principal.user_id),
        "email": principal.email,
        "organization_id": str(principal.organization_id),
        "organization_slug": principal.organization_slug,
        "is_org_owner": principal.is_org_owner,
        "permissions": sorted(principal.permissions),
    }
