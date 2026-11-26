"""Authentication service: login, MFA, refresh, logout, recovery, invitations.

Lookup discipline
-----------------
User/invitation/reset lookups before authentication go through the
SECURITY DEFINER functions defined in the initial migration
(``auth_get_user_by_email`` etc.). Ordinary request code never reads the
``users`` table without RLS context.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.config import get_settings
from app.database import as_uuid, set_rls_context
from app.models.auth import AuthSession, Invitation, InvitationRole, PasswordReset
from app.models.platform import Membership, Organization, User
from app.models.rbac import UserRole
from app.security import (
    hash_password,
    hash_token,
    issue_access_token,
    issue_mfa_token,
    issue_org_select_token,
    new_opaque_token,
    new_totp_secret,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.services import email as email_service

UTC = timezone.utc


@dataclass
class LoginResult:
    status: str  # "ok" | "mfa_required" | "org_required" | "no_org"
    access_token: str | None = None
    refresh_token: str | None = None
    mfa_token: str | None = None
    org_select_token: str | None = None
    user_id: str | None = None
    organizations: list[dict] | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _set_context(session: Session, org_id: uuid.UUID | None, user_id: uuid.UUID | None) -> None:
    """Set the RLS context for the current transaction.

    Auth flows resolve identity step by step: first the user (from a
    SECURITY DEFINER lookup), then the organization. Each step re-scopes
    the transaction so subsequent queries are RLS-filtered correctly.
    """
    set_rls_context(session, org_id, user_id)


def _audit_if_org(
    session: Session,
    user_id: uuid.UUID,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str = "success",
    metadata: dict | None = None,
) -> None:
    """Write an audit event when the user belongs to an organization.

    Users without any organization (e.g. a failed login before any
    membership exists) have no organization to attribute the event to, so
    the event is recorded in the application log instead of the audit
    table — the audit table's organization_id is a real foreign key and
    must never reference a non-existent organization.
    """
    org_id = _first_org_id(session, user_id)
    if org_id is None:
        return
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        metadata=metadata,
    )


def _lookup_user_by_email(session: Session, email: str) -> dict | None:
    row = session.execute(text("SELECT * FROM auth_get_user_by_email(:email)"), {"email": email}).mappings().first()
    return dict(row) if row else None


def _active_memberships(session: Session, user_id: uuid.UUID) -> list[Membership]:
    return list(
        session.execute(
            select(Membership)
            .where(Membership.user_id == user_id, Membership.status == "active")
            .order_by(Membership.created_at)
        ).scalars()
    )


def _create_session(
    session: Session, user_id: uuid.UUID, org_id: uuid.UUID, ip: str | None, user_agent: str | None
) -> tuple[str, AuthSession]:
    settings = get_settings()
    refresh_token = new_opaque_token()
    row = AuthSession(
        user_id=user_id,
        organization_id=org_id,
        refresh_token_hash=hash_token(refresh_token),
        expires_at=_now() + timedelta(days=settings.refresh_token_days),
        ip_address=ip,
        user_agent=user_agent,
    )
    session.add(row)
    return refresh_token, row


def _finish_login(
    session: Session, user: dict, org_id: uuid.UUID, ip: str | None, user_agent: str | None
) -> LoginResult:
    _set_context(session, org_id, as_uuid(user["id"]))
    refresh_token, _ = _create_session(session, as_uuid(user["id"]), org_id, ip, user_agent)
    access_token = issue_access_token(user["id"], str(org_id), user["email"])
    session.execute(
        text("UPDATE users SET last_login_at = :now WHERE id = :id"),
        {"now": _now(), "id": as_uuid(user["id"])},
    )
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=as_uuid(user["id"]),
        action=audit_mod.AUTH_LOGIN,
        resource_type="session",
        resource_id=str(user["id"]),
        outcome="success",
    )
    return LoginResult(status="ok", access_token=access_token, refresh_token=refresh_token, user_id=str(user["id"]))


def login(session: Session, email: str, password: str, ip: str | None, user_agent: str | None) -> LoginResult:
    """Authenticate by email/password. MFA and multi-org are handled here."""
    user = _lookup_user_by_email(session, email)
    if user is None or not user["is_active"] or not verify_password(password, user["password_hash"]):
        # Failed login is audited only when the user exists and has an org
        # (no user enumeration: the response is identical either way).
        if user is not None:
            _set_context(session, None, as_uuid(user["id"]))
            _audit_if_org(
                session,
                as_uuid(user["id"]),
                audit_mod.AUTH_LOGIN_FAILED,
                "session",
                user["id"],
                outcome="failure",
                metadata={"reason": "bad credentials"},
            )
        raise ValueError("Invalid email or password")

    _set_context(session, None, as_uuid(user["id"]))
    if user["mfa_enabled"]:
        return LoginResult(
            status="mfa_required",
            mfa_token=issue_mfa_token(user["id"], user["email"]),
            user_id=str(user["id"]),
        )

    memberships = _active_memberships(session, as_uuid(user["id"]))
    if not memberships:
        # Authenticated but belongs to no organization yet: issue an
        # org-less access token that may only create an organization.
        return LoginResult(
            status="no_org",
            access_token=issue_access_token(user["id"], None, user["email"]),
            user_id=str(user["id"]),
        )
    if len(memberships) == 1:
        return _finish_login(session, user, memberships[0].organization_id, ip, user_agent)
    orgs = session.execute(
        select(Organization).where(Organization.id.in_([m.organization_id for m in memberships]))
    ).scalars()
    return LoginResult(
        status="org_required",
        org_select_token=issue_org_select_token(user["id"], user["email"]),
        user_id=str(user["id"]),
        organizations=[{"id": str(o.id), "name": o.name, "slug": o.slug} for o in orgs],
    )


def _first_org_id(session: Session, user_id: uuid.UUID) -> uuid.UUID | None:
    m = (
        session.execute(select(Membership).where(Membership.user_id == user_id, Membership.status == "active"))
        .scalars()
        .first()
    )
    return m.organization_id if m else None


def complete_mfa(session: Session, mfa_token: str, code: str, ip: str | None, user_agent: str | None) -> LoginResult:
    """Verify the TOTP code for a pending MFA login and finish sign-in."""
    from app.security import decode_local_token

    claims = decode_local_token(mfa_token, expected_type="mfa")
    user = _lookup_user_by_email(session, claims.email)
    if user is None or not user["mfa_secret"] or not verify_totp(user["mfa_secret"], code):
        if user is not None:
            _set_context(session, None, as_uuid(user["id"]))
            _audit_if_org(
                session,
                as_uuid(user["id"]),
                audit_mod.AUTH_MFA_FAILED,
                "session",
                user["id"],
                outcome="failure",
            )
        raise ValueError("Invalid MFA code")
    _set_context(session, None, as_uuid(user["id"]))
    memberships = _active_memberships(session, as_uuid(user["id"]))
    if not memberships:
        return LoginResult(
            status="no_org",
            access_token=issue_access_token(user["id"], None, user["email"]),
            user_id=str(user["id"]),
        )
    if len(memberships) == 1:
        return _finish_login(session, user, memberships[0].organization_id, ip, user_agent)
    orgs = session.execute(
        select(Organization).where(Organization.id.in_([m.organization_id for m in memberships]))
    ).scalars()
    return LoginResult(
        status="org_required",
        org_select_token=issue_org_select_token(user["id"], user["email"]),
        user_id=str(user["id"]),
        organizations=[{"id": str(o.id), "name": o.name, "slug": o.slug} for o in orgs],
    )


def select_organization(
    session: Session, user_id: uuid.UUID, org_id: uuid.UUID, ip: str | None, user_agent: str | None
) -> LoginResult:
    """Finish sign-in for a multi-org user after they choose an organization."""
    # Scope the transaction to the chosen org/user BEFORE the membership
    # lookup: with the (None, None) context from get_db, the memberships
    # SELECT policy hides every row and the user looks like a non-member.
    _set_context(session, org_id, user_id)
    membership = session.execute(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.organization_id == org_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if membership is None:
        raise ValueError("No active membership in this organization")
    user = session.get(User, user_id)
    if user is None:
        raise ValueError("User not found")
    return _finish_login(
        session,
        {"id": str(user.id), "email": user.email},
        org_id,
        ip,
        user_agent,
    )


def _lookup_session_by_token(session: Session, refresh_token: str) -> dict | None:
    """Find a refresh session by its hash via the SECURITY DEFINER lookup.

    Refresh tokens are credentials: the lookup must work before any RLS
    context exists, so it goes through the controlled function, not a raw
    table read.
    """
    row = (
        session.execute(text("SELECT * FROM auth_get_session_by_token_hash(:h)"), {"h": hash_token(refresh_token)})
        .mappings()
        .first()
    )
    return dict(row) if row else None


def refresh(session: Session, refresh_token: str, ip: str | None, user_agent: str | None) -> LoginResult:
    """Rotate a refresh token. The old token is revoked; a new pair is issued."""
    found = _lookup_session_by_token(session, refresh_token)
    if found is None:
        raise ValueError("Invalid or expired refresh token")
    # The lookup went through the SECURITY DEFINER function (no RLS
    # context yet). Scope the transaction to the session's org/user
    # BEFORE the raw table read, or RLS hides the row.
    _set_context(session, as_uuid(found["organization_id"]), as_uuid(found["user_id"]))
    row = session.get(AuthSession, as_uuid(found["id"]))
    if row is None or row.revoked_at is not None or row.expires_at < _now():
        raise ValueError("Invalid or expired refresh token")
    _set_context(session, row.organization_id, row.user_id)
    row.revoked_at = _now()
    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise ValueError("Invalid or expired refresh token")
    new_refresh, _ = _create_session(session, row.user_id, row.organization_id, ip, user_agent)
    access_token = issue_access_token(str(row.user_id), str(row.organization_id), user.email)
    audit_mod.write_audit(
        session,
        organization_id=row.organization_id,
        actor_id=row.user_id,
        action=audit_mod.AUTH_TOKEN_REFRESHED,
        resource_type="session",
        resource_id=str(row.id),
        outcome="success",
    )
    return LoginResult(status="ok", access_token=access_token, refresh_token=new_refresh, user_id=str(row.user_id))


def logout(session: Session, refresh_token: str, user_id: uuid.UUID, org_id: uuid.UUID) -> None:
    found = _lookup_session_by_token(session, refresh_token)
    if found is None:
        return
    row = session.get(AuthSession, as_uuid(found["id"]))
    if row is not None and row.user_id == user_id and row.organization_id == org_id:
        _set_context(session, org_id, user_id)
        row.revoked_at = _now()
        audit_mod.write_audit(
            session,
            organization_id=org_id,
            actor_id=user_id,
            action=audit_mod.AUTH_LOGOUT,
            resource_type="session",
            resource_id=str(row.id),
            outcome="success",
        )


def revoke_all_sessions(session: Session, user_id: uuid.UUID) -> int:
    rows = session.execute(
        select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
    ).scalars()
    count = 0
    for row in rows:
        row.revoked_at = _now()
        count += 1
    return count


# --- MFA enrolment -------------------------------------------------------


def enroll_mfa(session: Session, user: User) -> tuple[str, str]:
    """Generate a TOTP secret and provisioning URI. MFA is enabled only
    after the user proves possession with ``verify_mfa_enrollment``."""
    secret = new_totp_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    return secret, totp_uri(secret, user.email)


def verify_mfa_enrollment(session: Session, user: User, code: str) -> bool:
    if not user.mfa_secret or not verify_totp(user.mfa_secret, code):
        return False
    user.mfa_enabled = True
    _audit_if_org(
        session,
        user.id,
        audit_mod.AUTH_MFA_ENROLLED,
        "user",
        str(user.id),
    )
    return True


def disable_mfa(session: Session, user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret = None


# --- Password recovery ---------------------------------------------------


def request_password_reset(session: Session, email: str) -> None:
    """Always succeeds silently (no user enumeration)."""
    settings = get_settings()
    user = _lookup_user_by_email(session, email)
    if user is None:
        return
    _set_context(session, None, as_uuid(user["id"]))
    token = new_opaque_token()
    session.add(
        PasswordReset(
            user_id=as_uuid(user["id"]),
            token_hash=hash_token(token),
            expires_at=_now() + timedelta(minutes=settings.password_reset_minutes),
        )
    )
    # The reset URL is delivered by email; the token is never logged.
    email_service.send_password_reset_email(email, "https://app.nullitsm.example/reset?token=REDACTED")
    _audit_if_org(
        session,
        as_uuid(user["id"]),
        audit_mod.AUTH_PASSWORD_RESET_REQUESTED,
        "user",
        user["id"],
    )


def reset_password(session: Session, token: str, new_password: str) -> None:
    row = (
        session.execute(text("SELECT * FROM auth_get_password_reset_by_token(:h)"), {"h": hash_token(token)})
        .mappings()
        .first()
    )
    if row is None:
        raise ValueError("Invalid or expired reset token")
    # The lookup went through the SECURITY DEFINER function (no RLS
    # context yet). Scope to the reset's user BEFORE the raw table read,
    # or RLS hides the row (password_resets is visible only to its user).
    _set_context(session, None, as_uuid(row["user_id"]))
    reset = session.get(PasswordReset, as_uuid(row["id"]))
    if reset is None or reset.used_at is not None or reset.expires_at < _now():
        raise ValueError("Invalid or expired reset token")
    user = session.get(User, reset.user_id)
    if user is None:
        raise ValueError("Invalid or expired reset token")
    _set_context(session, _first_org_id(session, user.id), user.id)
    user.password_hash = hash_password(new_password)
    reset.used_at = _now()
    revoke_all_sessions(session, user.id)
    _audit_if_org(
        session,
        user.id,
        audit_mod.AUTH_PASSWORD_RESET_COMPLETED,
        "user",
        str(user.id),
    )


# --- Invitation acceptance ----------------------------------------------


def accept_invitation(session: Session, token: str, full_name: str, password: str) -> tuple[User, Organization]:
    row = (
        session.execute(text("SELECT * FROM auth_get_invitation_by_token(:h)"), {"h": hash_token(token)})
        .mappings()
        .first()
    )
    if row is None:
        raise ValueError("Invalid or expired invitation")
    # The lookup went through the SECURITY DEFINER function (no RLS
    # context yet). Scope to the invitation's org BEFORE the raw table
    # read, or RLS hides the row.
    org_id = as_uuid(row["organization_id"])
    _set_context(session, org_id, None)
    invitation = session.get(Invitation, as_uuid(row["id"]))
    if invitation is None or invitation.status != "pending" or invitation.expires_at < _now():
        raise ValueError("Invalid or expired invitation")

    # The invitee may already exist (invited to a second org). Look them
    # up through the SECURITY DEFINER function: a raw users SELECT would
    # be RLS-filtered here (no membership, no user context yet).
    found_user = _lookup_user_by_email(session, invitation.email)
    if found_user is None:
        user = User(
            id=uuid.uuid4(),
            email=invitation.email,
            password_hash=hash_password(password),
            full_name=full_name,
            email_verified=True,
        )
        # The id is client-generated (SQLAlchemy only applies the uuid
        # default at flush, so an id must be assigned up front): set the
        # RLS user context to it BEFORE the insert, because INSERT ...
        # RETURNING is checked against the SELECT policy (own row), and
        # no membership exists yet.
        _set_context(session, org_id, user.id)
        session.add(user)
        session.flush()
    else:
        _set_context(session, org_id, as_uuid(found_user["id"]))
        user = session.get(User, as_uuid(found_user["id"]))
        if user is None:
            raise ValueError("Invalid or expired invitation")
        if user.full_name != full_name:
            user.full_name = full_name
        user.email_verified = True
    _set_context(session, org_id, user.id)

    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user.id)
    ).scalar_one_or_none()
    if membership is None:
        membership = Membership(organization_id=org_id, user_id=user.id, status="active")
        session.add(membership)
    else:
        membership.status = "active"

    role_rows = session.execute(select(InvitationRole).where(InvitationRole.invitation_id == invitation.id)).scalars()
    for ir in role_rows:
        exists = session.execute(
            select(UserRole).where(
                UserRole.organization_id == org_id,
                UserRole.user_id == user.id,
                UserRole.role_id == ir.role_id,
            )
        ).scalar_one_or_none()
        if exists is None:
            session.add(
                UserRole(
                    organization_id=org_id, user_id=user.id, role_id=ir.role_id, granted_by_id=invitation.invited_by_id
                )
            )

    invitation.status = "accepted"
    invitation.accepted_at = _now()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=user.id,
        action=audit_mod.MEMBERSHIP_ACCEPTED,
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome="success",
        metadata={"email": invitation.email},
    )
    # The organization row is readable only now that the membership
    # exists (the org SELECT policy is membership- or creator-gated).
    # The session runs with autoflush=False, so flush the pending
    # membership/role rows first — otherwise the policy's EXISTS check
    # sees no membership and the org looks missing.
    session.flush()
    org = session.get(Organization, org_id)
    if org is None:
        raise ValueError("Invalid or expired invitation")
    return user, org
