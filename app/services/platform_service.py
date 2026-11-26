"""Platform administration service: auth, roles, audit, and support grants.

This module is the backend for the Platform Admin Console
(``/api/v1/platform``). It operates ONLY on the platform domain
(``app/models/platform_admin.py``) and never on organization users,
roles, or data — except through the explicit, grant-gated
SECURITY DEFINER functions in migration 0002 for tenant reads.

Grant-scope rule (mirrored from the org domain): a platform admin may
only grant permissions they hold, and only a Platform Super Admin may
assign/revoke the Platform Super Admin role or manage platform roles
(``platform:roles:manage``).
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
from app.deps import check_platform_grant_scope
from app.models.platform_admin import (
    PlatformAccessGrant,
    PlatformAuditLog,
    PlatformPermission,
    PlatformRole,
    PlatformRolePermission,
    PlatformSession,
    PlatformUser,
    PlatformUserRole,
)
from app.permissions import PLATFORM_PERMISSIONS, PLATFORM_ROLE_TEMPLATES, resolve_template_permissions
from app.security import (
    hash_password,
    hash_token,
    issue_platform_access_token,
    issue_platform_mfa_token,
    new_opaque_token,
    new_totp_secret,
    totp_uri,
    verify_password,
    verify_totp,
)

UTC = timezone.utc

SUPER_ADMIN_ROLE_NAME = "Platform Super Admin"
ADMIN_ROLE_NAMES = ("Platform Super Admin", "Platform Administrator")
PRIVILEGED_LEVELS = ("Privileged", "Full Access")
VALID_ACCESS_LEVELS = ("Full Access", "Privileged", "Least Privilege", "Read-Only")


def _now() -> datetime:
    return datetime.now(UTC)


def seed_platform_roles(session: Session) -> dict[str, PlatformRole]:
    """Create the six platform role templates. Idempotent by name: the
    migration already seeds them, so this is a no-op on a migrated DB
    and a safety net for a bare one."""
    perm_by_code = {p.code: p for p in session.execute(select(PlatformPermission)).scalars()}
    created: dict[str, PlatformRole] = {}
    for name, template in PLATFORM_ROLE_TEMPLATES.items():
        existing = session.execute(select(PlatformRole).where(PlatformRole.name == name)).scalar_one_or_none()
        if existing is not None:
            created[name] = existing
            continue
        role = PlatformRole(
            name=name,
            description=template["description"],
            access_level=template["access_level"],
            is_system=True,
        )
        session.add(role)
        session.flush()
        for code in resolve_template_permissions(template, catalog=PLATFORM_PERMISSIONS):
            perm = perm_by_code.get(code)
            if perm is not None:
                session.add(PlatformRolePermission(role_id=role.id, permission_id=perm.id))
        created[name] = role
    return created


def platform_role_permission_codes(session: Session, role_id: uuid.UUID) -> list[str]:
    rows = session.execute(
        select(PlatformPermission.code)
        .join(PlatformRolePermission, PlatformRolePermission.permission_id == PlatformPermission.id)
        .where(PlatformRolePermission.role_id == role_id)
    ).all()
    return [r[0] for r in rows]


def write_platform_audit(
    session: Session,
    actor_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str,
    organization_id: uuid.UUID | None = None,
    outcome: str = "success",
    metadata: dict | None = None,
) -> PlatformAuditLog:
    """Write one append-only platform audit event. There is no update or
    delete path for platform audit records (no RLS policy, no API)."""
    row = PlatformAuditLog(
        actor_id=actor_id,
        organization_id=organization_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        meta=metadata or {},
    )
    session.add(row)
    return row


# --- Lookups (SECURITY DEFINER, pre-auth) ---------------------------------


def _lookup_platform_user_by_email(session: Session, email: str) -> dict | None:
    row = session.execute(text("SELECT * FROM platform_get_user_by_email(:email)"), {"email": email}).mappings().first()
    return dict(row) if row else None


def _lookup_platform_session_by_token(session: Session, refresh_token: str) -> dict | None:
    row = (
        session.execute(text("SELECT * FROM platform_get_session_by_token_hash(:h)"), {"h": hash_token(refresh_token)})
        .mappings()
        .first()
    )
    return dict(row) if row else None


def _set_platform_context(session: Session, platform_user_id: uuid.UUID) -> None:
    """Scope the transaction to a platform identity (before any platform
    table is touched: INSERT ... RETURNING is checked against the SELECT
    policy, which gates on this variable)."""
    set_rls_context(session, None, None, platform_user_id)


# --- Platform auth ----------------------------------------------------------


@dataclass
class PlatformLoginResult:
    status: str  # "ok" | "mfa_required"
    access_token: str | None = None
    refresh_token: str | None = None
    mfa_token: str | None = None
    platform_user_id: str | None = None


def _create_platform_session(
    session: Session,
    platform_user_id: uuid.UUID,
    ip: str | None,
    user_agent: str | None,
    mfa_verified: bool,
) -> tuple[str, PlatformSession]:
    settings = get_settings()
    refresh_token = new_opaque_token()
    row = PlatformSession(
        platform_user_id=platform_user_id,
        refresh_token_hash=hash_token(refresh_token),
        expires_at=_now() + timedelta(days=settings.refresh_token_days),
        mfa_verified=mfa_verified,
        ip_address=ip,
        user_agent=user_agent,
    )
    session.add(row)
    session.flush()
    return refresh_token, row


def _finish_platform_login(session: Session, user: dict, ip: str | None, user_agent: str | None) -> PlatformLoginResult:
    """Issue the token pair for an authenticated platform user.

    Sessions created here always have ``mfa_verified=True``: either the
    user has no MFA to step up from, or MFA was just completed via the
    challenge. A password-only login of an MFA-enabled user never reaches
    this function — it returns an MFA token instead.
    """
    user_id = as_uuid(user["id"])
    _set_platform_context(session, user_id)
    refresh_token, _ = _create_platform_session(session, user_id, ip, user_agent, mfa_verified=True)
    access_token = issue_platform_access_token(user["id"], user["email"], mfa=True)
    platform_user = session.get(PlatformUser, user_id)
    if platform_user is not None:
        platform_user.last_login_at = _now()
    write_platform_audit(
        session,
        actor_id=user_id,
        action=audit_mod.PLATFORM_AUTH_LOGIN,
        resource_type="session",
        resource_id=str(user_id),
        outcome="success",
    )
    return PlatformLoginResult(
        status="ok",
        access_token=access_token,
        refresh_token=refresh_token,
        platform_user_id=str(user["id"]),
    )


def login_platform(
    session: Session,
    email: str,
    password: str,
    ip: str | None,
    user_agent: str | None,
) -> PlatformLoginResult:
    """Authenticate a platform user by email/password.

    Denies inactive or unapproved accounts. MFA-enabled users get a
    short-lived MFA token only — no session is created until the
    challenge succeeds.
    """
    user = _lookup_platform_user_by_email(session, email)
    if (
        user is None
        or not user["is_active"]
        or user["review_status"] != "approved"
        or not verify_password(password, user["password_hash"])
    ):
        if user is not None:
            _set_platform_context(session, as_uuid(user["id"]))
            write_platform_audit(
                session,
                actor_id=as_uuid(user["id"]),
                action=audit_mod.PLATFORM_AUTH_LOGIN_FAILED,
                resource_type="session",
                resource_id=str(user["id"]),
                outcome="failure",
                metadata={"reason": "bad credentials or inactive account"},
            )
        raise ValueError("Invalid email or password")
    if user["mfa_enabled"]:
        return PlatformLoginResult(
            status="mfa_required",
            mfa_token=issue_platform_mfa_token(user["id"], user["email"]),
            platform_user_id=str(user["id"]),
        )
    return _finish_platform_login(session, user, ip, user_agent)


def complete_platform_mfa(
    session: Session,
    mfa_token: str,
    code: str,
    ip: str | None,
    user_agent: str | None,
) -> PlatformLoginResult:
    """Verify the TOTP code for a pending platform MFA login and finish sign-in."""
    from app.security import decode_local_token

    claims = decode_local_token(mfa_token, expected_type="platform_mfa")
    user = _lookup_platform_user_by_email(session, claims.email)
    if user is None or not user["mfa_secret"] or not verify_totp(user["mfa_secret"], code):
        if user is not None:
            _set_platform_context(session, as_uuid(user["id"]))
            write_platform_audit(
                session,
                actor_id=as_uuid(user["id"]),
                action=audit_mod.PLATFORM_AUTH_MFA_FAILED,
                resource_type="session",
                resource_id=str(user["id"]),
                outcome="failure",
            )
        raise ValueError("Invalid MFA code")
    if not user["is_active"] or user["review_status"] != "approved":
        raise ValueError("Invalid MFA code")
    return _finish_platform_login(session, user, ip, user_agent)


def refresh_platform(
    session: Session,
    refresh_token: str,
    ip: str | None,
    user_agent: str | None,
) -> PlatformLoginResult:
    """Rotate a platform refresh token. The old token is revoked; the new
    access token keeps the session's ``mfa_verified`` value (migration
    0003), so a refresh never silently gains or loses MFA standing."""
    found = _lookup_platform_session_by_token(session, refresh_token)
    if found is None:
        raise ValueError("Invalid or expired refresh token")
    platform_user_id = as_uuid(found["platform_user_id"])
    _set_platform_context(session, platform_user_id)
    row = session.get(PlatformSession, as_uuid(found["id"]))
    if row is None or row.revoked_at is not None or row.expires_at < _now():
        raise ValueError("Invalid or expired refresh token")
    mfa_verified = bool(row.mfa_verified)
    row.revoked_at = _now()
    user = session.get(PlatformUser, row.platform_user_id)
    if user is None or not user.is_active or user.review_status != "approved":
        raise ValueError("Invalid or expired refresh token")
    new_refresh, _ = _create_platform_session(session, row.platform_user_id, ip, user_agent, mfa_verified)
    access_token = issue_platform_access_token(str(row.platform_user_id), user.email, mfa=mfa_verified)
    write_platform_audit(
        session,
        actor_id=row.platform_user_id,
        action=audit_mod.PLATFORM_AUTH_TOKEN_REFRESHED,
        resource_type="session",
        resource_id=str(row.id),
        outcome="success",
    )
    return PlatformLoginResult(
        status="ok",
        access_token=access_token,
        refresh_token=new_refresh,
        platform_user_id=str(row.platform_user_id),
    )


def logout_platform(session: Session, refresh_token: str, platform_user_id: uuid.UUID) -> None:
    found = _lookup_platform_session_by_token(session, refresh_token)
    if found is None:
        return
    _set_platform_context(session, platform_user_id)
    row = session.get(PlatformSession, as_uuid(found["id"]))
    if row is not None and row.platform_user_id == platform_user_id:
        row.revoked_at = _now()
        write_platform_audit(
            session,
            actor_id=platform_user_id,
            action=audit_mod.PLATFORM_AUTH_LOGOUT,
            resource_type="session",
            resource_id=str(row.id),
            outcome="success",
        )


def enroll_platform_mfa(session: Session, user: PlatformUser) -> tuple[str, str]:
    """Generate a TOTP secret and provisioning URI. MFA is enabled only
    after the user proves possession with ``verify_platform_mfa_enrollment``."""
    secret = new_totp_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    return secret, totp_uri(secret, user.email)


def verify_platform_mfa_enrollment(session: Session, user: PlatformUser, code: str) -> bool:
    if not user.mfa_secret or not verify_totp(user.mfa_secret, code):
        return False
    user.mfa_enabled = True
    write_platform_audit(
        session,
        actor_id=user.id,
        action=audit_mod.PLATFORM_AUTH_MFA_ENROLLED,
        resource_type="platform_user",
        resource_id=str(user.id),
        outcome="success",
    )
    return True


# --- Platform users (admin directory) --------------------------------------


def list_platform_users(session: Session) -> list[PlatformUser]:
    return list(session.execute(select(PlatformUser).order_by(PlatformUser.email)).scalars())


def get_platform_user(session: Session, platform_user_id: uuid.UUID) -> PlatformUser | None:
    return session.get(PlatformUser, platform_user_id)


def platform_user_roles(session: Session, platform_user_id: uuid.UUID) -> list[PlatformRole]:
    rows = session.execute(
        select(PlatformRole)
        .join(PlatformUserRole, PlatformUserRole.role_id == PlatformRole.id)
        .where(PlatformUserRole.platform_user_id == platform_user_id)
        .order_by(PlatformRole.name)
    ).scalars()
    return list(rows)


def platform_user_role_names(session: Session, platform_user_id: uuid.UUID) -> list[str]:
    return [r.name for r in platform_user_roles(session, platform_user_id)]


def create_platform_user(session: Session, actor, email: str, full_name: str, password: str) -> PlatformUser:
    if _lookup_platform_user_by_email(session, email) is not None:
        raise ValueError(f"Platform user '{email}' already exists")
    user = PlatformUser(
        id=uuid.uuid4(),
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        source="invited",
        review_status="approved",
    )
    session.add(user)
    session.flush()
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ADMIN_CREATED,
        resource_type="platform_user",
        resource_id=str(user.id),
        outcome="success",
        metadata={"email": email, "full_name": full_name},
    )
    return user


def suspend_platform_user(session: Session, actor, user: PlatformUser) -> PlatformUser:
    if actor.platform_user_id == user.id:
        raise ValueError("Cannot suspend your own platform account")
    user.is_active = False
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ADMIN_SUSPENDED,
        resource_type="platform_user",
        resource_id=str(user.id),
        outcome="success",
        metadata={"email": user.email},
    )
    return user


def reactivate_platform_user(session: Session, actor, user: PlatformUser) -> PlatformUser:
    user.is_active = True
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ADMIN_REACTIVATED,
        resource_type="platform_user",
        resource_id=str(user.id),
        outcome="success",
        metadata={"email": user.email},
    )
    return user


# --- Platform roles ---------------------------------------------------------


def list_platform_roles(session: Session) -> list[PlatformRole]:
    return list(session.execute(select(PlatformRole).order_by(PlatformRole.name)).scalars())


def get_platform_role(session: Session, role_id: uuid.UUID) -> PlatformRole | None:
    return session.get(PlatformRole, role_id)


def _set_platform_role_permissions(session: Session, role: PlatformRole, permission_codes: list[str]) -> None:
    # Defense in depth: platform roles may only hold platform:* codes.
    non_platform = [c for c in permission_codes if not c.startswith("platform:")]
    if non_platform:
        raise ValueError(f"Platform roles cannot grant non-platform permissions: {', '.join(non_platform)}")
    perms = session.execute(select(PlatformPermission).where(PlatformPermission.code.in_(permission_codes))).scalars()
    perm_by_code = {p.code: p for p in perms}
    unknown = [c for c in permission_codes if c not in perm_by_code]
    if unknown:
        raise ValueError(f"Unknown platform permissions: {', '.join(unknown)}")
    session.execute(PlatformRolePermission.__table__.delete().where(PlatformRolePermission.role_id == role.id))
    for code in dict.fromkeys(permission_codes):
        session.add(PlatformRolePermission(role_id=role.id, permission_id=perm_by_code[code].id))


def create_platform_role(
    session: Session,
    actor,
    name: str,
    description: str,
    access_level: str,
    permission_codes: list[str],
) -> PlatformRole:
    if access_level not in VALID_ACCESS_LEVELS:
        raise ValueError("Invalid access_level")
    check_platform_grant_scope(actor, permission_codes)
    existing = session.execute(select(PlatformRole).where(PlatformRole.name == name)).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"Platform role '{name}' already exists")
    role = PlatformRole(name=name, description=description, access_level=access_level)
    session.add(role)
    session.flush()
    _set_platform_role_permissions(session, role, permission_codes)
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ROLE_CREATED,
        resource_type="platform_role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"name": name, "access_level": access_level, "permissions": permission_codes},
    )
    return role


def update_platform_role(
    session: Session, actor, role: PlatformRole, description: str | None, access_level: str | None
) -> PlatformRole:
    if description is not None:
        role.description = description
    if access_level is not None:
        if access_level not in VALID_ACCESS_LEVELS:
            raise ValueError("Invalid access_level")
        role.access_level = access_level
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ROLE_UPDATED,
        resource_type="platform_role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"name": role.name},
    )
    return role


def delete_platform_role(session: Session, actor, role: PlatformRole) -> None:
    if role.is_system:
        raise ValueError("System roles cannot be deleted")
    assigned = session.execute(select(PlatformUserRole).where(PlatformUserRole.role_id == role.id)).scalars().first()
    if assigned is not None:
        raise ValueError("Role is assigned to users; revoke it first")
    session.delete(role)
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ROLE_DELETED,
        resource_type="platform_role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"name": role.name},
    )


def configure_platform_role_permissions(
    session: Session, actor, role: PlatformRole, permission_codes: list[str]
) -> PlatformRole:
    check_platform_grant_scope(actor, permission_codes)
    _set_platform_role_permissions(session, role, permission_codes)
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ROLE_PERMISSIONS_CHANGED,
        resource_type="platform_role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"role": role.name, "permissions": permission_codes},
    )
    return role


def _check_super_admin_boundary(actor, role: PlatformRole) -> None:
    """Only a holder of platform:roles:manage may touch the
    Platform Super Admin role. Raises PermissionError (mapped to 403)."""
    if role.name == SUPER_ADMIN_ROLE_NAME and not actor.has("platform:roles:manage"):
        raise PermissionError("Only a Platform Super Admin may assign or revoke the Platform Super Admin role")


def assign_platform_role(session: Session, actor, target_user_id: uuid.UUID, role: PlatformRole) -> dict:
    if actor.platform_user_id == target_user_id:
        raise ValueError("Cannot assign a role to yourself")
    target = session.get(PlatformUser, target_user_id)
    if target is None:
        raise ValueError("Platform user not found")
    _check_super_admin_boundary(actor, role)
    check_platform_grant_scope(actor, platform_role_permission_codes(session, role.id))
    existing = session.execute(
        select(PlatformUserRole).where(
            PlatformUserRole.platform_user_id == target_user_id, PlatformUserRole.role_id == role.id
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            PlatformUserRole(platform_user_id=target_user_id, role_id=role.id, granted_by_id=actor.platform_user_id)
        )
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ROLE_ASSIGNED,
        resource_type="platform_user_role",
        resource_id=str(target_user_id),
        outcome="success",
        metadata={"role": role.name},
    )
    return {"status": "assigned"}


def revoke_platform_role(session: Session, actor, target_user_id: uuid.UUID, role: PlatformRole) -> None:
    if actor.platform_user_id == target_user_id and role.access_level in PRIVILEGED_LEVELS:
        raise ValueError("Cannot revoke your own privileged role")
    target = session.get(PlatformUser, target_user_id)
    if target is None:
        raise ValueError("Platform user not found")
    _check_super_admin_boundary(actor, role)
    row = session.execute(
        select(PlatformUserRole).where(
            PlatformUserRole.platform_user_id == target_user_id, PlatformUserRole.role_id == role.id
        )
    ).scalar_one_or_none()
    if row is None:
        raise ValueError("Role is not assigned to this user")
    if role.name == SUPER_ADMIN_ROLE_NAME:
        # Never revoke the last Platform Super Admin's role: the platform
        # would be left with no one able to manage platform roles.
        remaining = (
            session.execute(
                select(PlatformUserRole).where(
                    PlatformUserRole.role_id == role.id, PlatformUserRole.platform_user_id != target_user_id
                )
            )
            .scalars()
            .first()
        )
        if remaining is None:
            raise ValueError("Cannot revoke the last Platform Super Admin role")
    session.delete(row)
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_ROLE_REVOKED,
        resource_type="platform_user_role",
        resource_id=str(target_user_id),
        outcome="success",
        metadata={"role": role.name},
    )


# --- Tenant directory (SECURITY DEFINER reads) ------------------------------


def list_tenants(session: Session) -> list[dict]:
    rows = session.execute(text("SELECT * FROM platform_list_organizations()")).mappings().all()
    return [dict(r) for r in rows]


def get_tenant(session: Session, org_id: uuid.UUID) -> dict | None:
    row = session.execute(text("SELECT * FROM platform_get_organization(:id)"), {"id": org_id}).mappings().first()
    return dict(row) if row else None


def list_tenant_users(session: Session, platform_user_id: uuid.UUID, org_id: uuid.UUID) -> list[dict]:
    """Grant-gated tenant user read. The SECURITY DEFINER function
    enforces the grant in the database: with no active, unexpired
    grant it returns no rows — deliberately indistinguishable from an
    organization with no users. The caller audits every such read."""
    rows = (
        session.execute(
            text("SELECT * FROM platform_support_list_org_users(:org_id, :platform_user_id)"),
            {"org_id": org_id, "platform_user_id": platform_user_id},
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]


# --- Support grants ----------------------------------------------------------


def list_support_grants(session: Session, status: str | None = None) -> list[PlatformAccessGrant]:
    stmt = select(PlatformAccessGrant).order_by(PlatformAccessGrant.created_at.desc())
    if status is not None:
        stmt = stmt.where(PlatformAccessGrant.status == status)
    return list(session.execute(stmt).scalars())


def get_support_grant(session: Session, grant_id: uuid.UUID) -> PlatformAccessGrant | None:
    return session.get(PlatformAccessGrant, grant_id)


def request_support_grant(
    session: Session, actor, org_id: uuid.UUID, purpose: str, expires_at: datetime
) -> PlatformAccessGrant:
    if expires_at <= _now():
        raise ValueError("expires_at must be in the future")
    if get_tenant(session, org_id) is None:
        raise ValueError("Organization not found")
    grant = PlatformAccessGrant(
        platform_user_id=actor.platform_user_id,
        organization_id=org_id,
        purpose=purpose,
        status="pending",
        granted_by_id=actor.platform_user_id,
        expires_at=expires_at,
    )
    session.add(grant)
    session.flush()
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_SUPPORT_GRANT_REQUESTED,
        resource_type="support_grant",
        resource_id=str(grant.id),
        organization_id=org_id,
        outcome="success",
        metadata={"purpose": purpose},
    )
    return grant


def approve_support_grant(session: Session, approver, grant_id: uuid.UUID) -> PlatformAccessGrant:
    grant = session.get(PlatformAccessGrant, grant_id)
    if grant is None:
        raise ValueError("Support grant not found")
    if grant.status != "pending":
        raise ValueError(f"Support grant is already {grant.status}")
    if grant.expires_at <= _now():
        raise ValueError("Support grant has expired")
    if approver.platform_user_id == grant.platform_user_id:
        raise PermissionError("A support grant cannot be approved by its requester")
    if not approver.has("platform:support:manage"):
        raise PermissionError("Approver must hold platform:support:manage")
    approver_roles = set(platform_user_role_names(session, approver.platform_user_id))
    if not approver_roles.intersection(ADMIN_ROLE_NAMES):
        raise PermissionError("Support grants may only be approved by a Platform Super Admin or Platform Administrator")
    grant.status = "active"
    grant.approved_by_id = approver.platform_user_id
    write_platform_audit(
        session,
        actor_id=approver.platform_user_id,
        action=audit_mod.PLATFORM_SUPPORT_GRANT_APPROVED,
        resource_type="support_grant",
        resource_id=str(grant.id),
        organization_id=grant.organization_id,
        outcome="success",
        metadata={"platform_user_id": str(grant.platform_user_id)},
    )
    return grant


def revoke_support_grant(session: Session, actor, grant_id: uuid.UUID) -> PlatformAccessGrant:
    grant = session.get(PlatformAccessGrant, grant_id)
    if grant is None:
        raise ValueError("Support grant not found")
    if grant.status not in ("pending", "active"):
        raise ValueError(f"Support grant is already {grant.status}")
    grant.status = "revoked"
    write_platform_audit(
        session,
        actor_id=actor.platform_user_id,
        action=audit_mod.PLATFORM_SUPPORT_GRANT_REVOKED,
        resource_type="support_grant",
        resource_id=str(grant.id),
        organization_id=grant.organization_id,
        outcome="success",
    )
    return grant


# --- Platform audit (read-only) ---------------------------------------------


def list_platform_audit(
    session: Session,
    action: str | None = None,
    actor_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[PlatformAuditLog]:
    stmt = select(PlatformAuditLog).order_by(PlatformAuditLog.created_at.desc()).limit(limit).offset(offset)
    if action:
        stmt = stmt.where(PlatformAuditLog.action == action)
    if actor_id is not None:
        stmt = stmt.where(PlatformAuditLog.actor_id == actor_id)
    if organization_id is not None:
        stmt = stmt.where(PlatformAuditLog.organization_id == organization_id)
    return list(session.execute(stmt).scalars())
