"""Request dependencies: authentication, tenant resolution, authorization.

Tenant resolution (server-side, never client-trusted)
-----------------------------------------------------
1. The access token carries ``sub`` (user id) and ``org`` (organization id).
2. The dependency loads the session's membership and verifies the user is
   an ACTIVE member of that organization. A client-supplied
   ``X-Organization-Id`` header may request an organization switch, but it
   is only honoured when the user has an active membership there — otherwise
   the request is denied (and the denial is audited).
3. The DB session is then RLS-scoped to the resolved organization.

Authorization
-------------
``require_permission("tickets:create")`` loads the caller's permissions for
the resolved organization (via user_roles -> role_permissions) and denies
with 403 when the permission is missing. Denials are audited.

``require_scope``: when assigning roles or permissions, the actor may only
grant permissions they themselves hold (an administrator cannot grant
permissions beyond their authorized scope). The Administrator role holds
everything, so this binds non-admin granters.
"""

import uuid
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.database import SessionLocal, set_rls_context
from app.models.platform import Membership, Organization
from app.models.platform_admin import (
    PlatformPermission,
    PlatformRolePermission,
    PlatformUser,
    PlatformUserRole,
)
from app.models.rbac import Permission, RolePermission, UserRole
from app.security import decode_local_token, get_token_verifier


class Unauthorized(HTTPException):
    def __init__(self, detail: str = "Authentication required") -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class Forbidden(HTTPException):
    def __init__(self, detail: str = "Permission denied") -> None:
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


@dataclass
class Principal:
    """The authenticated caller, with their resolved organization."""

    user_id: uuid.UUID
    email: str
    organization_id: uuid.UUID
    organization_slug: str
    permissions: set[str] = field(default_factory=set)
    is_org_owner: bool = False

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def _bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise Unauthorized("Missing bearer token")
    return auth[len("Bearer ") :].strip()


def get_bearer_token(request: Request) -> str:
    """Public accessor for the raw bearer token.

    Used by auth paths that live outside this module (portal sessions,
    SCIM bearer tokens): they decode the token themselves and set their
    own RLS context.
    """
    return _bearer_token(request)


def _decode_access_token(token: str):
    verifier = get_token_verifier()
    if verifier is not None:
        return verifier.verify(token)
    return decode_local_token(token, expected_type="access")


def _load_membership(session: Session, user_id: uuid.UUID, org_id: uuid.UUID) -> Membership | None:
    return session.execute(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.organization_id == org_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()


def _load_permissions(session: Session, user_id: uuid.UUID, org_id: uuid.UUID) -> set[str]:
    rows = session.execute(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id, UserRole.organization_id == org_id)
    ).all()
    return {r[0] for r in rows}


def get_db(request: Request):
    """Yield a request-scoped DB session.

    The session is RLS-scoped once the principal is resolved; until then it
    runs with no tenant context (RLS denies tenant rows). Endpoints that
    need the principal use ``get_principal`` (which depends on this).
    """
    session = SessionLocal()
    try:
        session.begin()
        set_rls_context(session, None, None)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_user_from_token(request: Request, session: Session = Depends(get_db)) -> tuple[uuid.UUID, str]:
    """Authenticate a bearer token and return (user_id, email).

    Used by endpoints that do not require an organization — organization
    creation by a user who belongs to no organization yet. The token's
    organization (if any) is ignored here; organization-scoped endpoints
    must use :func:`get_principal` instead.

    Sets the RLS user context (no org) so the caller's own user row is
    readable — without it, ``session.get(User, ...)`` returns None under
    the users SELECT policy and the caller looks unauthenticated.
    """
    token = _bearer_token(request)
    try:
        claims = _decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise Unauthorized("Session expired")
    except jwt.InvalidTokenError:
        raise Unauthorized("Invalid token")
    try:
        user_id = uuid.UUID(claims.sub)
    except ValueError:
        raise Unauthorized("Invalid token subject")
    set_rls_context(session, None, user_id)
    return user_id, claims.email


def get_principal(
    request: Request,
    session: Session = Depends(get_db),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
) -> Principal:
    """Authenticate the bearer token and resolve the organization."""
    token = _bearer_token(request)
    try:
        claims = _decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise Unauthorized("Session expired")
    except jwt.InvalidTokenError:
        raise Unauthorized("Invalid token")

    try:
        user_id = uuid.UUID(claims.sub)
    except ValueError:
        raise Unauthorized("Invalid token subject")

    # Set the user context BEFORE any tenant table is touched: the
    # membership SELECT policy allows a caller to read their own memberships.
    set_rls_context(session, None, user_id)

    # Resolve the organization: header may request a switch, but the token's
    # org is the default. Either way, membership is verified server-side.
    requested_org: uuid.UUID | None = None
    if x_organization_id:
        try:
            requested_org = uuid.UUID(x_organization_id)
        except ValueError:
            raise Forbidden("Invalid organization header")
    token_org = uuid.UUID(claims.org) if claims.org else None
    target_org = requested_org or token_org
    if target_org is None:
        raise Unauthorized("No organization selected — switch organization first")

    membership = _load_membership(session, user_id, target_org)
    if membership is None:
        # Audited denial: cross-organization access attempt. Scope the
        # transaction to the requested org first so the audit INSERT
        # passes its RLS policy (the row records the denied attempt).
        set_rls_context(session, target_org, user_id)
        try:
            audit_mod.write_audit(
                session,
                organization_id=target_org,
                actor_id=user_id,
                action=audit_mod.AUTHZ_DENIED,
                resource_type="organization",
                resource_id=str(target_org),
                outcome="denied",
                metadata={"reason": "no active membership"},
            )
            session.commit()
        except Exception:
            session.rollback()
        raise Forbidden("No active membership in this organization")

    # Re-scope the transaction to the resolved tenant for the rest of the
    # request. (SET LOCAL inside the already-open transaction.)
    set_rls_context(session, target_org, user_id)
    org = session.get(Organization, target_org)
    permissions = _load_permissions(session, user_id, target_org)

    return Principal(
        user_id=user_id,
        email=claims.email,
        organization_id=target_org,
        organization_slug=org.slug if org else "",
        permissions=permissions,
        is_org_owner=membership.is_owner,
    )


def require_permission(permission: str):
    """Dependency factory: caller must hold ``permission`` in this org."""

    def _check(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(permission):
            raise Forbidden(f"Missing permission: {permission}")
        return principal

    return _check


def require_any_permission(*permissions: str):
    """Dependency factory: caller must hold at least one of ``permissions``."""

    def _check(principal: Principal = Depends(get_principal)) -> Principal:
        if not any(principal.has(p) for p in permissions):
            raise Forbidden(f"Missing any of: {', '.join(permissions)}")
        return principal

    return _check


def check_grant_scope(principal: Principal, permission_codes: list[str]) -> None:
    """An actor may only grant permissions they themselves hold.

    This is what stops an administrator (or any role granter) from granting
    permissions beyond their authorized scope. The Administrator role holds
    every permission, so it passes; anyone else is bounded by their own set.
    """
    missing = [c for c in permission_codes if not principal.has(c)]
    if missing:
        raise Forbidden(f"Cannot grant permissions you do not hold: {', '.join(missing)}")


# --- Platform domain -------------------------------------------------------
# The platform domain is a SEPARATE identity and authorization boundary
# from the organization domain above: platform users are internal NULL
# personnel, authenticated by a DISTINCT JWT type (``platform_access``),
# holding only ``platform:*`` permissions. An org access token can never
# authenticate here (its type is ``access``) and a platform token can
# never authenticate an org endpoint. No auto-conversion either way.


@dataclass
class PlatformPrincipal:
    """The authenticated platform caller."""

    platform_user_id: uuid.UUID
    email: str
    permissions: set[str] = field(default_factory=set)
    mfa: bool = False

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def _load_platform_permissions(session: Session, platform_user_id: uuid.UUID) -> set[str]:
    rows = session.execute(
        select(PlatformPermission.code)
        .join(PlatformRolePermission, PlatformRolePermission.permission_id == PlatformPermission.id)
        .join(PlatformUserRole, PlatformUserRole.role_id == PlatformRolePermission.role_id)
        .where(PlatformUserRole.platform_user_id == platform_user_id)
    ).all()
    return {r[0] for r in rows}


def get_platform_principal(request: Request, session: Session = Depends(get_db)) -> PlatformPrincipal:
    """Authenticate a platform access token and resolve the platform user.

    Platform tokens are local HS256 JWTs only (never OIDC): the token
    type ``platform_access`` is checked, so an org ``access`` token is
    rejected here. The session is RLS-scoped to the platform identity;
    org tables stay invisible to it.
    """
    token = _bearer_token(request)
    try:
        claims = decode_local_token(token, expected_type="platform_access")
    except jwt.ExpiredSignatureError:
        raise Unauthorized("Session expired")
    except jwt.InvalidTokenError:
        raise Unauthorized("Invalid token")
    try:
        platform_user_id = uuid.UUID(claims.sub)
    except ValueError:
        raise Unauthorized("Invalid token subject")

    # Set the platform RLS context BEFORE any platform table is touched:
    # the platform_users SELECT policy gates on this variable.
    set_rls_context(session, None, None, platform_user_id)
    user = session.get(PlatformUser, platform_user_id)
    if user is None or not user.is_active or user.review_status != "approved":
        raise Unauthorized("Platform account is not active")
    permissions = _load_platform_permissions(session, platform_user_id)
    return PlatformPrincipal(
        platform_user_id=platform_user_id,
        email=claims.email,
        permissions=permissions,
        mfa=claims.mfa,
    )


def require_platform_permission(code: str, require_mfa: bool = False):
    """Dependency factory: caller must hold the platform ``code``.

    MFA rule (enforced here so routers just pass the code): every
    ``*:manage`` platform permission requires MFA (``mfa=true`` on the
    access token); every ``*:read`` works with ``mfa=false``.
    """

    needs_mfa = require_mfa or code.endswith(":manage")

    def _check(principal: PlatformPrincipal = Depends(get_platform_principal)) -> PlatformPrincipal:
        if not principal.has(code):
            raise Forbidden(f"Missing permission: {code}")
        if needs_mfa and not principal.mfa:
            raise Forbidden(f"Permission {code} requires MFA")
        return principal

    return _check


def check_platform_grant_scope(principal: PlatformPrincipal, permission_codes: list[str]) -> None:
    """A platform admin may only grant platform permissions they hold."""
    missing = [c for c in permission_codes if not principal.has(c)]
    if missing:
        raise Forbidden(f"Cannot grant permissions you do not hold: {', '.join(missing)}")
