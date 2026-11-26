"""Employee self-service portal helpers.

The portal is a SEPARATE session type from the org domain: a portal
login mints a ``portal_access`` JWT (60-minute expiry) and a
``portal_sessions`` row holding only the SHA-256 hash of the token.
An org ``access`` token can never authenticate a portal endpoint and
a portal token can never authenticate an org endpoint — the JWT
``type`` claim is checked on decode in both directions.

Token issuance lives here (not in app.security, which is a shared file
owned by the auth workstream): the claim shape mirrors
``issue_platform_access_token``.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import as_uuid, set_rls_context
from app.models.itsm import RequestCounter
from app.models.platform import Membership, Organization, User
from app.models.rbac import Permission, RolePermission, UserRole
from app.models.ticket import TicketCounter
from app.security import hash_token, new_opaque_token, verify_password
from app.services import auth_service

PORTAL_TOKEN_MINUTES = 60


def issue_portal_access_token(user_id, org_id, email: str) -> str:
    """Mint a ``portal_access`` JWT (60 minutes).

    A random ``jti`` makes every token unique: without it, two logins
    in the same second would mint byte-identical JWTs, and the
    ``portal_sessions.token_hash`` unique constraint would reject the
    second login.
    """
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": str(user_id),
        "org": str(org_id),
        "email": email,
        "type": "portal_access",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + PORTAL_TOKEN_MINUTES * 60,
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def authenticate_portal_user(session: Session, email: str, password: str) -> tuple[dict, Membership]:
    """Authenticate by email/password via the auth service lookup path.

    Returns (user_row, membership). The caller picks the organization:
    an explicit org is honoured only with an active membership there,
    otherwise the earliest active membership wins. MFA-enabled users
    cannot use the portal password flow — they must complete MFA via
    the main login (the portal has no MFA challenge step).
    Raises ValueError on bad credentials / no membership.
    """
    user = auth_service._lookup_user_by_email(session, email)
    if user is None or not user["is_active"] or not verify_password(password, user["password_hash"]):
        raise ValueError("Invalid email or password")
    if user["mfa_enabled"]:
        raise ValueError("MFA is enabled — complete MFA via the main login")
    user_id = as_uuid(user["id"])
    set_rls_context(session, None, user_id)
    memberships = list(
        session.execute(
            select(Membership)
            .where(Membership.user_id == user_id, Membership.status == "active")
            .order_by(Membership.created_at)
        ).scalars()
    )
    if not memberships:
        raise ValueError("No active membership in any organization")
    return user, memberships[0]


def load_portal_permissions(session: Session, user_id: uuid.UUID, org_id: uuid.UUID) -> set[str]:
    """Org permissions for (user, org) — same join as deps._load_permissions."""
    rows = session.execute(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id, UserRole.organization_id == org_id)
    ).all()
    return {r[0] for r in rows}


def new_portal_token() -> str:
    """Opaque token whose SHA-256 hash is stored in portal_sessions."""
    return new_opaque_token()


def portal_token_hash(token: str) -> str:
    return hash_token(token)


def next_ticket_number(session: Session, org_id: uuid.UUID) -> str:
    """Per-org ticket number (INC-000001, ...) via a row-locked counter.

    Mirrors routers/tickets._next_number (the router is not imported —
    services must not depend on routers).
    """
    counter = session.execute(
        select(TicketCounter).where(TicketCounter.organization_id == org_id).with_for_update()
    ).scalar_one_or_none()
    if counter is None:
        counter = TicketCounter(organization_id=org_id, last_number=0)
        session.add(counter)
        session.flush()
    counter.last_number += 1
    return f"INC-{counter.last_number:06d}"


def next_request_number(session: Session, org_id: uuid.UUID) -> str:
    """Per-org service-request number (REQ-000001, ...) via a row-locked counter."""
    counter = session.execute(
        select(RequestCounter).where(RequestCounter.organization_id == org_id).with_for_update()
    ).scalar_one_or_none()
    if counter is None:
        counter = RequestCounter(organization_id=org_id, last_number=0)
        session.add(counter)
        session.flush()
    counter.last_number += 1
    return f"REQ-{counter.last_number:06d}"


def org_branding(session: Session, org_id: uuid.UUID) -> dict:
    """Branding snapshot for the portal: organizations.settings['branding']."""
    org = session.get(Organization, org_id)
    if org is None:
        return {}
    settings = org.settings or {}
    return dict(settings.get("branding", {})) if isinstance(settings, dict) else {}


@dataclass
class PortalPrincipal:
    """The authenticated portal caller, with their resolved organization."""

    user_id: uuid.UUID
    email: str
    organization_id: uuid.UUID
    organization_slug: str
    session_id: uuid.UUID
    permissions: set[str] = field(default_factory=set)

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def user_profile(session: Session, user_id: uuid.UUID) -> dict | None:
    user = session.get(User, user_id)
    if user is None:
        return None
    return {"id": str(user.id), "email": user.email, "full_name": user.full_name}


def _now() -> datetime:
    return datetime.now(timezone.utc)
