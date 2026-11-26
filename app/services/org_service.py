"""Organization service: provisioning, membership, invitations, policy.

Provisioning a new organization:
  1. Create the organization row (slug must be unique).
  2. Create the owner membership for the provisioning user.
  3. Seed the six role templates as organization roles.
  4. Grant the owner the Administrator role.
  5. Audit the creation.

Least-privilege policy lives in ``organizations.settings`` under the
``least_privilege_policy`` key:
  - enforce_least_privilege (bool, default True)
  - require_approval_for_elevated (bool, default True)
  - periodic_access_review (bool, default True)
  - access_expiration (bool, default False)
  - access_review_schedule (str, default "90d")
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.config import get_settings
from app.database import set_rls_context
from app.models.access import AccessReview
from app.models.auth import Invitation, InvitationRole
from app.models.platform import Membership, Organization, User
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.permissions import ROLE_TEMPLATES, resolve_template_permissions
from app.security import hash_token, new_opaque_token
from app.services import email as email_service

UTC = timezone.utc

DEFAULT_POLICY = {
    "enforce_least_privilege": True,
    "require_approval_for_elevated": True,
    "periodic_access_review": True,
    "access_expiration": False,
    "access_review_schedule": "90d",
}

ELEVATED_LEVELS = {"Privileged", "Full Access"}


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "org"


def seed_org_roles(session: Session, org_id: uuid.UUID) -> dict[str, Role]:
    """Create the eight role templates as organization roles. Returns by name."""
    perm_by_code = {p.code: p for p in session.execute(select(Permission)).scalars()}
    created: dict[str, Role] = {}
    for name, template in ROLE_TEMPLATES.items():
        role = Role(
            organization_id=org_id,
            name=name,
            description=template["description"],
            access_level=template["access_level"],
            is_system=True,
        )
        session.add(role)
        session.flush()
        for code in resolve_template_permissions(template):
            perm = perm_by_code.get(code)
            if perm is not None:
                session.add(RolePermission(role_id=role.id, permission_id=perm.id, organization_id=org_id))
        created[name] = role
    return created


def create_organization(session: Session, owner: User, name: str, slug: str | None = None) -> Organization:
    slug = slug or _slugify(name)
    existing = session.execute(select(Organization).where(Organization.slug == slug)).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"Organization slug '{slug}' is already taken")
    org = Organization(
        name=name,
        slug=slug,
        settings={"least_privilege_policy": dict(DEFAULT_POLICY)},
        created_by_id=owner.id,
    )
    session.add(org)
    session.flush()
    # Scope the transaction to the new org before inserting its membership,
    # roles, and audit row: those tables' RLS policies require the org
    # context to match the row's organization_id.
    set_rls_context(session, org.id, owner.id)
    session.add(Membership(organization_id=org.id, user_id=owner.id, status="active", is_owner=True))
    roles = seed_org_roles(session, org.id)
    admin_role = roles["Organization Administrator"]
    session.add(UserRole(organization_id=org.id, user_id=owner.id, role_id=admin_role.id, granted_by_id=owner.id))
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=owner.id,
        action=audit_mod.ORG_CREATED,
        resource_type="organization",
        resource_id=str(org.id),
        outcome="success",
        metadata={"name": name, "slug": slug},
    )
    return org


def get_policy(org: Organization) -> dict:
    settings = org.settings or {}
    policy = dict(DEFAULT_POLICY)
    policy.update(settings.get("least_privilege_policy", {}))
    return policy


def set_policy(session: Session, org: Organization, actor_id: uuid.UUID, policy: dict) -> dict:
    merged = get_policy(org)
    merged.update(policy)
    settings = dict(org.settings or {})
    settings["least_privilege_policy"] = merged
    org.settings = settings
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor_id,
        action=audit_mod.ORG_UPDATED,
        resource_type="organization",
        resource_id=str(org.id),
        outcome="success",
        metadata={"policy": merged},
    )
    return merged


def invite_technician(
    session: Session,
    org: Organization,
    inviter: User,
    email: str,
    role_ids: list[uuid.UUID],
) -> tuple[Invitation, str]:
    """Create an invitation. Returns (invitation, raw_token).

    The raw token is returned once so the caller can deliver it (email in
    production; the dev log records the accept URL without the token).
    Only the hash is stored.
    """
    settings = get_settings()
    roles = session.execute(select(Role).where(Role.id.in_(role_ids), Role.organization_id == org.id)).scalars()
    role_list = list(roles)
    if len(role_list) != len(role_ids):
        raise ValueError("One or more roles do not belong to this organization")
    token = new_opaque_token()
    invitation = Invitation(
        organization_id=org.id,
        email=email,
        token_hash=hash_token(token),
        invited_by_id=inviter.id,
        expires_at=datetime.now(UTC) + timedelta(days=settings.invitation_days),
    )
    session.add(invitation)
    session.flush()
    for role in role_list:
        session.add(InvitationRole(invitation_id=invitation.id, role_id=role.id, organization_id=org.id))
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=inviter.id,
        action=audit_mod.INVITATION_CREATED,
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome="success",
        metadata={"email": email, "roles": [r.name for r in role_list]},
    )
    email_service.send_invitation_email(email, org.name, "https://app.nullitsm.example/invite/accept")
    return invitation, token


def revoke_invitation(session: Session, org: Organization, actor_id: uuid.UUID, invitation_id: uuid.UUID) -> Invitation:
    invitation = session.get(Invitation, invitation_id)
    if invitation is None or invitation.organization_id != org.id:
        raise ValueError("Invitation not found")
    invitation.status = "revoked"
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor_id,
        action=audit_mod.INVITATION_REVOKED,
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome="success",
        metadata={"email": invitation.email},
    )
    return invitation


def list_members(session: Session, org_id: uuid.UUID) -> list[dict]:
    rows = session.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == org_id)
        .order_by(User.full_name)
    ).all()
    return [
        {
            "user_id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "status": m.status,
            "is_owner": m.is_owner,
            "expires_at": m.expires_at.isoformat() if m.expires_at else None,
            "joined_at": m.created_at.isoformat(),
        }
        for m, user in rows
    ]


def update_membership_status(
    session: Session, org: Organization, actor_id: uuid.UUID, user_id: uuid.UUID, status: str
) -> Membership:
    if status not in ("active", "suspended"):
        raise ValueError("status must be 'active' or 'suspended'")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org.id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise ValueError("Membership not found")
    if membership.is_owner and status == "suspended":
        raise ValueError("The organization owner cannot be suspended")
    membership.status = status
    action = audit_mod.MEMBERSHIP_SUSPENDED if status == "suspended" else audit_mod.MEMBERSHIP_ACCEPTED
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor_id,
        action=action,
        resource_type="membership",
        resource_id=str(membership.id),
        outcome="success",
        metadata={"user_id": str(user_id), "status": status},
    )
    return membership


def start_access_review(session: Session, org: Organization, actor_id: uuid.UUID) -> AccessReview:
    """Create a periodic access review with a snapshot of current access."""
    members = list_members(session, org.id)
    role_rows = session.execute(
        select(UserRole, Role).join(Role, Role.id == UserRole.role_id).where(UserRole.organization_id == org.id)
    ).all()
    snapshot = {
        "members": members,
        "role_assignments": [
            {"user_id": str(ur.user_id), "role": role.name, "access_level": role.access_level} for ur, role in role_rows
        ],
    }
    review = AccessReview(organization_id=org.id, initiated_by_id=actor_id, snapshot=snapshot)
    session.add(review)
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor_id,
        action="access.review_started",
        resource_type="access_review",
        resource_id=str(review.id),
        outcome="success",
        metadata={"members": len(members)},
    )
    return review


def complete_access_review(
    session: Session, org: Organization, actor_id: uuid.UUID, review_id: uuid.UUID
) -> AccessReview:
    review = session.get(AccessReview, review_id)
    if review is None or review.organization_id != org.id:
        raise ValueError("Access review not found")
    review.status = "completed"
    review.completed_at = datetime.now(UTC)
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor_id,
        action="access.review_completed",
        resource_type="access_review",
        resource_id=str(review.id),
        outcome="success",
    )
    return review
