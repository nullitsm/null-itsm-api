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

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.config import get_settings
from app.database import set_rls_context
from app.models.access import AccessReview
from app.models.auth import Invitation, InvitationRole
from app.models.platform import Membership, Organization, User
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.models.registration import Department, Team
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


def _slug_exists(session: Session, slug: str) -> bool:
    """Slug uniqueness via the SECURITY DEFINER function: an ORM
    organizations SELECT is RLS-filtered, and at registration time the
    caller belongs to no org yet, so it would see nothing."""
    return bool(session.execute(text("SELECT org_slug_exists(:slug)"), {"slug": slug}).scalar())


def _unique_slug(session: Session, name: str) -> str:
    base = _slugify(name)
    slug = base
    counter = 2
    while _slug_exists(session, slug):
        slug = f"{base}-{counter}"
        counter += 1
    return slug


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
    if slug is not None:
        if _slug_exists(session, slug):
            raise ValueError(f"Organization slug '{slug}' is already taken")
    else:
        # Same name, second org: suffix the slug instead of failing.
        slug = _unique_slug(session, name)
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
    full_name: str = "",
    department: str = "",
    team: str = "",
) -> tuple[Invitation, str, str, "email_service.DeliveryResult"]:
    """Create an invitation. Returns (invitation, raw_token, accept_url, delivery).

    The raw token is returned once so the caller can deliver it (email in
    production; the dev outbox records it and the inviting admin sees the
    link in the API response for testing). Only the hash is stored.
    Single-use, bound to this email + org, expires in 48 hours.
    Duplicate pending invitations for the same email + org are rejected.
    The delivery result is accurate: ``delivered`` is True only when the
    provider accepted the message; a failed submission is returned, not
    hidden, so the API never claims an email went out when it did not.
    """
    settings = get_settings()
    roles = session.execute(select(Role).where(Role.id.in_(role_ids), Role.organization_id == org.id)).scalars()
    role_list = list(roles)
    if len(role_list) != len(role_ids):
        raise ValueError("One or more roles do not belong to this organization")
    email = email.strip().lower()
    # Expire any stale pending invitation for this email first: an expired
    # invitation keeps status 'pending' until something retires it, and the
    # at-most-one-pending invariant (partial unique index, migration 0018)
    # would otherwise block a legitimate re-invite after expiry.
    stale = session.execute(
        select(Invitation).where(
            Invitation.organization_id == org.id,
            Invitation.email == email,
            Invitation.status == "pending",
            Invitation.expires_at <= datetime.now(UTC),
        )
    ).scalar_one_or_none()
    if stale is not None:
        stale.status = "expired"
        session.flush()
        audit_mod.write_audit(
            session,
            organization_id=org.id,
            actor_id=inviter.id,
            action=audit_mod.INVITATION_EXPIRED,
            resource_type="invitation",
            resource_id=str(stale.id),
            outcome="success",
            metadata={"email": email},
        )
    existing = session.execute(
        select(Invitation).where(
            Invitation.organization_id == org.id,
            Invitation.email == email,
            Invitation.status == "pending",
            Invitation.expires_at > datetime.now(UTC),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError("A pending invitation already exists for this email in this organization")
    token = new_opaque_token()
    invitation = Invitation(
        organization_id=org.id,
        email=email,
        full_name=full_name,
        department=department,
        team=team,
        token_hash=hash_token(token),
        invited_by_id=inviter.id,
        expires_at=datetime.now(UTC) + timedelta(days=settings.invitation_days),
    )
    session.add(invitation)
    session.flush()
    for role in role_list:
        session.add(InvitationRole(invitation_id=invitation.id, role_id=role.id, organization_id=org.id))
    accept_url = f"{settings.app_url}/invite/accept?token={token}"
    delivery = email_service.send_invitation_email(
        email,
        org.name,
        accept_url,
        session,
        org.id,
        recipient_name=full_name,
        role_names=[r.name for r in role_list],
        inviter_name=inviter.full_name,
        org_invitation_id=invitation.id,
        created_by_id=inviter.id,
    )
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=inviter.id,
        action=audit_mod.INVITATION_CREATED,
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome="success",
        metadata={
            "email": email,
            "roles": [r.name for r in role_list],
            "delivery": {
                "status": "sent" if delivery.delivered else ("dev_recorded" if delivery.dev_recorded else "failed"),
                "provider": delivery.provider,
                "provider_message_id": delivery.provider_message_id,
                "error": delivery.error,
            },
        },
    )
    return invitation, token, accept_url, delivery


def resend_invitation(
    session: Session, org: Organization, actor_id: uuid.UUID, invitation_id: uuid.UUID
) -> tuple[Invitation, str, str, "email_service.DeliveryResult"]:
    """Regenerate a pending invitation's token + 48h expiry and re-send.

    The old link is invalidated (its hash is replaced). Only pending
    invitations can be resent. Returns (invitation, token, accept_url, delivery).
    """
    settings = get_settings()
    invitation = session.get(Invitation, invitation_id)
    if invitation is None or invitation.organization_id != org.id:
        raise ValueError("Invitation not found")
    if invitation.status != "pending":
        raise ValueError("Only a pending invitation can be resent")
    token = new_opaque_token()
    invitation.token_hash = hash_token(token)
    invitation.expires_at = datetime.now(UTC) + timedelta(days=settings.invitation_days)
    accept_url = f"{settings.app_url}/invite/accept?token={token}"
    inviter = session.get(User, actor_id)
    role_names = [
        r.name
        for r in session.execute(
            select(Role)
            .join(InvitationRole, InvitationRole.role_id == Role.id)
            .where(InvitationRole.invitation_id == invitation.id)
        ).scalars()
    ]
    delivery = email_service.send_invitation_email(
        invitation.email,
        org.name,
        accept_url,
        session,
        org.id,
        recipient_name=invitation.full_name,
        role_names=role_names,
        inviter_name=inviter.full_name if inviter is not None else "",
        org_invitation_id=invitation.id,
        created_by_id=actor_id,
    )
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor_id,
        action=audit_mod.INVITATION_RESENT,
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome="success",
        metadata={
            "email": invitation.email,
            "delivery": {
                "status": "sent" if delivery.delivered else ("dev_recorded" if delivery.dev_recorded else "failed"),
                "provider": delivery.provider,
                "provider_message_id": delivery.provider_message_id,
                "error": delivery.error,
            },
        },
    )
    return invitation, token, accept_url, delivery


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
    if status not in ("active", "suspended", "deactivated"):
        raise ValueError("status must be 'active', 'suspended' or 'deactivated'")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org.id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise ValueError("Membership not found")
    if membership.is_owner and status == "suspended":
        raise ValueError("The organization owner cannot be suspended")
    if membership.is_owner and status == "deactivated":
        raise ValueError("The organization owner cannot be removed")
    if status == "deactivated" and _is_last_org_admin(session, org.id, user_id):
        raise ValueError("Cannot remove the last Organization Administrator")
    membership.status = status
    action = {
        "suspended": audit_mod.MEMBERSHIP_SUSPENDED,
        "deactivated": audit_mod.MEMBERSHIP_REMOVED,
    }.get(status, audit_mod.MEMBERSHIP_ACCEPTED)
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


def _is_last_org_admin(session: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """True when the user holds the Organization Administrator role and
    no other ACTIVE member holds it. A member who holds no admin role
    is never "the last admin"."""
    admin_role = session.execute(
        select(Role).where(Role.organization_id == org_id, Role.name == "Organization Administrator")
    ).scalar_one_or_none()
    if admin_role is None:
        return False
    holds_admin = session.execute(
        select(UserRole).where(
            UserRole.organization_id == org_id,
            UserRole.user_id == user_id,
            UserRole.role_id == admin_role.id,
        )
    ).scalar_one_or_none()
    if holds_admin is None:
        return False
    others = session.execute(
        select(UserRole)
        .join(Membership, Membership.user_id == UserRole.user_id)
        .where(
            UserRole.organization_id == org_id,
            UserRole.role_id == admin_role.id,
            UserRole.user_id != user_id,
            Membership.organization_id == org_id,
            Membership.status == "active",
        )
    ).all()
    return len(others) == 0


def remove_technician(
    session: Session,
    org: Organization,
    actor_id: uuid.UUID,
    user_id: uuid.UUID,
    reason: str | None = None,
) -> dict:
    """Remove a technician from the organization — deactivate, never delete.

    - The membership becomes "deactivated"; the user record and all
      audit history are preserved, and re-adding requires a fresh
      invitation. Access ends immediately: every request re-checks for
      an active membership, and revoked sessions cannot refresh.
    - The organization owner cannot be removed, and neither can the
      last Organization Administrator.
    - Any pending invitation for the user's email in this org is
      cancelled (revoked).
    - Assigned assets/endpoints go through the Phase 2 offboarding
      flow (``asset_service.offboard_user`` with target "deactivated"):
      one recovery ticket per assigned asset, assets to in_repair with
      a lifecycle event, sessions and temporary grants revoked.
    - The removal is audited (MEMBERSHIP_REMOVED) with actor, target,
      reason and the offboarding report.

    An admin removing themselves is allowed when another admin remains;
    the last-admin guard is what protects the org, not the actor's
    identity. Returns the removal report for the API response.
    """
    from app.services import asset_service

    membership = session.execute(
        select(Membership).where(Membership.organization_id == org.id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise ValueError("Membership not found")
    if membership.status == "deactivated":
        raise ValueError("This member has already been removed")
    if membership.is_owner:
        raise ValueError("The organization owner cannot be removed")
    if _is_last_org_admin(session, org.id, user_id):
        raise ValueError("Cannot remove the last Organization Administrator")
    user = session.get(User, user_id)
    if user is None:
        raise ValueError("User not found")

    # Cancel any pending invitation for this email in the org (a
    # re-invite sent after the member had already accepted one).
    cancelled: list[str] = []
    pending = (
        session.execute(
            select(Invitation).where(
                Invitation.organization_id == org.id,
                Invitation.email == user.email,
                Invitation.status == "pending",
            )
        )
        .scalars()
        .all()
    )
    for inv in pending:
        inv.status = "revoked"
        cancelled.append(str(inv.id))
        audit_mod.write_audit(
            session,
            organization_id=org.id,
            actor_id=actor_id,
            action=audit_mod.INVITATION_REVOKED,
            resource_type="invitation",
            resource_id=str(inv.id),
            outcome="success",
            metadata={"email": inv.email, "reason": "member removed"},
        )

    report = asset_service.offboard_user(session, org.id, user_id, actor_id, target_status="deactivated")

    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor_id,
        action=audit_mod.MEMBERSHIP_REMOVED,
        resource_type="membership",
        resource_id=str(membership.id),
        outcome="success",
        metadata={
            "user_id": str(user_id),
            "email": user.email,
            "reason": reason or "",
            "invitations_cancelled": cancelled,
            "assets_recovered": report["assets_recovered"],
            "tickets_created": report["tickets_created"],
            "sessions_revoked": report["sessions_revoked"],
            "temp_grants_revoked": report["temp_grants_revoked"],
        },
    )
    return {
        "user_id": str(user_id),
        "email": user.email,
        "full_name": user.full_name,
        "membership_status": "deactivated",
        "reason": reason or "",
        "invitations_cancelled": cancelled,
        "assets_recovered": report["assets_recovered"],
        "tickets_created": report["tickets_created"],
        "sessions_revoked": report["sessions_revoked"],
        "temp_grants_revoked": report["temp_grants_revoked"],
    }


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


# --- Departments & teams --------------------------------------------------


DEFAULT_DEPARTMENTS = ["IT Operations", "Service Desk", "Security"]


def create_default_departments(session: Session, org_id: uuid.UUID) -> list[Department]:
    """Create the default departments for a newly registered org."""
    return [create_department(session, org_id, name) for name in DEFAULT_DEPARTMENTS]


def create_department(session: Session, org_id: uuid.UUID, name: str, description: str = "") -> Department:
    name = name.strip()
    if not name:
        raise ValueError("Department name is required")
    existing = session.execute(
        select(Department).where(Department.organization_id == org_id, Department.name == name)
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"Department '{name}' already exists")
    dept = Department(organization_id=org_id, name=name, description=description)
    session.add(dept)
    session.flush()
    return dept


def list_departments(session: Session, org_id: uuid.UUID) -> list[Department]:
    return list(
        session.execute(
            select(Department).where(Department.organization_id == org_id).order_by(Department.name)
        ).scalars()
    )


def create_team(
    session: Session,
    org_id: uuid.UUID,
    name: str,
    department_id: uuid.UUID | None = None,
    description: str = "",
) -> Team:
    name = name.strip()
    if not name:
        raise ValueError("Team name is required")
    if department_id is not None:
        dept = session.get(Department, department_id)
        if dept is None or dept.organization_id != org_id:
            raise ValueError("Department does not belong to this organization")
    existing = session.execute(
        select(Team).where(
            Team.organization_id == org_id,
            Team.department_id == department_id,
            Team.name == name,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"Team '{name}' already exists in this department")
    team = Team(organization_id=org_id, department_id=department_id, name=name, description=description)
    session.add(team)
    session.flush()
    return team


def list_teams(session: Session, org_id: uuid.UUID, department_id: uuid.UUID | None = None) -> list[Team]:
    query = select(Team).where(Team.organization_id == org_id)
    if department_id is not None:
        query = query.where(Team.department_id == department_id)
    return list(session.execute(query.order_by(Team.name)).scalars())
