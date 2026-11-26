"""Role service: roles, permissions, assignments, elevated-access approvals.

Grant-scope rule (enforced everywhere a permission is granted):
an actor may only grant permissions they themselves hold. This is what
stops an administrator from granting permissions beyond their authorized
scope — the check runs on role creation, permission configuration, role
assignment, and invitation roles.

Elevated access: when the organization's least-privilege policy requires
approval for elevated access, assigning a Privileged/Full Access role does
NOT grant immediately. It creates a pending AccessApproval that an
administrator must approve; approval then performs the assignment.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import check_grant_scope
from app.models.access import AccessApproval
from app.models.platform import Membership, Organization
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.services.org_service import ELEVATED_LEVELS, get_policy

UTC = timezone.utc


def list_roles(session: Session, org_id: uuid.UUID) -> list[Role]:
    return list(session.execute(select(Role).where(Role.organization_id == org_id).order_by(Role.name)).scalars())


def get_role(session: Session, org_id: uuid.UUID, role_id: uuid.UUID) -> Role | None:
    return session.execute(select(Role).where(Role.id == role_id, Role.organization_id == org_id)).scalar_one_or_none()


def role_permission_codes(session: Session, role_id: uuid.UUID) -> list[str]:
    rows = session.execute(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role_id)
    ).all()
    return [r[0] for r in rows]


def create_role(
    session: Session,
    org: Organization,
    actor,
    name: str,
    description: str,
    access_level: str,
    permission_codes: list[str],
) -> Role:
    if access_level not in ("Full Access", "Privileged", "Least Privilege", "Read-Only"):
        raise ValueError("Invalid access_level")
    check_grant_scope(actor, permission_codes)
    existing = session.execute(
        select(Role).where(Role.organization_id == org.id, Role.name == name)
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"Role '{name}' already exists in this organization")
    role = Role(organization_id=org.id, name=name, description=description, access_level=access_level)
    session.add(role)
    session.flush()
    _set_role_permissions(session, org.id, role, permission_codes)
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor.user_id,
        action=audit_mod.ROLE_CREATED,
        resource_type="role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"name": name, "access_level": access_level, "permissions": permission_codes},
    )
    return role


def _set_role_permissions(session: Session, org_id: uuid.UUID, role: Role, permission_codes: list[str]) -> None:
    # Defense in depth: the organization permission catalog contains no
    # platform:* code, so an org role can never grant platform access.
    # Reject such codes explicitly (rather than relying only on the
    # "unknown permission" check below) so the boundary is visible.
    platform_codes = [c for c in permission_codes if c.startswith("platform:")]
    if platform_codes:
        raise ValueError(f"Organization roles cannot grant platform permissions: {', '.join(platform_codes)}")
    perms = session.execute(select(Permission).where(Permission.code.in_(permission_codes))).scalars()
    perm_by_code = {p.code: p for p in perms}
    unknown = [c for c in permission_codes if c not in perm_by_code]
    if unknown:
        raise ValueError(f"Unknown permissions: {', '.join(unknown)}")
    session.execute(RolePermission.__table__.delete().where(RolePermission.role_id == role.id))
    for code in permission_codes:
        session.add(RolePermission(role_id=role.id, permission_id=perm_by_code[code].id, organization_id=org_id))


def configure_role_permissions(
    session: Session, org: Organization, actor, role: Role, permission_codes: list[str]
) -> Role:
    check_grant_scope(actor, permission_codes)
    _set_role_permissions(session, org.id, role, permission_codes)
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor.user_id,
        action=audit_mod.PERMISSIONS_CHANGED,
        resource_type="role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"role": role.name, "permissions": permission_codes},
    )
    return role


def update_role(
    session: Session, org: Organization, actor, role: Role, description: str | None, access_level: str | None
) -> Role:
    if description is not None:
        role.description = description
    if access_level is not None:
        if access_level not in ("Full Access", "Privileged", "Least Privilege", "Read-Only"):
            raise ValueError("Invalid access_level")
        role.access_level = access_level
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor.user_id,
        action=audit_mod.ROLE_UPDATED,
        resource_type="role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"name": role.name},
    )
    return role


def delete_role(session: Session, org: Organization, actor, role: Role) -> None:
    if role.is_system:
        raise ValueError("System roles cannot be deleted")
    assigned = session.execute(select(UserRole).where(UserRole.role_id == role.id)).scalars().first()
    if assigned is not None:
        raise ValueError("Role is assigned to users; revoke it first")
    session.delete(role)
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor.user_id,
        action=audit_mod.ROLE_DELETED,
        resource_type="role",
        resource_id=str(role.id),
        outcome="success",
        metadata={"name": role.name},
    )


def _assign_role_row(
    session: Session, org_id: uuid.UUID, user_id: uuid.UUID, role_id: uuid.UUID, granted_by_id: uuid.UUID
) -> UserRole:
    existing = session.execute(
        select(UserRole).where(
            UserRole.organization_id == org_id,
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    row = UserRole(organization_id=org_id, user_id=user_id, role_id=role_id, granted_by_id=granted_by_id)
    session.add(row)
    return row


def assign_role(session: Session, org: Organization, actor, user_id: uuid.UUID, role: Role) -> dict:
    """Assign a role. Returns {'status': 'assigned'} or
    {'status': 'pending_approval', 'approval_id': ...} when the org policy
    requires approval for elevated access."""
    membership = session.execute(
        select(Membership).where(
            Membership.organization_id == org.id, Membership.user_id == user_id, Membership.status == "active"
        )
    ).scalar_one_or_none()
    if membership is None:
        raise ValueError("User is not an active member of this organization")
    codes = role_permission_codes(session, role.id)
    check_grant_scope(actor, codes)
    policy = get_policy(org)
    if policy.get("require_approval_for_elevated") and role.access_level in ELEVATED_LEVELS:
        approval = AccessApproval(
            organization_id=org.id,
            requested_by_id=actor.user_id,
            target_user_id=user_id,
            role_id=role.id,
        )
        session.add(approval)
        session.flush()
        audit_mod.write_audit(
            session,
            organization_id=org.id,
            actor_id=actor.user_id,
            action="access.approval_requested",
            resource_type="access_approval",
            resource_id=str(approval.id),
            outcome="success",
            metadata={"user_id": str(user_id), "role": role.name},
        )
        return {"status": "pending_approval", "approval_id": str(approval.id)}
    _assign_role_row(session, org.id, user_id, role.id, actor.user_id)
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor.user_id,
        action=audit_mod.ROLE_ASSIGNED,
        resource_type="user_role",
        resource_id=str(user_id),
        outcome="success",
        metadata={"role": role.name},
    )
    return {"status": "assigned"}


def decide_approval(
    session: Session, org: Organization, actor, approval_id: uuid.UUID, approve: bool
) -> AccessApproval:
    approval = session.get(AccessApproval, approval_id)
    if approval is None or approval.organization_id != org.id:
        raise ValueError("Approval request not found")
    if approval.status != "pending":
        raise ValueError(f"Approval request is already {approval.status}")
    role = get_role(session, org.id, approval.role_id)
    if role is None:
        raise ValueError("Role no longer exists")
    codes = role_permission_codes(session, role.id)
    check_grant_scope(actor, codes)
    approval.status = "approved" if approve else "denied"
    approval.decided_by_id = actor.user_id
    approval.decided_at = datetime.now(UTC)
    if approve:
        _assign_role_row(session, org.id, approval.target_user_id, role.id, actor.user_id)
        audit_mod.write_audit(
            session,
            organization_id=org.id,
            actor_id=actor.user_id,
            action=audit_mod.ROLE_ASSIGNED,
            resource_type="user_role",
            resource_id=str(approval.target_user_id),
            outcome="success",
            metadata={"role": role.name, "via_approval": str(approval.id)},
        )
    else:
        audit_mod.write_audit(
            session,
            organization_id=org.id,
            actor_id=actor.user_id,
            action="access.approval_denied",
            resource_type="access_approval",
            resource_id=str(approval.id),
            outcome="success",
            metadata={"role": role.name},
        )
    return approval


def revoke_role(session: Session, org: Organization, actor, user_id: uuid.UUID, role: Role) -> None:
    row = session.execute(
        select(UserRole).where(
            UserRole.organization_id == org.id,
            UserRole.user_id == user_id,
            UserRole.role_id == role.id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise ValueError("Role is not assigned to this user")
    # Never revoke the owner's last Organization Administrator role via the API.
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org.id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is not None and membership.is_owner and role.name == "Organization Administrator":
        remaining_admins = (
            session.execute(
                select(UserRole)
                .join(Membership, Membership.user_id == UserRole.user_id)
                .where(
                    UserRole.organization_id == org.id,
                    UserRole.role_id == role.id,
                    Membership.is_owner.is_(True),
                    UserRole.user_id != user_id,
                )
            )
            .scalars()
            .first()
        )
        if remaining_admins is None:
            raise ValueError("Cannot revoke the last owner's Organization Administrator role")
    session.delete(row)
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=actor.user_id,
        action=audit_mod.ROLE_REVOKED,
        resource_type="user_role",
        resource_id=str(user_id),
        outcome="success",
        metadata={"role": role.name},
    )


def user_roles(session: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> list[Role]:
    rows = session.execute(
        select(Role)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.organization_id == org_id, UserRole.user_id == user_id)
    ).scalars()
    return list(rows)
