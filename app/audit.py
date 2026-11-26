"""Audit logging.

Every security-relevant event is written to ``audit_logs`` with organization,
actor, action, resource, timestamp, outcome, and metadata. Audit rows are
append-only: there is no update/delete path anywhere in the application,
and the database RLS policy set contains no UPDATE or DELETE policy for
``audit_logs``.

Audit actions are namespaced ``<domain>.<verb>``, e.g. ``auth.login``.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLog

# --- Action catalogue ----------------------------------------------------

AUTH_LOGIN = "auth.login"
AUTH_LOGIN_FAILED = "auth.login_failed"
AUTH_LOGOUT = "auth.logout"
AUTH_MFA_ENROLLED = "auth.mfa_enrolled"
AUTH_MFA_FAILED = "auth.mfa_failed"
AUTH_PASSWORD_RESET_REQUESTED = "auth.password_reset_requested"
AUTH_PASSWORD_RESET_COMPLETED = "auth.password_reset_completed"
AUTH_TOKEN_REFRESHED = "auth.token_refreshed"
AUTH_SESSION_REVOKED = "auth.session_revoked"
AUTHZ_DENIED = "authz.denied"

ORG_CREATED = "org.created"
ORG_UPDATED = "org.updated"
ORG_SWITCHED = "org.switched"

MEMBERSHIP_INVITED = "membership.invited"
MEMBERSHIP_ACCEPTED = "membership.accepted"
MEMBERSHIP_REMOVED = "membership.removed"
MEMBERSHIP_SUSPENDED = "membership.suspended"

ROLE_CREATED = "role.created"
ROLE_UPDATED = "role.updated"
ROLE_DELETED = "role.deleted"
ROLE_ASSIGNED = "role.assigned"
ROLE_REVOKED = "role.revoked"
PERMISSIONS_CHANGED = "role.permissions_changed"

INVITATION_CREATED = "invitation.created"
INVITATION_REVOKED = "invitation.revoked"

TICKET_CREATED = "ticket.created"
TICKET_UPDATED = "ticket.updated"

# --- Platform domain ------------------------------------------------------
# Platform audit events live in platform_audit_logs (append-only, like the
# org log) and use the same "<domain>.<verb>" shape with a platform prefix.

PLATFORM_AUTH_LOGIN = "platform.auth.login"
PLATFORM_AUTH_LOGIN_FAILED = "platform.auth.login_failed"
PLATFORM_AUTH_LOGOUT = "platform.auth.logout"
PLATFORM_AUTH_MFA_ENROLLED = "platform.auth.mfa_enrolled"
PLATFORM_AUTH_MFA_FAILED = "platform.auth.mfa_failed"
PLATFORM_AUTH_TOKEN_REFRESHED = "platform.auth.token_refreshed"

PLATFORM_ADMIN_CREATED = "platform.admin.created"
PLATFORM_ADMIN_SUSPENDED = "platform.admin.suspended"
PLATFORM_ADMIN_REACTIVATED = "platform.admin.reactivated"

PLATFORM_ROLE_CREATED = "platform.role.created"
PLATFORM_ROLE_UPDATED = "platform.role.updated"
PLATFORM_ROLE_DELETED = "platform.role.deleted"
PLATFORM_ROLE_ASSIGNED = "platform.role.assigned"
PLATFORM_ROLE_REVOKED = "platform.role.revoked"
PLATFORM_ROLE_PERMISSIONS_CHANGED = "platform.role.permissions_changed"

PLATFORM_SUPPORT_GRANT_REQUESTED = "platform.support_grant.requested"
PLATFORM_SUPPORT_GRANT_APPROVED = "platform.support_grant.approved"
PLATFORM_SUPPORT_GRANT_REVOKED = "platform.support_grant.revoked"

PLATFORM_TENANT_READ = "platform.tenant_read"
PLATFORM_TENANT_USERS_READ = "platform.tenant_users_read"


def write_audit(
    session: Session,
    *,
    organization_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str = "success",
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one audit event. The caller commits the transaction."""
    entry = AuditLog(
        organization_id=organization_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        meta=metadata or {},
    )
    session.add(entry)
    return entry
