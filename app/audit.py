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
TICKET_COMMENTED = "ticket.commented"

# --- Phase 2: ITSM engine --------------------------------------------------
REQUEST_CREATED = "request.created"
REQUEST_UPDATED = "request.updated"
REQUEST_APPROVED = "request.approved"
REQUEST_FULFILLED = "request.fulfilled"

CATALOG_ITEM_CREATED = "catalog.item_created"
CATALOG_ITEM_UPDATED = "catalog.item_updated"
CATALOG_CATEGORY_CREATED = "catalog.category_created"
CATALOG_CATEGORY_UPDATED = "catalog.category_updated"
CATALOG_CATEGORY_DELETED = "catalog.category_deleted"

KB_ARTICLE_CREATED = "knowledge.article_created"
KB_ARTICLE_PUBLISHED = "knowledge.article_published"
KB_ARTICLE_UPDATED = "knowledge.article_updated"
KB_FEEDBACK_CREATED = "knowledge.feedback_created"

CHANGE_CREATED = "change.created"
CHANGE_UPDATED = "change.updated"
CHANGE_APPROVED = "change.approved"
CHANGE_REJECTED = "change.rejected"
CHANGE_EXECUTED = "change.executed"

PROBLEM_CREATED = "problem.created"
PROBLEM_UPDATED = "problem.updated"
KNOWN_ERROR_CREATED = "problem.known_error_created"
KNOWN_ERROR_UPDATED = "problem.known_error_updated"
KNOWN_ERROR_DELETED = "problem.known_error_deleted"
KNOWN_ERROR_LINKED = "problem.known_error_linked"

NOTIFICATION_CREATED = "notification.created"
NOTIFICATION_READ = "notification.read"
NOTIFICATION_READ_ALL = "notification.read_all"

TICKET_COMMENTED = "ticket.commented"
TICKET_ATTACHMENT_CREATED = "ticket.attachment_created"
TICKET_LINK_CREATED = "ticket.link_created"
TICKET_LINK_DELETED = "ticket.link_deleted"

TEMPLATE_CREATED = "template.created"
TEMPLATE_UPDATED = "template.updated"
TEMPLATE_DELETED = "template.deleted"
RECURRING_CREATED = "template.recurring_created"
RECURRING_UPDATED = "template.recurring_updated"
RECURRING_DELETED = "template.recurring_deleted"

SURVEY_CREATED = "survey.created"
SURVEY_UPDATED = "survey.updated"
SURVEY_DELETED = "survey.deleted"
SURVEY_RESPONSE_SUBMITTED = "survey.response_submitted"

INCIDENT_DECLARED = "incident.declared"
INCIDENT_UPDATED = "incident.updated"

# --- Phase 2: SLA -----------------------------------------------------------
SLA_POLICY_CREATED = "sla.policy_created"
SLA_POLICY_UPDATED = "sla.policy_updated"
SLA_BREACH_DETECTED = "sla.breach_detected"
SLA_BREACH_ACKNOWLEDGED = "sla.breach_acknowledged"
SLA_ESCALATED = "sla.escalated"

# --- Phase 2: email / portal / import-export -------------------------------
EMAIL_MESSAGE_INGESTED = "email.message_ingested"
EMAIL_REPLY_SENT = "email.reply_sent"
EMAIL_TRIAGED = "email.triaged"
PORTAL_LOGIN = "portal.login"
IMPORT_STARTED = "import.started"
IMPORT_COMPLETED = "import.completed"
IMPORT_FAILED = "import.failed"
EXPORT_CREATED = "export.created"
EXPORT_COMPLETED = "export.completed"

# --- Phase 2: identity / directory / assets --------------------------------
IDP_CREATED = "identity.idp_created"
IDP_UPDATED = "identity.idp_updated"
SCIM_SYNC_COMPLETED = "identity.scim_sync_completed"
DIRECTORY_SYNC_COMPLETED = "identity.directory_sync_completed"
ACCESS_CERTIFICATION_CREATED = "identity.certification_created"
ACCESS_CERTIFICATION_DECIDED = "identity.certification_decided"
TEMP_ACCESS_GRANTED = "identity.temp_access_granted"
TEMP_ACCESS_REVOKED = "identity.temp_access_revoked"
SERVICE_ACCOUNT_CREATED = "identity.service_account_created"
SERVICE_ACCOUNT_REVOKED = "identity.service_account_revoked"
API_CREDENTIAL_CREATED = "identity.api_credential_created"
API_CREDENTIAL_REVOKED = "identity.api_credential_revoked"

ASSET_CREATED = "asset.created"
ASSET_UPDATED = "asset.updated"
ASSET_ASSIGNED = "asset.assigned"
ASSET_RETURNED = "asset.returned"
ASSET_STATUS_CHANGED = "asset.status_changed"
LICENSE_CREATED = "license.created"
LICENSE_ASSIGNED = "license.assigned"
OFFBOARDING_COMPLETED = "asset.offboarding_completed"

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
