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
ORG_REGISTERED = "org.registered"
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
INVITATION_ACCEPTED = "invitation.accepted"
INVITATION_RESENT = "invitation.resent"
INVITATION_REVOKED = "invitation.revoked"
INVITATION_EXPIRED = "invitation.expired"

PLATFORM_INVITATION_CREATED = "platform.invitation.created"
PLATFORM_INVITATION_ACCEPTED = "platform.invitation.accepted"
PLATFORM_INVITATION_RESENT = "platform.invitation.resent"
PLATFORM_INVITATION_REVOKED = "platform.invitation.revoked"
PLATFORM_INVITATION_EXPIRED = "platform.invitation.expired"

ONBOARDING_UPDATED = "onboarding.updated"
ONBOARDING_COMPLETED = "onboarding.completed"

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
EMAIL_DELIVERY_SENT = "email.delivery.sent"
EMAIL_DELIVERY_FAILED = "email.delivery.failed"
EMAIL_DELIVERY_DEV_RECORDED = "email.delivery.dev_recorded"
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


# --- Phase 3: agent / endpoints / patching / vulnerabilities ----------------
AGENT_ENROLLED = "agent.enrolled"
AGENT_JOB_ISSUED = "agent.job_issued"
AGENT_JOB_DELIVERED = "agent.job_delivered"
AGENT_JOB_RESULT = "agent.job_result"
AGENT_JOB_RESULT_UNAPPLIED = "agent.job_result_unapplied"
AGENT_JOB_RESULT_HANDLER_FAILED = "agent.job_result_handler_failed"
AGENT_RELEASE_CREATED = "agent.release_created"
AGENT_RELEASE_UPDATED = "agent.release_updated"
AGENT_RELEASE_DELETED = "agent.release_deleted"

ENDPOINT_ENROLLMENT_TOKEN_CREATED = "endpoint.enrollment_token_created"
ENDPOINT_ENROLLMENT_TOKEN_REVOKED = "endpoint.enrollment_token_revoked"
ENDPOINT_UPDATED = "endpoint.updated"
ENDPOINT_REVOKED = "endpoint.revoked"

PATCHING_SCAN_CREATED = "patching.scan_created"
PATCHING_DEPLOYMENT_CREATED = "patching.deployment_created"
PATCHING_DEPLOYMENT_APPROVED = "patching.deployment_approved"
PATCHING_DEPLOYMENT_EXECUTED = "patching.deployment_executed"
PATCHING_DEPLOYMENT_CANCELLED = "patching.deployment_cancelled"
PATCHING_DEPLOYMENT_VERIFIED = "patching.deployment_verified"

VULN_ENGINE_CREATED = "vulnerability.engine_created"
VULN_ENGINE_UPDATED = "vulnerability.engine_updated"
VULN_ENGINE_DELETED = "vulnerability.engine_deleted"
VULN_ENGINE_DEFAULT_SET = "vulnerability.engine_default_set"
VULN_SCAN_CREATED = "vulnerability.scan_created"
VULN_SCAN_RESULTS_IMPORTED = "vulnerability.scan_results_imported"

# --- CMDB (Phase 3) ---------------------------------------------------------
CMDB_ITEM_CREATED = "cmdb.item_created"
CMDB_ITEM_UPDATED = "cmdb.item_updated"
CMDB_ITEM_DELETED = "cmdb.item_deleted"
CMDB_RELATIONSHIP_CREATED = "cmdb.relationship_created"
CMDB_RELATIONSHIP_DELETED = "cmdb.relationship_deleted"

# --- Network operations (Phase 3) -------------------------------------------
NETWORK_DEVICE_CREATED = "network.device_created"
NETWORK_DEVICE_UPDATED = "network.device_updated"
NETWORK_DEVICE_DELETED = "network.device_deleted"
NETWORK_INTERFACE_CREATED = "network.interface_created"
NETWORK_INTERFACE_UPDATED = "network.interface_updated"
NETWORK_INTERFACE_DELETED = "network.interface_deleted"
NETWORK_TOPOLOGY_LINK_CREATED = "network.topology_link_created"
NETWORK_TOPOLOGY_LINK_DELETED = "network.topology_link_deleted"
NETWORK_SERVICE_DEPENDENCY_CREATED = "network.service_dependency_created"
NETWORK_SERVICE_DEPENDENCY_UPDATED = "network.service_dependency_updated"
NETWORK_SERVICE_DEPENDENCY_DELETED = "network.service_dependency_deleted"
NETWORK_METRICS_INGESTED = "network.metrics_ingested"
NETWORK_EVENT_CREATED = "network.event_created"
NETWORK_EVENT_ACKNOWLEDGED = "network.event_acknowledged"
NETWORK_CERTIFICATE_CREATED = "network.certificate_created"
NETWORK_CERTIFICATE_UPDATED = "network.certificate_updated"
NETWORK_CERTIFICATE_DELETED = "network.certificate_deleted"
NETWORK_DISCOVERY_COMPLETED = "network.discovery_completed"
VULN_SCAN_CANCELLED = "vulnerability.scan_cancelled"
VULN_SCAN_POLLED = "vulnerability.scan_polled"
VULN_FINDING_UPDATED = "vulnerability.finding_updated"
VULN_FINDING_VERIFICATION_STARTED = "vulnerability.finding_verification_started"
VULN_FINDING_VERIFIED = "vulnerability.finding_verified"
VULN_REMEDIATION_CREATED = "vulnerability.remediation_created"

# --- Phase 4: enterprise operations -----------------------------------------
WORKFLOW_CREATED = "workflow.created"
WORKFLOW_UPDATED = "workflow.updated"
WORKFLOW_DELETED = "workflow.deleted"
WORKFLOW_PUBLISHED = "workflow.published"
WORKFLOW_ARCHIVED = "workflow.archived"
WORKFLOW_RUN_STARTED = "workflow.run_started"
WORKFLOW_RUN_RETRIED = "workflow.run_retried"
AUTOMATION_RULE_CREATED = "automation.rule_created"
AUTOMATION_RULE_UPDATED = "automation.rule_updated"
AUTOMATION_RULE_DELETED = "automation.rule_deleted"
AUTOMATION_RULE_EVALUATED = "automation.rule_evaluated"
FORM_CREATED = "form.created"
FORM_UPDATED = "form.updated"
FORM_DELETED = "form.deleted"
FORM_FIELD_CREATED = "form.field_created"
FORM_FIELD_UPDATED = "form.field_updated"
FORM_FIELD_DELETED = "form.field_deleted"
FORM_VALUES_SUBMITTED = "form.values_submitted"
DASHBOARD_CREATED = "dashboard.created"
DASHBOARD_UPDATED = "dashboard.updated"
DASHBOARD_DELETED = "dashboard.deleted"
DASHBOARD_WIDGET_CREATED = "dashboard.widget_created"
DASHBOARD_WIDGET_UPDATED = "dashboard.widget_updated"
DASHBOARD_WIDGET_DELETED = "dashboard.widget_deleted"
REPORT_CREATED = "report.created"
REPORT_UPDATED = "report.updated"
REPORT_DELETED = "report.deleted"
REPORT_GENERATED = "report.generated"
REPORT_SCHEDULE_CREATED = "report.schedule_created"
REPORT_SCHEDULE_UPDATED = "report.schedule_updated"
REPORT_SCHEDULE_DELETED = "report.schedule_deleted"
WEBHOOK_CREATED = "webhook.created"
WEBHOOK_UPDATED = "webhook.updated"
WEBHOOK_DELETED = "webhook.deleted"
WEBHOOK_DELIVERED = "webhook.delivered"
INTEGRATION_CREATED = "integration.created"
INTEGRATION_UPDATED = "integration.updated"
INTEGRATION_DELETED = "integration.deleted"
INTEGRATION_CREDENTIAL_SET = "integration.credential_set"
INTEGRATION_TESTED = "integration.tested"
APIKEY_CREATED = "apikey.created"
APIKEY_REVOKED = "apikey.revoked"
GRC_CONTROL_CREATED = "grc_control.created"
GRC_CONTROL_UPDATED = "grc_control.updated"
GRC_CONTROL_DELETED = "grc_control.deleted"
GRC_MAPPING_CREATED = "grc_mapping.created"
GRC_MAPPING_DELETED = "grc_mapping.deleted"
GRC_EVIDENCE_CREATED = "grc_evidence.created"
GRC_EVIDENCE_DELETED = "grc_evidence.deleted"
GRC_ASSESSMENT_CREATED = "grc_assessment.created"
GRC_ASSESSMENT_UPDATED = "grc_assessment.updated"
GRC_EXCEPTION_CREATED = "grc_exception.created"
GRC_EXCEPTION_REVOKED = "grc_exception.revoked"
RELEASE_CREATED = "release.created"
RELEASE_UPDATED = "release.updated"
RELEASE_DELETED = "release.deleted"
FEATURE_FLAG_CREATED = "feature_flag.created"
FEATURE_FLAG_UPDATED = "feature_flag.updated"
FEATURE_FLAG_DELETED = "feature_flag.deleted"
STATUS_INCIDENT_CREATED = "status_incident.created"
STATUS_INCIDENT_UPDATED = "status_incident.updated"
STATUS_INCIDENT_DELETED = "status_incident.deleted"
STATUS_INCIDENT_UPDATE_CREATED = "status_incident_update.created"
ENTITY_LINK_CREATED = "entity_link.created"
ENTITY_LINK_DELETED = "entity_link.deleted"


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
