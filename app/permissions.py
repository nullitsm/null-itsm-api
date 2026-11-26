"""Granular permission catalog.

Codes are ``<module>:<action>``. The catalog is seeded into the
``permissions`` table by the initial migration and is the same catalog the
Users & Roles screen renders. Phase 1 roles grant only Phase 1-relevant
permissions; later phases grant the rest (see docs/DATA_MODEL.md).

Role templates (seeded per organization at provisioning, from
``ROLE_TEMPLATES``) — the eight organization roles from the two-domain
spec (Nov 25, 2026). Organization roles use the org permission catalog
only; they can NEVER grant platform-level permissions (the
``platform:*`` namespace lives in ``PLATFORM_PERMISSIONS`` and is
enforced by a separate domain — see app/models/platform_admin.py).
- Organization Administrator — every org permission, Full Access
- IT Operations   — endpoints / patching / vulnerabilities / CMDB, Privileged
- Service Desk Technician — tickets / requests / knowledge, Least Privilege
- Endpoint Administrator — endpoints / patching / software, Privileged
- Security Analyst — vulnerabilities / threat intel / compliance read, Privileged
- Change Manager — changes / problems / approvals, Privileged
- Auditor         — read-only everywhere + audit:read, Read-Only
- Employee / Requester — own tickets / requests / catalog / knowledge, Least Privilege
"""

from __future__ import annotations

# (code, module, description)
PERMISSIONS: list[tuple[str, str, str]] = [
    # Tickets / Service Desk
    ("tickets:read", "tickets", "View tickets"),
    ("tickets:create", "tickets", "Create tickets"),
    ("tickets:update", "tickets", "Update ticket fields and status"),
    ("tickets:assign", "tickets", "Assign and reassign tickets"),
    ("tickets:resolve", "tickets", "Resolve and reopen tickets"),
    ("tickets:comment", "tickets", "Add internal notes and public replies"),
    ("tickets:delete", "tickets", "Delete tickets"),
    # Requests
    ("requests:read", "requests", "View service requests"),
    ("requests:create", "requests", "Create service requests"),
    ("requests:approve", "requests", "Approve service requests"),
    ("requests:fulfill", "requests", "Fulfill service requests"),
    # Service Catalog
    ("catalog:read", "catalog", "View the service catalog"),
    ("catalog:manage", "catalog", "Create and edit catalog items"),
    # Knowledge Base
    ("knowledge:read", "knowledge", "Read knowledge articles"),
    ("knowledge:create", "knowledge", "Create knowledge articles"),
    ("knowledge:publish", "knowledge", "Publish knowledge articles"),
    # Endpoints
    ("endpoints:read", "endpoints", "View endpoints"),
    ("endpoints:scan", "endpoints", "Run patch and asset scans"),
    ("endpoints:deploy", "endpoints", "Deploy configurations and patches"),
    ("endpoints:remote_control", "endpoints", "Start remote control sessions"),
    ("endpoints:modify", "endpoints", "Modify endpoints (rename, services, registry)"),
    ("endpoints:manage", "endpoints", "Manage endpoint inventory"),
    # Patching
    ("patching:read", "patching", "View patch jobs and status"),
    ("patching:deploy", "patching", "Deploy patches"),
    ("patching:approve", "patching", "Approve patch deployments"),
    # Vulnerabilities
    ("vulnerabilities:read", "vulnerabilities", "View vulnerabilities"),
    ("vulnerabilities:remediate", "vulnerabilities", "Create remediation work"),
    ("vulnerabilities:manage", "vulnerabilities", "Manage vulnerability data"),
    # Changes
    ("changes:read", "changes", "View changes"),
    ("changes:create", "changes", "Create changes"),
    ("changes:approve", "changes", "Approve changes"),
    ("changes:execute", "changes", "Execute approved changes"),
    # CMDB / Assets
    ("cmdb:read", "cmdb", "View configuration items and assets"),
    ("cmdb:manage", "cmdb", "Create and edit configuration items"),
    # Problems
    ("problems:read", "problems", "View problems"),
    ("problems:create", "problems", "Create problems"),
    ("problems:manage", "problems", "Manage problems and known errors"),
    # Reports & Analytics
    ("reports:read", "reports", "View reports and analytics"),
    ("reports:manage", "reports", "Build and schedule reports"),
    # Administration
    ("org:manage", "admin", "Manage organization settings"),
    ("users:invite", "admin", "Invite technicians"),
    ("users:manage", "admin", "Manage users and memberships"),
    ("roles:manage", "admin", "Create, edit, and assign roles"),
    ("permissions:manage", "admin", "Configure role permissions"),
    ("audit:read", "admin", "Read the audit log"),
    ("settings:manage", "admin", "Manage platform settings"),
    # Billing (Phase 5 — catalogued now, granted only by Phase 5 roles)
    ("billing:read", "billing", "View subscription and usage"),
    ("billing:manage", "billing", "Manage subscription and billing"),
    # Subscriptions & entitlements (Phase 5)
    ("subscriptions:read", "subscriptions", "View subscription plans and status"),
    ("subscriptions:manage", "subscriptions", "Manage subscriptions and entitlements"),
    ("usage:read", "subscriptions", "View usage metering"),
    # NOTE: there is deliberately NO platform:* code in this catalog.
    # Platform administration uses the separate PLATFORM_PERMISSIONS
    # namespace below. An organization role can never hold a platform
    # permission, so the org "Administrator" template's "*" expansion
    # can never grant platform access.
    # Network & servers (Tier 2, Phase 3)
    ("network:read", "network", "View network devices and topology"),
    ("network:manage", "network", "Manage network monitoring"),
    ("network:discover", "network", "Run network discovery"),
    ("servers:read", "servers", "View servers"),
    ("servers:manage", "servers", "Manage servers"),
    # Assets & licensing (Tier 1, Phase 3)
    ("assets:read", "assets", "View assets and lifecycle records"),
    ("assets:manage", "assets", "Manage assets, assignments, and lifecycle"),
    ("licenses:read", "licenses", "View software licenses"),
    ("licenses:manage", "licenses", "Manage licenses and compliance"),
    ("vendors:read", "vendors", "View vendors and purchase orders"),
    ("vendors:manage", "vendors", "Manage vendors, POs, and warranties"),
    # Threat intelligence (Tier 3, builds on the live threat map)
    ("threatintel:read", "threat_intel", "View threat intelligence"),
    ("threatintel:manage", "threat_intel", "Manage threat intelligence"),
    # Compliance / GRC (dedicated module, Phases 4–5)
    ("compliance:read", "grc", "View compliance controls and evidence"),
    ("compliance:manage", "grc", "Manage controls, evidence, and assessments"),
    # Workflows & automation (Tier 2, Phase 4)
    ("workflows:read", "automation", "View workflows and rules"),
    ("workflows:manage", "automation", "Design workflows and automation rules"),
    ("workflows:execute", "automation", "Execute and retry automations"),
    # Portal (Tier 1, Phase 2 — employee self-service)
    ("portal:submit", "portal", "Submit tickets and requests via the portal"),
    ("portal:approve", "portal", "Approve assigned requests"),
    # Major incidents & on-call (Tier 2, Phase 3)
    ("incidents:manage", "incidents", "Coordinate major incidents"),
    ("oncall:read", "oncall", "View on-call schedules"),
    ("oncall:manage", "oncall", "Manage on-call schedules and workload"),
    # Integrations & developer portal (Phase 4)
    ("integrations:read", "integrations", "View integrations"),
    ("integrations:manage", "integrations", "Configure integrations"),
    ("apikeys:manage", "developer", "Manage API keys"),
    # Identity & directory (Tier 1, Phase 2 — SAML/SCIM/Entra/LDAP)
    ("identity:read", "identity", "View identity providers and directory sync"),
    ("identity:manage", "identity", "Configure SAML, SCIM, and directory sync"),
    # Status page & releases (Tier 2, Phase 4–5)
    ("statuspage:manage", "status_page", "Publish status page updates"),
    ("releases:manage", "releases", "Manage releases and feature flags"),
]

READ_PERMISSIONS = {code for code, _, _ in PERMISSIONS if code.endswith(":read")}

ROLE_TEMPLATES: dict[str, dict] = {
    "Organization Administrator": {
        "description": "Full administration of this organization.",
        "access_level": "Full Access",
        "permissions": "*",
    },
    "IT Operations": {
        "description": "Manage endpoints, patching, vulnerabilities, and assets.",
        "access_level": "Privileged",
        "permissions": [
            "tickets:read",
            "endpoints:read",
            "endpoints:scan",
            "endpoints:deploy",
            "endpoints:remote_control",
            "endpoints:modify",
            "endpoints:manage",
            "patching:read",
            "patching:deploy",
            "patching:approve",
            "vulnerabilities:read",
            "vulnerabilities:remediate",
            "vulnerabilities:manage",
            "cmdb:read",
            "cmdb:manage",
            "changes:read",
            "reports:read",
        ],
    },
    "Service Desk Technician": {
        "description": "Create, assign, and resolve tickets and requests.",
        "access_level": "Least Privilege",
        "permissions": [
            "tickets:read",
            "tickets:create",
            "tickets:update",
            "tickets:assign",
            "tickets:resolve",
            "tickets:comment",
            "requests:read",
            "requests:create",
            "requests:approve",
            "requests:fulfill",
            "catalog:read",
            "knowledge:read",
            "knowledge:create",
            "problems:read",
            "reports:read",
        ],
    },
    "Endpoint Administrator": {
        "description": "Manage endpoints, patching, and software deployment.",
        "access_level": "Privileged",
        "permissions": [
            "endpoints:read",
            "endpoints:scan",
            "endpoints:deploy",
            "endpoints:remote_control",
            "endpoints:modify",
            "endpoints:manage",
            "patching:read",
            "patching:deploy",
            "patching:approve",
            "assets:read",
            "cmdb:read",
            "cmdb:manage",
            "tickets:read",
            "reports:read",
        ],
    },
    "Security Analyst": {
        "description": "View and remediate vulnerabilities; threat intel and compliance read.",
        "access_level": "Privileged",
        "permissions": [
            "vulnerabilities:read",
            "vulnerabilities:remediate",
            "vulnerabilities:manage",
            "threatintel:read",
            "compliance:read",
            "endpoints:read",
            "tickets:read",
            "audit:read",
            "reports:read",
        ],
    },
    "Change Manager": {
        "description": "Manage changes, problems, and approvals.",
        "access_level": "Privileged",
        "permissions": [
            "changes:read",
            "changes:create",
            "changes:approve",
            "changes:execute",
            "problems:read",
            "problems:create",
            "problems:manage",
            "tickets:read",
            "reports:read",
        ],
    },
    "Auditor": {
        "description": "Read-only access for reporting and compliance.",
        "access_level": "Read-Only",
        "permissions": [code for code in READ_PERMISSIONS],
    },
    "Employee / Requester": {
        "description": "Submit and track own tickets and requests; browse catalog and knowledge.",
        "access_level": "Least Privilege",
        "permissions": [
            "tickets:read",
            "tickets:create",
            "tickets:comment",
            "requests:read",
            "requests:create",
            "catalog:read",
            "knowledge:read",
            "portal:submit",
        ],
    },
}


def resolve_template_permissions(template: dict, catalog: list[tuple[str, str, str]] = PERMISSIONS) -> list[str]:
    """Expand a role template's permission spec to concrete codes.

    Deduplicated (order-preserving): a repeated code in a template must
    never produce a duplicate role_permissions row.
    """
    spec = template["permissions"]
    codes = [code for code, _, _ in catalog] if spec == "*" else list(spec)
    return list(dict.fromkeys(codes))


# ---------------------------------------------------------------------------
# Platform permission catalog — the SECOND administrative domain.
#
# These codes live in the ``platform_permissions`` table and are granted
# only to platform roles (see PLATFORM_ROLE_TEMPLATES). They are a
# SEPARATE namespace from the org catalog above: no organization role,
# permission check, or role editor ever sees them, and the org catalog
# contains no ``platform:*`` code. Billing/subscription codes here are
# defined now; their endpoints arrive in Phase 5.
# ---------------------------------------------------------------------------

# (code, module, description)
PLATFORM_PERMISSIONS: list[tuple[str, str, str]] = [
    ("platform:tenants:read", "platform", "View customer organizations"),
    ("platform:tenants:manage", "platform", "Manage customer organizations"),
    ("platform:users:read", "platform", "View platform admin users"),
    ("platform:users:manage", "platform", "Create and suspend platform admin users"),
    ("platform:roles:read", "platform", "View platform roles"),
    # Super Admin-only: only a Platform Super Admin may manage platform
    # roles and permissions, or grant/revoke the Super Admin role itself.
    ("platform:roles:manage", "platform", "Manage platform roles and permissions"),
    ("platform:audit:read", "platform", "Read platform audit logs"),
    ("platform:support:read", "platform", "View support access grants"),
    ("platform:support:manage", "platform", "Request, approve, and revoke support access grants"),
    ("platform:security:read", "platform", "View platform security posture"),
    ("platform:security:manage", "platform", "Manage platform security settings"),
    ("platform:billing:read", "platform", "View billing and subscriptions"),
    ("platform:billing:manage", "platform", "Manage billing and subscriptions"),
    ("platform:subscriptions:read", "platform", "View subscription plans and status"),
    ("platform:subscriptions:manage", "platform", "Manage subscriptions and entitlements"),
    ("platform:settings:manage", "platform", "Manage platform settings"),
    ("platform:health:read", "platform", "View platform health and tenant health"),
]

PLATFORM_READ_PERMISSIONS = {code for code, _, _ in PLATFORM_PERMISSIONS if code.endswith(":read")}

PLATFORM_ROLE_TEMPLATES: dict[str, dict] = {
    "Platform Super Admin": {
        "description": "Full platform administration; only role managing platform roles / the Super Admin boundary.",
        "access_level": "Full Access",
        "permissions": "*",
    },
    "Platform Administrator": {
        "description": "Manage platform users and tenants; assign non-Super-Admin platform roles.",
        "access_level": "Privileged",
        "permissions": [code for code, _, _ in PLATFORM_PERMISSIONS if code != "platform:roles:manage"],
    },
    "Platform Support": {
        "description": "Support customer tenants via explicit, time-boxed, audited access grants.",
        "access_level": "Privileged",
        "permissions": [
            "platform:tenants:read",
            "platform:users:read",
            "platform:support:read",
            "platform:support:manage",
            "platform:audit:read",
            "platform:health:read",
        ],
    },
    "Security Administrator": {
        "description": "Platform security posture, monitoring, and audit.",
        "access_level": "Privileged",
        "permissions": [
            "platform:security:read",
            "platform:security:manage",
            "platform:audit:read",
            "platform:tenants:read",
            "platform:health:read",
        ],
    },
    "Billing Administrator": {
        "description": "Billing, subscriptions, and usage metering.",
        "access_level": "Privileged",
        "permissions": [
            "platform:billing:read",
            "platform:billing:manage",
            "platform:subscriptions:read",
            "platform:subscriptions:manage",
            "platform:tenants:read",
        ],
    },
    "Platform Auditor": {
        "description": "Read-only platform audit and reporting.",
        "access_level": "Read-Only",
        "permissions": [code for code in PLATFORM_READ_PERMISSIONS],
    },
}
