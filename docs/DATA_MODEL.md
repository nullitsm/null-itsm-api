# NULL ITSM — Unified Data Model

Status: Phase 1 implemented (migrations 0001–0002). Later-phase entities are
**designed here so Phase 1's schema never needs rework**; they are implemented
in their phases. Nothing in this document is a promise that a later-phase
table already exists — the "Phase" column says when each entity lands.

Conventions (apply to every table):
- UUID primary keys (`uuid_pk()`), `created_at` / `updated_at` TIMESTAMPTZ.
- Every tenant-owned row carries `organization_id`; PostgreSQL RLS enforces
  it (see `docs/SECURITY.md`). Never trust a client-supplied org id.
- `organization_id` NULL means "system/global" (permission catalogs,
  platform roles, system role templates).
- Tokens (refresh / invitation / password-reset) are stored ONLY as SHA-256
  hashes. Passwords are Argon2id. TOTP secrets are opaque base32 strings.
- Audit tables are append-only: no UPDATE/DELETE RLS policy, no API.

## Phase 1 — implemented (migrations 0001, 0002)

### Organization domain (`app/models/platform.py`, `rbac.py`, `auth.py`, `audit.py`, `ticket.py`, `access.py`)

| Table | Key columns | Notes |
|---|---|---|
| `organizations` | id, name, slug (unique), settings JSONB, is_active, is_dev_fixture, created_by_id → users | `settings` holds the least-privilege policy + branding. `created_by_id` exists so the creator can read the row back at creation (no membership yet). |
| `users` | id, email (unique), password_hash, full_name, is_active, email_verified, mfa_enabled, mfa_secret, last_login_at | Global identity: one person, many orgs. |
| `memberships` | organization_id, user_id, status (active/invited/suspended), is_owner, expires_at | Unique (org, user). The source of truth for membership. |
| `permissions` | code (unique), module, description | Org catalog. **No `platform:*` code** (removed in 0002). |
| `roles` | organization_id (NULL = system template), name, description, access_level, is_system | Unique (org, name). Eight templates (see below). |
| `role_permissions` | role_id, permission_id, organization_id | Unique (role, permission). org copied from the role. |
| `user_roles` | organization_id, user_id, role_id, granted_by_id | Unique (org, user, role). |
| `sessions` | user_id, organization_id, refresh_token_hash, expires_at, revoked_at, ip_address, user_agent | Refresh sessions; access tokens are stateless JWTs. |
| `invitations` | organization_id, email, token_hash (unique), invited_by_id, status, expires_at, accepted_at | `invitation_roles` links roles to an invitation. |
| `password_resets` | user_id, token_hash (unique), expires_at, used_at | |
| `audit_logs` | organization_id, actor_id (nullable), action, resource_type, resource_id, outcome, metadata JSONB | Append-only. |
| `tickets` | organization_id, number (per-org INC-000001…), title, description, status, priority, category, requester_id, assignee_id | `ticket_counters` holds the per-org last_number (row-locked). |
| `access_approvals` | organization_id, requested_by_id, target_user_id, role_id, status, decided_by_id, decided_at | Elevated-access approval (org policy `require_approval_for_elevated`). |
| `access_reviews` | organization_id, reviewer_id, status, … | Periodic access review records. |

**Organization roles (seeded per org at provisioning)** — Organization
Administrator (Full Access, `*`), IT Operations (Privileged), Service Desk
Technician (Least Privilege), Endpoint Administrator (Privileged), Security
Analyst (Privileged), Change Manager (Privileged), Auditor (Read-Only),
Employee / Requester (Least Privilege). Plus org-created custom roles
within subscription limits (Phase 5).

### Platform domain (`app/models/platform_admin.py`, migration 0002)

A SEPARATE identity and authorization boundary. Platform users are internal
NULL personnel; they are not organization members and hold no org roles.

| Table | Key columns | Notes |
|---|---|---|
| `platform_users` | id, email (unique), password_hash, full_name, is_active, mfa_enabled, mfa_secret, source (bootstrap/invited/sso), review_status (approved/pending_review), last_login_at | `review_status='pending_review'` flags accounts that could not be classified safely during migration — manual review, never guessed. |
| `platform_permissions` | code (unique), module, description | 17 `platform:*` codes. Separate namespace; never visible to the org domain. |
| `platform_roles` | name (unique, global), description, access_level, is_system | Six templates: Platform Super Admin, Platform Administrator, Platform Support, Security Administrator, Billing Administrator, Platform Auditor. |
| `platform_role_permissions` | role_id, permission_id | Unique (role, permission). |
| `platform_user_roles` | platform_user_id, role_id, granted_by_id | Unique (user, role). |
| `platform_sessions` | platform_user_id, refresh_token_hash, expires_at, revoked_at, ip_address, user_agent, mfa_verified | `mfa_verified` added in migration 0003 (refresh preserves the MFA claim). |
| `platform_access_grants` | platform_user_id, organization_id, purpose, status (pending/active/revoked/expired), granted_by_id, approved_by_id, expires_at | Explicit, time-boxed cross-tenant support access. No grant → no tenant read. |
| `platform_audit_logs` | actor_id (platform user, nullable), organization_id (nullable), action, resource_type, resource_id, outcome, metadata JSONB | Append-only. `organization_id` is set when the event touched a tenant. |

**Platform authorization rules**
- Only Platform Super Admin holds `platform:roles:manage` and may
  grant/revoke the Platform Super Admin role.
- Platform Administrators manage platform users and assign non-Super-Admin roles.
- `*:manage` platform permissions require an MFA-verified token (`mfa: true`);
  `*:read` permissions work with `mfa: false`.
- Tenant reads by a platform admin require an active, unexpired grant and
  are enforced in the database (`platform_support_list_org_users`) and
  written to the platform audit log.
- An org token can never authenticate a platform endpoint and vice versa
  (distinct JWT types: `access` vs `platform_access`).

## Later phases — designed, not yet built

### Phase 2 — ITSM engine
`requests` (service requests, linked to catalog items), `catalog_items`
+ `catalog_categories`, `knowledge_articles` (+ `knowledge_feedback`),
`changes` (+ `change_approvals`, `change_tasks`), `problems`
(+ `known_errors`), `notifications` (in-app + email queue),
`sla_policies` (+ `business_hours`, `sla_breaches`, `escalation_rules`),
`email_messages` (inbound email-to-ticket + replies, Celery+IMAP/SMTP),
`portal_sessions` (employee self-service; org branding in `organizations.settings`),
`surveys` + `survey_responses`, `ticket_templates`, `recurring_tickets`,
`ticket_links` (parent/child, related), `major_incidents`,
`identity_providers` (SAML/OIDC config), `scim_tokens`, `directory_sync_runs`
(SAML/SCIM/Entra/AD/LDAP — Tier 1), `imports`/`exports` (data portability).

### Phase 3 — Endpoint + security engine
`endpoints` (agent-enrolled devices; identity via the agent API contract in
`docs/API_CONTRACT.md` — the agent itself lives in `nullitsm/null-endpoint-agent`),
`endpoint_inventory` (apps, services, hardware), `patches` + `patch_jobs`
+ `patch_deployments`, `vulnerabilities` (+ `vulnerability_findings` per
endpoint, CVE + CISA KEV enrichment), `scans` + `scan_results` (Greenbone/
OpenVAS engine, multi-engine architecture), `remediation_tickets`
(vulnerability → ticket → patch → rescan verification),
`assets` (+ `asset_lifecycle_events`, `purchase_orders`, `vendors`,
`warranties`, `licenses`, `license_assignments`, `asset_assignments`,
check-in/out, transfers, lost/stolen, depreciation, retirement, disposal),
`configuration_items` (CMDB) + `ci_relationships`, `network_devices`
+ `network_interfaces` + `topology_links` + `service_dependencies`
(network ops + monitoring, Tier 2), `on_call_schedules` + `on_call_rotations`.

### Phase 4 — Enterprise operations
`workflows` (+ `workflow_versions`, `workflow_runs`, `workflow_run_steps`
— execution history, retries, permissions), `automation_rules`
(+ `automation_runs`), `custom_forms` + `custom_fields` + `field_values`,
`dashboards` + `dashboard_widgets`, `reports` + `scheduled_reports`,
`webhooks` + `webhook_deliveries`, `integrations` (+ `integration_credentials`
— framework, not hardcoded vendors; priority Entra ID, Intune, Greenbone,
Defender, Slack, Teams, GitHub, Power BI), `api_keys` (developer portal),
`feature_flags` + `releases`, `status_page_incidents` (customer support +
status page), `grc_controls` (+ `grc_control_mappings` SOC 2 / ISO 27001 /
NIST CSF / CIS, `grc_evidence`, `grc_assessments`, `grc_exceptions`).
**Honesty rule:** GRC features help customers manage compliance; they do
NOT make NULL certified — never claim certification.

### Phase 5 — Commercial SaaS
`subscriptions` (+ `plans`, `plan_features`, `entitlements`),
`usage_meters` (users, endpoints, storage, API calls),
`invoices` (billing integration architecture only — no real payments until
the provider + production credentials are approved), `tenants`
(platform-side tenant health/subscription status — the Platform Admin
Console), `backups` + `restore_tests` (backup/DR, RTO/RPO),
`threat_indicators` + `threat_actor_notes` (NULL Threat Intelligence,
building on the live threat map), `ai_suggestions`
(NULL Intelligence — AI suggestions REQUIRE human approval for
consequential actions).

## Cross-module linking (the unified-model promise)
A vulnerability links to its endpoint, its remediation ticket, its patch
deployment, and its verification scan. An asset links to its assigned
employee, its purchase order, its vendor, its warranty, and its licenses.
A change links to its CAB approval, its affected CIs, and its tickets.
No duplicated records, no disconnected modules; every link carries
`organization_id` and is RLS-scoped.
