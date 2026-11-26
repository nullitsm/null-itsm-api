# NULL ITSM — Development Register

Coordination surface for the NULL ITSM build across Frontend / Backend /
Database / Security / Integration / Testing / Deployment. The central copy
lives in the master repo (`nullitsm/null-platform`,
`docs/DEVELOPMENT_REGISTER.md`); this repo's copy is kept in sync by the
parent at phase boundaries.

**Protected baseline checkpoint (frontend):** `be38333228373760cad736a876b8305c150c79f6`
(Command Center upload, Nov 25, 2026, 17:12 EST) — the state the live
frontend rounds build on. Do not change it from this repo.

**Component repos:** frontend `nullitsm/nullitsm.github.io` (live),
backend `nullitsm/null-itsm-api` (this repo), endpoint agent
`nullitsm/null-endpoint-agent` (planned, Phase 3), integrations
`nullitsm/null-integrations` (planned, Phase 4), infrastructure
`nullitsm/null-infrastructure` (planned; IaC code only).

**Status key:** Done | In progress | Planned | Blocked (with reason) |
Deferred (with reason).

## Phase 1 — Foundation (DONE, Nov 25, 2026)

| Feature | Implementation | Backend | Frontend | Database | Security | Integration | Testing | Deployment |
|---|---|---|---|---|---|---|---|---|
| FastAPI app (`/api/v1`, OpenAPI, health, logging, rate limiting, CORS dev-only) | Done | Done | — | — | Done | — | 35 tests pass | Local uvicorn verified |
| Multi-tenancy: `organization_id` + RLS on every tenant table | Done | Done | — | Done (0001) | Done | — | Tenant isolation + RLS-at-DB tests pass | — |
| Auth: login/logout, OIDC-ready JWT, TOTP MFA, password reset, invitations, refresh rotation | Done | Done | Deferred (contract only) | Done (0001) | Done | OIDC: local dev issuer; Cognito gated on infra approval | Auth tests pass | — |
| Organizations: provisioning, settings/policy, membership, switching, invitations, access reviews | Done | Done | Deferred | Done (0001) | Done | — | Org tests pass | — |
| Users & Roles API (8 org roles, granular permissions, grant-scope, elevated-access approval, access expiration) | Done | Done | Deferred (contract + JS client) | Done (0001, 0002 renames) | Done | — | RBAC tests pass | — |
| Two administrative domains (org vs platform admins) | Done | Done | In progress (separate Users & Roles pages, other chat) | Done (0002, 0003) | Done | — | Platform tests (test child) | — |
| Audit logging (org + platform, append-only) | Done | Done | Deferred | Done (0001, 0002) | Done | — | Audit immutability tests pass | — |
| Tickets (per-org INC numbers, row-locked counter) | Done | Done | Live (other chat) | Done (0001) | Done | — | Ticket tests pass | — |
| Celery workers (tenant-aware: expire memberships, invitation email, audit export stub) | Done | Done | — | — | Done | Redis local; worker boot verified | — | — |
| S3 storage interface | Done | Done (raises when unconfigured) | — | — | Done | S3 gated on infra approval | — | — |
| Dockerfile + docker-compose (api + postgres + redis + worker) | Done | Done | — | — | — | **Docker NOT available in this VM** — compose is code only; verification uses local Postgres 16 + Redis 7 | — | Blocked: no Docker here |
| AWS staging infra as code (ECS Fargate, RDS, ElastiCache, S3, Cognito, Secrets Manager, CloudWatch, CI/CD) | Done (code only) | — | — | — | — | — | Review only (no terraform binary here — run `terraform validate`/`plan` before any apply) | **Blocked: AWS provisioning needs explicit user approval — nothing provisioned, nothing spent** |
| Frontend API client (`frontend/null-api-client.js`) + API contract + integration guide | Done | — | Deferred (wiring) | — | Done | — | `node --check` passes | — |

**Phase 1 verification (Nov 25, 2026):** full suite 35/35 passing (stable
across repeat runs); API booted against local PostgreSQL + Redis and
verified live (`/health`, `/health/ready`, login → org → tickets,
tenant-isolated queries, platform login + grant flow). See the Phase 1
report for the live transcript.

**Outstanding dependencies (Phase 1):** staging deployment + Cognito
provisioning + backup/recovery testing (all need infrastructure approval);
frontend wiring (parent says when rounds settle); Docker unavailable in
this VM (compose is code-only).

## Phase 2 — Complete ITSM engine (PLANNED — next)

| Feature | Tier | Status |
|---|---|---|
| Service Desk: tickets (done in Phase 1) + requests, SLA timers | — | Planned |
| Service Catalog + Knowledge Base | — | Planned |
| Change + Problem (+ CAB, approvals) | — | Planned |
| Notifications (in-app + email) | — | Planned |
| Advanced SLA + escalation engine (business hours, breach alerts) | **Tier 1** | Planned |
| Email-to-ticket + email replies (Celery + IMAP/SMTP worker) | **Tier 1** | Planned |
| Employee self-service portal `/portal` (org branding) | **Tier 1** | Planned |
| SAML / SCIM / AD / Entra / LDAP, deprovisioning, group sync, access certification | **Tier 1** | Planned |
| Data import/export | **Tier 1** | Planned |
| Ticket templates, recurring tickets, collision detection, satisfaction surveys | Tier 2 | Planned |
| Major incidents + parent/child tickets | Tier 2 | Planned |
| On-call scheduling + workload balancing | Tier 2 | Planned |

## Phase 3 — Endpoint + security engine (PLANNED)

| Feature | Tier | Status |
|---|---|---|
| Endpoint agent API contract (enrollment, identity, heartbeats, inventory, jobs, updates) | — | Contract in `docs/API_CONTRACT.md` §9; agent repo `nullitsm/null-endpoint-agent` created at Phase 3 start |
| Endpoint management, patching, software | — | Planned |
| Vulnerability management: real Greenbone/OpenVAS engine, multi-engine architecture, real CVE + CISA KEV, remediation tickets, rescan verification | — | Planned |
| CMDB / assets | — | Planned |
| Asset lifecycle + software licensing (POs, vendors, warranties, assignments, check-in/out, transfers, lost/stolen, depreciation, retirement, disposal, license compliance/renewals) | **Tier 1** | Planned |
| Network ops + monitoring (discovery, topology, SNMP, syslog, outage alerts, service dependency mapping) | Tier 2 | Planned |
| NULL Threat Intelligence workspace (builds on the live threat map) | Tier 3 | Planned |
| NULL Infrastructure Intelligence (assets/endpoints/network/services/vulns/dependencies in one picture) | Tier 3 | Planned |

## Phase 4 — Enterprise operations (PLANNED)

| Feature | Tier | Status |
|---|---|---|
| Workflow designer + automation rules (execution history, retries, permissions) | Tier 2 | Planned |
| Custom forms/fields/dashboards/reports, scheduled PDF/CSV/Excel exports | Tier 2 | Planned |
| Webhooks + integrations framework (priority: Entra ID, Intune, Greenbone, Defender, Slack, Teams, GitHub, Power BI) | Tier 2 | Planned |
| Cross-module linking (vuln → endpoint → ticket → patch → verification scan) | — | Planned |
| Advanced reporting + custom dashboards | Tier 2 | Planned |
| API developer portal (keys, docs, usage) | Tier 2 | Planned |
| Release management + feature flags | Tier 2 | Planned |
| Customer support + status page | Tier 2 | Planned |
| GRC module (SOC 2 / ISO 27001 / NIST CSF / CIS mappings, evidence, ownership, assessments, exceptions) | — | Planned — **honesty rule: helps customers manage compliance; does NOT certify NULL** |
| NULL Intelligence (AI-assisted ops; human approval required for consequential actions) | Tier 3 | Planned |
| Predictive analytics, automated vuln correlation, cross-module remediation orchestration | Tier 3 | Planned |

## Phase 5 — Commercial SaaS (PLANNED)

| Feature | Tier | Status |
|---|---|---|
| Onboarding | — | Planned |
| Subscriptions / entitlements / limits / usage metering | **Tier 1** | Planned (permissions defined in Phase 1; endpoints here) |
| Billing integration (architecture only — no real payments until provider + production credentials are approved) | **Tier 1** | Planned |
| Platform Admin Console (admin directory, tenants, support tools, platform audit — API done in Phase 1; console UI is frontend work) | **Tier 1** | Backend done; UI planned |
| Multi-tenant administration, tenant health, usage monitoring | **Tier 1** | Planned |
| Backup / disaster recovery (automated backups, tested restoration, RTO/RPO, multi-zone) | **Tier 1** | Planned — **needs infra approval** |
| Security testing + monitoring (incl. NULL's own vuln management, secrets/KMS, anomaly detection) | **Tier 1** | Planned |
| Production readiness (availability targets, incident response, service health reporting) | — | Planned |

## Final navigation (product structure)
Command Center (Overview, My Workspace, Notifications) · Service
Management (Tickets, Requests, Catalog, Knowledge) · IT Operations
(Endpoints, Patching, Software, Remote Management) · Security
(Vulnerabilities, Threat Intelligence, Compliance) · Infrastructure
(Assets, CMDB, Network, Servers) · ITSM Workflows (Changes, Problems,
CAB, Approvals) · Automation (Workflow Designer, Rules, Schedules) ·
Analytics (Reports, Dashboards, Performance) · Administration (Users,
Roles, Organizations, Integrations) · Platform Management
(Subscriptions, Billing, Tenant Management).

## Personas (12)
Platform Super Administrators, Organization Administrators, IT Managers,
Service Desk Managers, Service Desk Technicians, Endpoint Administrators,
Security Analysts, Network Administrators, Change Managers, Auditors,
Employees/Requesters, External Vendors. RBAC is built around these; the
org role templates map to them (see `docs/DATA_MODEL.md`).
