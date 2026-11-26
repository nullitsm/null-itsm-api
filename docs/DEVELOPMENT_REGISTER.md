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

## Phase 2 — Complete ITSM engine (DONE, Nov 26, 2026)

| Feature | Tier | Status |
|---|---|---|
| Service Desk: tickets (done in Phase 1) + requests, SLA timers | — | Done (migrations 0004–0005; 26 ITSM + 18 SLA tests) |
| Service Catalog + Knowledge Base | — | Done (migration 0004) |
| Change + Problem (+ CAB, approvals) | — | Done (migration 0004) |
| Notifications (in-app + email) | — | Done (migration 0004; shared `notification_service`) |
| Advanced SLA + escalation engine (business hours, breach alerts) | **Tier 1** | Done (migration 0005; business-hours math, breach scan + escalation sweeps, ticket-create hook stamps due dates) |
| Email-to-ticket + email replies (Celery + IMAP/SMTP worker) | **Tier 1** | Done (migration 0006; RFC822 ingest, threading, unknown-sender triage, SMTP-when-configured else logged) |
| Employee self-service portal `/portal` (org branding) | **Tier 1** | Done (migration 0006; `portal_access` JWT sessions, own-records-only scoping) |
| SAML / SCIM / AD / Entra / LDAP, deprovisioning, group sync, access certification | **Tier 1** | Done (migration 0007; SCIM v2, SAML metadata + real python3-saml ACS, OIDC discovery, directory sync framework — Entra real client, LDAP honest not-configured) |
| Data import/export | **Tier 1** | Done (migration 0006; ServiceNow/Jira/CSV profiles, idempotent rows, CSV/JSON export with on-demand download) |
| Asset lifecycle + software licensing (POs, vendors, warranties, assignments, check-in/out, transfers, lost/stolen, depreciation, retirement, disposal, license compliance/renewals) | **Tier 1** | Done in Phase 2 (migration 0007 — pulled forward from Phase 3 per the Phase 2 brief; employee-offboarding flow verified end-to-end) |
| Ticket templates, recurring tickets, collision detection, satisfaction surveys | Tier 2 | Done (templates/recurring/surveys in migration 0004; collision detection not built — see below) |
| Major incidents + parent/child tickets | Tier 2 | Done (migration 0004; major incidents + ticket_links) |
| On-call scheduling + workload balancing | Tier 2 | Planned (not in Phase 2) |
| Sweep org enumeration (`list_organization_ids()` SECURITY DEFINER fn) | — | Done (migration 0008; SLA + recurring sweeps use it) |

**Phase 2 verification (Nov 26, 2026):** full suite **146/146 passing**
(54 Phase 1 + 92 Phase 2: 26 ITSM, 18 SLA, 27 email/portal, 21
identity/assets); `ruff check` + `ruff format` clean. Migration chain
single head `0008`; 0007 table-order bug found by a builder and fixed
at integration (verified `0006 → head` on a scratch DB with the 0007
tables dropped). Live boot against local PostgreSQL 16 + Redis 7:
`/health`, `/health/ready`, login → tickets → SLA policy → ticket
create (due dates stamped by the hook, business-hours aware) →
request → portal login → platform tenants; all four Celery sweeps run
(SLA 2 orgs/3 tickets, recurring 2 orgs, temp grants, mailboxes
`polled: 0` with none configured). Celery beat wired: SLA scan 5 min,
mailbox poll 5 min, temp-grant expiry hourly, recurring sweep 15 min.

**Phase 2 deferred / honest gaps:** collision detection (not built);
ticket attachments are JSON metadata (`{filename, content_type,
size_bytes, content_base64?}` — `python-multipart` is not installed, so
no multipart upload yet; bytes go to storage only when configured,
otherwise 503); SAML ACS validates assertions but mints no session
(SSO session issuance is out of scope for Phase 2); portal login
rejects MFA-enabled users (complete MFA via the main login); LDAP
directory sync raises honest "not configured" (`ldap3` not installed);
Entra sync needs tenant/client credentials; export to S3 needs the
storage backend configured (otherwise on-demand download regenerates).

**Outstanding dependencies (Phase 2):** frontend wiring (parent says
when rounds settle); Docker unavailable in this VM (compose is code
only); AWS/Cognito/staging still gated on infrastructure approval.

## Phase 3 — Endpoint + security engine (DONE, Nov 26, 2026)

Backend side implemented, 236/236 tests passing
(`scripts/run_tests_locked.sh`), live-boot verified end to end (31/31
checks: enroll → heartbeat → inventory → patch_scan job → finding;
manual vuln import → remediate → verify → agent rescan → verified;
CMDB + network smoke). Migrations 0009–0012, single head `0012`.

| Feature | Tier | Status |
|---|---|---|
| Endpoint agent API contract (enrollment, identity, heartbeats, inventory, jobs, updates) | — | **Done** — `app/routers/agents.py`, `app/routers/endpoints.py`, `app/services/agent_service.py`, `app/services/endpoint_service.py`, `app/device_auth.py`; contract §9 flipped to implemented; agent repo `nullitsm/null-endpoint-agent` still to be created (parent) — no real device has run these calls yet |
| Endpoint management, patching, software | — | **Done** — patching: `app/routers/patching.py`, `app/services/patching_service.py`; update check returns `download_url: null` (no artifact storage configured — no update is ever offered) |
| Vulnerability management: real Greenbone/OpenVAS engine, multi-engine architecture, real CVE + CISA KEV, remediation tickets, rescan verification | — | **Done** — `app/services/greenbone.py` (pure-stdlib GMP client), `app/services/vuln_service.py`, `app/tasks/vuln_tasks.py` (`null.tasks.sync_cve_kev`, daily beat), `app/routers/vulnerabilities.py`; verify flow added by the coordinator (`POST …/findings/{id}/verify`) |
| CMDB / assets | — | **Done** — `app/routers/cmdb.py`, `app/services/cmdb_service.py` (assets themselves were done in Phase 2) |
| Asset lifecycle + software licensing (POs, vendors, warranties, assignments, check-in/out, transfers, lost/stolen, depreciation, retirement, disposal, license compliance/renewals) | **Tier 1** | Done in Phase 2 (migration 0007) |
| Network ops + monitoring (discovery, topology, SNMP, syslog, outage alerts, service dependency mapping) | Tier 2 | **Done, except:** DNS/DHCP and syslog ingestion not built; SNMP only when `pysnmp` is installed (else honestly `snmp_unavailable`); on-call schedules/rotations deferred to Tier 2 — `app/routers/network.py`, `app/services/network_service.py`, `app/tasks/network_tasks.py` (`null.tasks.check_network_health`, hourly beat) |
| NULL Threat Intelligence workspace (builds on the live threat map) | Tier 3 | Planned |
| NULL Infrastructure Intelligence (assets/endpoints/network/services/vulns/dependencies in one picture) | Tier 3 | Planned |

**Outstanding dependencies (Phase 3):** agent repo creation (parent,
when the coordinator says ready — the backend is ready); artifact
storage for agent updates (until then `download_url` stays `null`);
NVD full backfill is the daily sync job, not a single run (one bounded
2000-result page per run by design); Docker unavailable in this VM
(compose is code only); AWS/Cognito/staging still gated on
infrastructure approval.

## Sample-data removal (DONE, Nov 26, 2026)

At the user's direction, all sample data was removed from the backend:
`app/seed.py` and `scripts/seed_dev.py` deleted, the
`NULL_SEED_DEV_FIXTURES` setting removed, live-boot scripts rewired to
provision a real org through the public API from an empty database.
Tests build their own data fresh in the test database via
`tests/factories.py`. The `organizations.is_dev_fixture` column and API
field stay in the schema/contract (always `false` now) — no migration
was needed. Verified after removal: suite **236/236 passing** and live
boot **33/33 checks** from a completely empty database (0 orgs/users/
tickets/platform users before the boot created its own org via API).

## Registration + onboarding + invitations (DONE, Nov 26, 2026)

Priority insertion (user request Nov 25, 20:55 EST), built after the
sample-data removal and before Phase 4. Migration 0013; **259/259
tests passing** (23 new in `tests/test_registration.py`) and live boot
**33/33 checks** from a completely empty database, now provisioning
through `POST /api/v1/auth/register` instead of a direct DB insert.

- **Organization registration** — public `POST /api/v1/auth/register`
  (5/min): org name/email/website/industry/size + admin name/email/
  password. Creates the org (auto-suffixed slug on collision),
  the first admin, the owner membership, the Organization
  Administrator grant, default settings, the three default
  departments, and the onboarding record (profile complete), then
  signs the admin in. 409 when the admin email already exists.
  Registration **never** creates a platform administrator (verified:
  org admin credentials get 401 on platform login).
- **Multi-tenant testing** — register two orgs (NULL Demo Corporation,
  Acme Technology Group) + Genesee Test Organization for switching;
  tests prove cross-org reads 403/404, cross-org writes rejected, and
  per-org ticket lists disjoint.
- **Onboarding** — per-org progress (`org_onboarding`): profile →
  departments → invite_technicians → service_desk →
  business_hours_sla → assets_endpoints → finish. Skippable except
  profile/finish; finishing requires the rest complete-or-skipped and
  locks the record. Step data applies real effects (departments
  created, service-desk settings merged, default business hours +
  SLA policy created).
- **Org switching** — existing `select-organization` /
  `switch-organization` endpoints (server-side membership checks),
  now covered by tests incl. switching to a non-member org → 403.
- **Invitations, two separate workflows** — org (`/organizations/{id}/invitations`,
  org roles only) and platform (`/platform/admin-invitations`,
  platform roles only; only a Platform Super Admin may invite to the
  Super Admin role). Single-use tokens, SHA-256 hashed, bound to
  email + org, **48h expiry** (`invitation_days` 7 → 2). Resend
  regenerates the token (old link dies); revoke blocks acceptance;
  accept is audited (`invitation.accepted` + `membership.accepted`,
  platform equivalents in the platform audit log). Public lookup
  `GET /api/v1/auth/invitations/{token}` feeds the accept page
  (name/email pre-filled and locked). MFA enrollment follows
  acceptance via the existing Phase 1 endpoints.
- **Local email** — no real email service, no spend. When SMTP is
  unconfigured the backend writes invitation mail to the
  `dev_email_outbox` table (org + platform scopes) and returns the
  `accept_url` to the inviting admin in the create/resend response.
  Read it via `GET /organizations/{id}/outbox` or
  `GET /platform/outbox`. Full instructions in `docs/DEV_SETUP.md`.
- **Fixes found while building this piece** — `users:read` did not
  exist in the permission catalog (new GET endpoints would 403 for
  everyone): added to the catalog + the five staff templates (Auditor
  via `READ_PERMISSIONS`, Org Admin via `*`). Slug uniqueness checks
  were RLS-blind at registration time (no org context → duplicate
  slugs 500'd): new SECURITY DEFINER `org_slug_exists()`; same-name
  orgs now get suffixed slugs, explicit slugs still 409.
  `auth_get_invitation_by_token` was replaced (DROP + CREATE) to
  return org name/slug, profile fields, and role names.

## Real email delivery + remove technician (follow-ups, Nov 26, 2026)

Extends the registration/invitation work. Migrations 0018 (delivery
records + idempotency indexes) and 0019 (users RLS fix, below).
**297/297 tests passing** (26 new in `tests/test_email_delivery.py`,
12 new in `tests/test_member_removal.py`) and live boot **33/33
checks** from a completely empty database.

- **Real email delivery** — centralized service (`app/services/email.py`)
  with a provider abstraction: `email_provider="none"` (dev outbox,
  default) vs `"resend"` (real sends). `email_deliveries` table
  records every attempt (provider message id, status, attempts,
  error; rendered bodies stored so retries re-send identically).
  Retries via Celery (`null.tasks.retry_email_delivery`, backoff 60s ×
  2^n, max 3, never double-sends). Idempotency: API-level duplicate
  rejection + partial unique indexes (one pending invitation per
  (org, email)); stale pending rows retire to `expired` at invite
  time. NULL-branded templates (ivory/ink/purple), subject exactly
  "You've been invited to join NULL ITSM". Full detail in
  `docs/EMAIL.md`.
- **Resend key via surrogate (this VM)** — no key value exists
  anywhere an agent can read it, so when `NULL_RESEND_API_KEY` is
  unset the backend fetches a fresh `hsurr:` surrogate per send from
  authd (`app/services/resend_surrogate.py`, credential
  `custom.resend`) and sends it through the egress proxy, which swaps
  it for the real key. Env key wins when set; neither → loud 503.
  Transport: browser UA (Cloudflare 1010), explicit proxy with
  `trust_env=False` (NO_PROXY `::1` parse bug), TLS verified against
  the **system CA store** (httpx's certifi does not know the Hatch
  egress CA — found live: default client fails every send with
  `CERTIFICATE_VERIFY_FAILED`). **Verified end to end Nov 26, 2026:**
  a real invitation reached `jamiah_mcq@yahoo.com` from the live boot
  (Resend message id `01a215df-d718-7767-afab-955c0f0944ff`,
  `delivery.status == "sent"`, accept link hidden). Receipt in the
  Yahoo inbox + acceptance of that invitation are still open (token
  relay from the email; the live DB is kept until then). Sender for
  live sends is `onboarding@resend.dev` (no verified domain yet).
- **Remove technician** — `POST /api/v1/organizations/{org_id}/members/{user_id}/remove`
  (`users:manage`, optional `{"reason"}`). Deactivates the membership
  (never a hard delete): user record + audit history preserved,
  re-adding needs a fresh invitation. Access ends immediately (every
  request re-checks for an active membership; revoked sessions cannot
  refresh). Assigned assets go through the Phase 2 offboarding flow
  (`offboard_user` with target `"deactivated"`): one recovery ticket
  per asset, assets to `in_repair`. Pending invitations for the email
  are cancelled. Guards: the org owner cannot be removed; the last
  Organization Administrator cannot be removed (same invariant now
  enforced on the PATCH status path too); an admin may remove
  themselves when another admin remains. Audited as
  `membership.removed` with actor/target/reason/report. Platform
  users are removed via the existing suspend endpoint
  (`PATCH /api/v1/platform/admins/{id}/suspend`, already tested) —
  not duplicated.
- **RLS fix found by the removal tests (migration 0019)** — the
  `users_select` policy only showed a co-member while their
  membership was `active`, so a suspended or removed member vanished
  from Organization Users the moment their status changed. The policy
  now shows co-members regardless of their status (the *caller* must
  still be active). One existing test depended on the old hiding
  (`test_rls_blocks_cross_org_user_read` asserted exactly 2 Acme
  users); it now asserts the two fixture users are present and no
  Globex users leak, which is the actual isolation property.
- **Environment note (Nov 26, 2026)** — the VM was replaced and the
  system PostgreSQL/Redis installs were wiped with it (home
  persisted). Reinstalled from apt (PostgreSQL 16, Redis 7.0) and
  started manually (`pg_ctlcluster 16 main start`,
  `redis-server --daemonize yes`); there is no systemd here, so the
  services do not auto-start after a restart. Port 8001 is held by
  another agent's dev-mode server (DB `null_itsm_endpoint`); live
  boots now run on port 8002 (`NULL_LIVE_BOOT_PORT`) and refuse to
  test against a server they did not start.

## Phase 4 — Enterprise operations (COMPLETE Nov 26, 2026; migrations 0014–0017; full suite 389/389 passing)

Built in four workstreams (A workflows/automation, B forms/dashboards/reports,
C webhooks/integrations/API keys, D GRC/releases/feature flags/status page/
cross-module links) and integrated by the coordinator: all routers + models
registered, audit literals centralized (68 constants in `app/audit.py`),
`links:manage` added to the permission catalog (migration 0017 re-seeds it).

| Feature | Tier | Status |
|---|---|---|
| Workflow designer + automation rules (versioning, execution history, retries) | Tier 2 | Done — ticket-scoped rules; no wait/branching/HTTP/sub-workflow steps |
| Custom forms/fields/dashboards/reports, scheduled CSV exports | Tier 2 | Done — CSV works; `xlsx` is an honest 501 (`openpyxl` not installed) |
| Webhooks + integrations framework (Entra ID, Intune, Greenbone, Defender, Slack, Teams, GitHub, Power BI) | Tier 2 | Done — generic-HTTP provider registry + real connection checks; no per-vendor drivers |
| Cross-module linking (vuln → endpoint → ticket → patch → verification scan) | — | Done — allow-listed entity/link types, cross-org → 404 |
| Advanced reporting + custom dashboards | Tier 2 | Done — real GROUP BY widget queries; scheduled reports email CSV on a 5-min sweep |
| API developer portal (keys, docs, usage) | Tier 2 | Done — API keys (SHA-256 stored, shown once) authenticate via `X-Api-Key` in the main dependency chain; no usage metering yet |
| Release management + feature flags | Tier 2 | Done — deterministic per-org bucket `sha256(org_id:key) % 100`; no per-user targeting |
| Customer support + status page | Tier 2 | Done — public `GET /api/v1/status/public/{org_slug}`; no subscriber notifications or uptime history |
| GRC module (SOC 2 / ISO 27001 / NIST CSF / CIS mappings, evidence, ownership, assessments, exceptions) | — | Done — control status is DERIVED only (exception → `exception`; latest assessment → `satisfied`/`failed`/`in_progress`; none → `not_assessed`). `satisfied` is a recorded assessment outcome, never a certification claim. No file upload for evidence. **Honesty rule: helps customers manage compliance; does NOT certify NULL** |
| NULL Intelligence (AI-assisted ops; human approval required for consequential actions) | Tier 3 | Deferred to Phase 5 — DATA_MODEL puts `ai_suggestions` in Phase 5 |
| Predictive analytics, automated vuln correlation, cross-module remediation orchestration | Tier 3 | Deferred |

**Integration wiring (coordinator):**
- Automation hooks: ticket create fires `ticket.created`, update fires
  `ticket.updated` + `ticket.priority_changed` when the priority changed.
  A bad rule never fails the ticket write (per-action errors are recorded
  on the run as failed/partial).
- **SLA sweep order (decision, Nov 26): detect → escalate → automate.**
  `scan_breaches` only detects and returns `breached_ticket_ids`;
  `scan_sla_breaches` (Celery, every 5 min) evaluates Phase 2 escalations
  first, then fires `sla_breach` automation rules. Automation runs last
  so an action that changes a ticket (e.g. set priority critical) cannot
  defeat an escalation rule's conditions for the same breach.
- Webhook emission: `emit_event` (post-commit, best-effort, never raises)
  from ticket create/update/resolve, change create/approve, incident
  declare, endpoint enroll, and vulnerability first-seen (`new_findings`
  = freshly created findings only; re-imports do not re-emit). Delivery
  is synchronous in-process (bounded by the 10s httpx timeout, max 3
  attempts) — async delivery is a future improvement.
- API-key auth: bearer token wins when present; otherwise `X-Api-Key`.
  Key scopes are permission codes, so the same `require_permission`
  gates apply. `X-Organization-Id`, when present, must match the key's
  org (else 403). Endpoints that need a user identity (`/auth/me`,
  logout, MFA, notifications list/read-all, `/organizations/mine`,
  change approve/reject) reject API keys with 403 via
  `get_user_principal`.
- Scheduled reports: `run_scheduled_report` emails one CSV per
  recipient (`<slug>-YYYYMMDD-HHMM.csv`, NULL-styled, template
  `scheduled_report`, `retry=False` — the CSV bytes are not stored, so
  a failed delivery is recorded in `email_deliveries` and the next run
  re-sends; `last_status` reflects generation only). Sweep
  (`null.tasks.sweep_scheduled_reports`, beat every 5 min) fires each
  due schedule once per cron minute, using the (last run, now] window.
- **Field encryption (deployment note):** webhook secrets and
  integration credentials are Fernet-encrypted at rest under
  `NULL_FIELD_ENCRYPTION_KEY` and creation fails closed without it.
  The live-boot scripts generate a fresh dev key per run; see
  `docs/DEV_SETUP.md` §2.
- **Bug found live (Nov 26):** the patch handler's `new_findings` is an
  INT count while the vuln handler's is a LIST of payloads; the agent
  job-result endpoint iterated it unconditionally and 500'd on every
  patch result (`TypeError: 'int' object is not iterable`). Fixed by
  iterating only the list shape; regression test
  `test_patch_job_result_still_accepted` covers it.

**Verification (Nov 26, 2026):** full suite **389 passed** via the locked
script (`bash scripts/run_tests_locked.sh -q`, ~84s) — 297 pre-Phase-4 +
92 Phase 4 tests (75 workstream: A 24 + B 19 + C 19 + D 13; 17
integration in `tests/test_phase4_integration.py`, incl. the
patch-result regression test). Live boot **33/33**
(`scripts/live_boot_check.py`, port 8002, fresh empty DB) plus a live
Phase 4 smoke **19/19** (every new route exercised against the booted
server: workflows, automation rules, forms, dashboards, reports +
generate + schedule, webhooks, integrations, API keys + live key auth,
GRC, releases, feature flags, status incidents + public page, OpenAPI
523 operations across 351 paths, 528 routes total).

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
