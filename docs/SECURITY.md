# NULL ITSM API — Security Model

This document states how the backend protects tenants, identities, and
audit data. It is a description of what is implemented and verified, not
an aspiration. Anything marked "gated" is code-only until the named
approval exists.

## 1. Multi-tenancy (the non-negotiable)

- Every tenant-owned row carries `organization_id`.
- PostgreSQL Row-Level Security is enabled on every tenant table
  (migrations 0001–0008). Policies are enforced for the application role
  `null_app`, which owns nothing and has no `BYPASSRLS`.
- RLS is enabled, NOT forced: owner-owned SECURITY DEFINER functions must
  bypass RLS to read a credential row before any context exists (see
  `docs/DECISIONS.md`). The app never connects as the owner.
- Per-request context is `SET LOCAL app.current_org_id` /
  `app.current_user_id` / `app.current_platform_user_id`, set server-side
  from the authenticated session — never from a client-supplied org id
  alone. `SET LOCAL` dies with the transaction, so context cannot leak
  between requests.
- Tenant resolution: the token's org claim or the `X-Organization-Id`
  header is only a *request*; an active membership is the authority.
  Cross-org access returns 404 (never reveals existence) or 403.
- Background jobs are tenant-aware (Celery tasks carry `org_id`).
- Verified by tests: API-level isolation, raw-SQL RLS checks as the app
  role, cross-org insert rejection, no-context invisibility.

## 2. Two administrative domains

Organization users and platform admin users are separate models,
separate sessions, separate roles, separate permission namespaces, and
separate JWT types (`access` vs `platform_access`).

| | Organization domain | Platform domain |
|---|---|---|
| Identity | `users` (+ `memberships`) | `platform_users` |
| Roles | `roles` (per-org) | `platform_roles` (global) |
| Permissions | org catalog (no `platform:*` code) | `platform:*` catalog (17 codes) |
| Sessions | `sessions` | `platform_sessions` (+ `mfa_verified`) |
| Audit | `audit_logs` | `platform_audit_logs` |
| RLS context | `app.current_org_id` + `app.current_user_id` | `app.current_platform_user_id` (no org context) |

Rules enforced in the backend (not navigation visibility):
- Org roles can never grant platform permissions (the org catalog has no
  such code; the org role editor rejects `platform:`-prefixed codes).
- Platform roles cannot be assigned through the org role editor.
- No auto-conversion: an org admin is never a platform admin.
- Only Platform Super Admin holds `platform:roles:manage` and may
  grant/revoke the Platform Super Admin role.
- Platform `*:manage` permissions require an MFA-verified token
  (`mfa: true`); `*:read` works without MFA. Refresh preserves the `mfa`
  claim from the session row, never from the presented token.
- Platform access to tenant data requires an explicit, time-boxed
  `platform_access_grants` row, enforced in the database
  (`platform_support_list_org_users`) and written to the platform audit
  log. Without a grant the tenant-users endpoint returns `[]`.
- A platform session sets no org context, so org tables are invisible to
  it through the ORM; tenant reads go only through the grant-checked
  SECURITY DEFINER functions.

## 3. Authentication

- Passwords: Argon2id (`hash_password` / `verify_password`). Minimum 12
  characters. Never plaintext, never in the repo.
- Refresh / invitation / password-reset tokens: opaque, stored ONLY as
  SHA-256 hashes. Raw tokens are shown once and never persisted.
- Access tokens: JWT HS256 (dev issuer) / RS256 via JWKS when
  `NULL_OIDC_ISSUER` is set (production: AWS Cognito — **gated on
  infrastructure approval**). 15-minute lifetime; refresh tokens 7 days,
  rotated on every use (old token revoked; reuse fails).
- MFA: TOTP (pyotp). Enrollment shows the secret + provisioning URI once.
  Login with MFA enabled returns a short-lived `mfa` token; the access
  token is issued only after the challenge. Privileged platform access
  requires the `mfa` claim (see §2).
- Password reset: always-200, no enumeration (unknown emails get the same
  response). Invitation acceptance creates the user + membership + roles.
- Registration: public `POST /api/v1/auth/register` (5/min) creates the
  org + first admin + owner membership + Organization Administrator
  grant + default departments + onboarding record, then signs the admin
  in. It never creates a platform administrator; an existing admin
  email is refused (409) so nobody can attach an org to someone else's
  account. Invitations are single-use, SHA-256-hashed, bound to email
  + org, and expire after 48 hours (`invitation_days = 2`); resend
  rotates the token. Org and platform invitations are separate tables
  and flows — an org invitation can never create a platform admin.
  With SMTP unconfigured, invitation mail goes to the `dev_email_outbox`
  table (local testing only) and the accept link is returned to the
  inviting admin; the raw token is never logged.
- Sessions expire; logout revokes; login anomalies are audited.
- Rate limiting (slowapi, shared limiter in `app/rate_limit.py`): login
  10/min, MFA challenge 10/min, registration 5/min, password-reset request 5/min. Disabled
  in tests via `limiter.enabled = False` on the one shared instance.

## 4. Authorization

- Permission-based, per organization (org domain) or platform-wide
  (platform domain). Missing permission → 403, audited.
- **Grant-scope rule:** an actor may only grant permissions they hold.
  Enforced on role creation, permission configuration, role assignment,
  and invitation roles (both domains).
- **Self-escalation prevention:** no self role assignment, no
  self-revocation of privileged roles, no self-suspension. Revoking the
  last owner's Organization Administrator role (or the last Platform
  Super Admin's role) is refused.
- **Elevated access:** when the org policy requires approval, assigning a
  Privileged/Full Access role creates a pending `AccessApproval` instead
  of granting; an administrator decides it.
- **Access expiration:** memberships and invitations carry `expires_at`;
  a Celery task suspends expired memberships hourly.
- Failed authorization attempts are audited.

## 5. Audit (append-only)

- Every event records organization, actor, action, resource type,
  resource id, timestamp, outcome, metadata.
- Covered: authentication events, membership changes, invitations, role
  assignments, permission modifications, admin changes, failed
  authorization attempts, sensitive operations, platform tenant reads.
- Append-only by design: the RLS policy set contains NO UPDATE/DELETE
  policy for `audit_logs` / `platform_audit_logs`, and no write API
  exists. PostgreSQL's default-deny updates/deletes zero rows (verified
  by test — see `docs/DECISIONS.md`).

## 6. Secrets and transport

- Secrets only via environment variables (`.env.example`, never real
  secrets in the repo, never secrets in frontend code).
- Production secrets live in AWS Secrets Manager; TOTP secrets are
  encrypted at rest in production (KMS). **Gated on infrastructure
  approval.**
- HTTPS in production (ALB + ACM — **gated**). Local dev is HTTP on
  localhost only.
- CORS: development origins only by default; production sets
  `NULL_CORS_ORIGINS` explicitly.

## 7. Data protection and integrity

- Vulnerability findings: real engines, real CVE/KEV data, real stored
  evidence. Simulated states are clearly labelled. Never invent findings
  or claim simulated commands ran on real devices.
- GRC features help customers manage compliance; they do NOT make NULL
  certified. Never claim certification.
- Backups / DR / RTO/RPO: **planned in Phase 5, gated on infrastructure
  approval**. No backup exists yet; do not claim one does.
- Input validation on every endpoint (Pydantic); request-id logging;
  validation errors return 422 with per-field details.

## 8. Known gaps (Phase 2)

- OIDC production provider (Cognito) not provisioned — local dev JWT
  issuer only. **Gated.**
- No WAF, no centralized SIEM ingestion, no automated security testing
  pipeline yet (Phase 5 / Tier 1).
- Agent command allowlisting and signed agent updates are defined in the
  Phase 3 contract (`docs/API_CONTRACT.md` §9) and implemented on the
  backend side (job types are allowlisted server-side; the agent repo
  itself does not exist yet, so no real device enforces the allowlist
  yet). Update checks return `download_url: null` — no artifact storage
  is configured, so no update is ever offered.
- SAML ACS validates assertions but mints no session (SSO session
  issuance is out of scope for Phase 2); portal login rejects
  MFA-enabled users (no MFA challenge step in the portal).
- Collision detection is not built (Phase 2, Tier 2).
- No sample data: there are no dev fixtures or demo records in the repo
  (removed Nov 26, 2026). A fresh database is empty; tests build their
  own data in the test database via `tests/factories.py`.

## 9. Phase 2 additions (Nov 26, 2026)

- **Third token type:** portal sessions use JWT type `portal_access`
  (60 min, recorded by SHA-256 hash in `portal_sessions`). A portal
  token never authenticates a non-portal endpoint; an org `access`
  token never authenticates a portal endpoint. Portal endpoints scope
  to the caller's own records (another user's ticket/request is 404).
- **SCIM bearer tokens:** `scim_tokens` rows hold only SHA-256 hashes;
  the raw token is shown once at creation. Lookup goes through the
  SECURITY DEFINER function `auth_get_scim_token_by_hash` (exact-hash
  match, at most one row). A token is bound to its org server-side —
  the client never supplies the org id.
- **SAML ACS is unauthenticated by design** (the IdP posts the
  assertion): the provider row is resolved through the SECURITY
  DEFINER function `auth_get_identity_provider_by_id`, which returns
  public config only (never secrets). Assertions are validated with
  `python3-saml`; an unvalidatable assertion is never accepted, and a
  validated assertion mints no session.
- **Field encryption:** per-org mailbox passwords, OIDC client secrets,
  and license keys are Fernet-encrypted at rest (`app/crypto.py`,
  key from `NULL_FIELD_ENCRYPTION_KEY`). Encryption fails closed
  (503) when no key is configured — secrets are never stored plaintext
  as a fallback. Service-account / API-credential secrets are stored
  only as SHA-256 hashes and shown once at creation.
- **Sweep enumeration:** Celery sweeps enumerate organizations through
  the grant-checked SECURITY DEFINER function `list_organization_ids()`
  (migration 0008, ids only) and the narrower
  `email_list_active_mailbox_orgs()` (migration 0006). Per-org work is
  always RLS-scoped to the enumerated id.
- **Offboarding** (`POST /api/v1/assets/offboard`) is one transaction:
  suspend membership, revoke sessions, create recovery tickets,
  return assets, revoke temp grants, audit with the full report.
  Offboarding the org owner is refused.
- **Attachments are metadata only:** file bytes go to the storage
  backend when configured; when storage is unconfigured the upload
  endpoint returns 503 and stores nothing. File content is never
  stored in the database.
- **Append-only additions:** `asset_lifecycle_events` (SELECT+INSERT
  RLS only, like the audit logs) and the same rule for
  `knowledge_feedback` / `survey_responses`.

## 10. Phase 3 additions (Nov 26, 2026)

- **Device authentication:** enrollment tokens and device tokens are
  stored only as SHA-256 hashes; raw values are shown once at creation.
  Pre-auth lookups go through SECURITY DEFINER functions
  (`auth_get_enrollment_token_by_hash`,
  `auth_get_endpoint_by_device_token`) — exact-hash match, at most one
  row. Enrollment tokens are single-use and consumed atomically (a
  concurrent second enroll with the same token gets 401). A device
  token authenticates only its own device's agent endpoints; it
  confers no user permissions and cannot call any user endpoint.
  Revoking an endpoint (or its token) makes every agent call 401.
- **Agent jobs are server-allowlisted by type** (`patch_scan`,
  `patch_deploy`, `vuln_scan`, `inventory_refresh`); the backend never
  sends arbitrary shell strings, and a job is issued only to the device
  it names, only when the issuing user held the relevant permission at
  issue time. Delivery is at-most-once; results are attributable to
  the device that ran them. A failing downstream result handler is
  audited (`agent.job_result_handler_failed`) and swallowed so the
  device's recorded result survives — a device's result is ground
  truth, and the apply functions are idempotent.
- **Vuln engine credentials:** Greenbone (and future engine) passwords
  are Fernet-encrypted at rest (`app/crypto.py`, key from
  `NULL_FIELD_ENCRYPTION_KEY`); storing one with no key configured
  fails closed with 503, never plaintext. Secrets are never returned
  by the API (`has_password` only). SNMP communities are stored
  encrypted the same way and never returned.
- **Global tables without RLS:** `agent_releases` and `cve_catalog`
  are public, non-tenant data (a release catalog and public CVE/KEV
  data). They carry no `organization_id` and no RLS policy — by
  design, not by omission. Everything org-scoped in Phase 3 uses the
  standard RLS ALL policy.
- **Verification flow authorization:** issuing a verification
  `vuln_scan` job is authorized by the verify call's
  `vulnerabilities:manage` permission; the job payload carries only
  the finding id (`verify_finding_id`). A finding can reach
  `remediated` only through the remediate → verify flow (direct PATCH
  to `remediated` is 400), so verification evidence (agent rescan or
  imported rescan) is always attached before a finding can become
  `verified`.
- **No invented findings:** scan results, patch findings, and
  vulnerability findings come only from agent results, engine polls,
  or operator imports. CVE/KEV data comes only from the real NVD API
  and CISA KEV feed; a failed sync leaves the catalog unchanged.

## 11. Phase 4 additions (Nov 26, 2026)

- **API keys:** raw key shown once at creation; only the SHA-256 hash
  is stored; lookups go through the SECURITY DEFINER function
  `auth_get_api_key_by_hash` (exact-hash match). A key authenticates
  only its own org — `X-Organization-Id`, when present, must match
  the key's org (else 403) — and its scopes ARE permission codes, so
  the same `require_permission` gates apply. A present-but-invalid
  Bearer token is a 401 and never falls through to key auth. Endpoints
  that need a user identity (`/auth/me`, logout, MFA, notification
  list/read-all, `/organizations/mine`, change approve/reject) reject
  API keys with 403 (`get_user_principal`). `last_used_at` is stamped
  on successful key auth.
- **Webhook secrets + integration credentials:** Fernet-encrypted at
  rest under `NULL_FIELD_ENCRYPTION_KEY` (same store as vuln engine
  passwords); creation fails closed without a key — there is no
  plaintext fallback. Webhook payloads are HMAC-SHA256 signed
  (`X-NULL-Signature`) with the per-webhook secret; the secret is
  returned once at creation and never again. Delivery rows are
  append-only.
- **Status page public endpoint:** `GET /api/v1/status/public/{slug}`
  needs no auth and returns incidents + updates only (resolved via the
  SECURITY DEFINER `status_page_org_id_by_slug`); no other org data is
  reachable through it.
- **GRC honesty:** control `status` is derived only — an active
  exception → `exception`, the latest assessment outcome →
  `satisfied`/`failed`/`in_progress`, none → `not_assessed`.
  `satisfied` records that an assessment passed; it is not a
  certification claim and must never be presented as one.
- **Automation cannot break writes:** automation rules and webhook
  emission run after the ticket write commits; a failing rule action
  is recorded on the run as failed/partial and never fails the ticket
  write, and `emit_event` never raises into the request.
