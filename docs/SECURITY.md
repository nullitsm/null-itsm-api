# NULL ITSM API — Security Model

This document states how the backend protects tenants, identities, and
audit data. It is a description of what is implemented and verified, not
an aspiration. Anything marked "gated" is code-only until the named
approval exists.

## 1. Multi-tenancy (the non-negotiable)

- Every tenant-owned row carries `organization_id`.
- PostgreSQL Row-Level Security is enabled on every tenant table
  (migrations 0001–0002). Policies are enforced for the application role
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
- Sessions expire; logout revokes; login anomalies are audited.
- Rate limiting (slowapi, shared limiter in `app/rate_limit.py`): login
  10/min, MFA challenge 10/min, password-reset request 5/min. Disabled
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

## 8. Known gaps (Phase 1)

- OIDC production provider (Cognito) not provisioned — local dev JWT
  issuer only. **Gated.**
- No WAF, no centralized SIEM ingestion, no automated security testing
  pipeline yet (Phase 5 / Tier 1).
- Agent command allowlisting and signed agent updates are defined in the
  Phase 3 contract (`docs/API_CONTRACT.md` §9) but not implemented — the
  agent does not exist yet.
- The dev fixtures (`DevPass123!@#`, `platform@null.example.com`) are
  gated by `NULL_SEED_DEV_FIXTURES=true` and must never run in production.
