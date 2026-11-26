# NULL ITSM API Contract

Backend: `nullitsm/null-itsm-api` — FastAPI + PostgreSQL (RLS) + Redis,
modular monolith. This document is the contract the frontend
(`frontend/null-api-client.js` in this repo) and the Phase 3 endpoint agent
(`nullitsm/null-endpoint-agent`) build against.

Source of truth for Phase 1: `app/routers/*.py`, `app/schemas.py`,
`app/deps.py`, `app/services/auth_service.py`, `app/config.py`,
`app/permissions.py`. If this document and the code disagree, the code wins
and this document must be corrected.

---

## 1. Base URL and versioning

- **Base URL (local dev):** `http://localhost:8000` (API listens on port 8000).
- **Version prefix:** all business endpoints live under `/api/v1/`. Health
  endpoints are unversioned (`/health`, `/health/ready`).
- **Versioning policy:** breaking changes get a new version prefix (`/api/v2/`);
  additive changes (new endpoints, new optional fields) stay on `/api/v1/`.
  Clients must ignore unknown response fields.
- **Content type:** JSON everywhere. Requests send
  `Content-Type: application/json`; responses are JSON except `204 No Content`.
- **IDs:** UUIDs (string form) for users, orgs, roles, tickets, invitations,
  approvals, reviews, audit rows. Ticket *numbers* are separate, human
  readable, per-org (`INC-000001`, …) — see §7.
- **Timestamps:** ISO 8601 with timezone (e.g. `2026-11-25T17:00:00Z`).

## 2. Authentication model

### 2.1 Token types

| Token | Lifetime | How it is issued | How it is stored (browser) |
|---|---|---|---|
| Access token (JWT, HS256, type `access`) | **15 minutes** | Login / MFA / org-select / org-switch / refresh | Memory only — never in any browser storage |
| Refresh token (opaque, SHA-256 hashed server-side) | **7 days** | Same as above | `sessionStorage`, key `null-itsm-refresh-token` |
| MFA token (JWT, type `mfa`) | **5 minutes** | Login when the user has MFA enabled | Memory only, single use for `/mfa/challenge` |
| Org-select token (JWT, type `org_select`) | Short-lived (login flow) | Login when the user belongs to >1 org | Memory only, single use for `/select-organization` |
| Password-reset token | **60 minutes** | `/password-reset/request` (emailed) | Not stored — arrives in the reset link |
| Invitation token | **7 days** | Technician invite (emailed) | Not stored — arrives in the invite link |
| Platform access token (JWT, HS256, type `platform_access`) | **15 minutes** | Platform login / MFA / refresh | Memory only — never in any browser storage |
| Platform MFA token (JWT, type `platform_mfa`) | **5 minutes** | Platform login when the platform user has MFA enabled | Memory only, single use for `/platform/auth/mfa-challenge` |
| Platform refresh token (opaque, SHA-256 hashed server-side) | **7 days** | Same as above | `sessionStorage`, key `null-itsm-platform-refresh-token` |

Access-token claims include `sub` (user id), `email`, and `org`
(organization id, absent until an org is chosen). Platform access tokens
carry `sub` (platform user id), `email`, and an `mfa` boolean claim.
**Org and platform tokens are distinct JWT types and are never
interchangeable**: an org token gets 401 on every `/api/v1/platform`
endpoint and a platform token gets 401 on every org endpoint. The client
must never trust decoded claims for authorization — the server verifies
the signature and re-checks membership on every request. The client only
reads `exp` for its route-protection helper.

### 2.2 Refresh rotation

`POST /api/v1/auth/refresh` **rotates**: the presented refresh token is
revoked (`revoked_at` set) and a fresh access + refresh pair is issued.
Reusing a revoked refresh token fails with 401. The browser client retries
a 401 exactly once after a successful refresh; if the refresh fails, it
clears all local session state and fires `onUnauthorized`.

### 2.3 Login flow (status machine)

`POST /api/v1/auth/login` returns a `LoginResponse` whose `status` field
drives the next step — the client must branch on it, not on the presence
of tokens alone:

| `status` | Meaning | Next step |
|---|---|---|
| `ok` | Signed in, single org (or org already resolved) | Tokens present; go to Command Center |
| `mfa_required` | Password OK, MFA code needed | `POST /auth/mfa/challenge` with `mfa_token` + 6-digit code; the response is itself a `LoginResponse` (may then be `ok` or `org_required`) |
| `org_required` | Password (+ MFA) OK, user belongs to multiple orgs | `POST /auth/select-organization` with `Authorization: Bearer <org_select_token>` and `{organization_id}` |
| `no_org` | Authenticated but the user belongs to no org yet | `POST /api/v1/organizations` to create one, then `/auth/select-organization` with the `org_select_token` |

Wrong credentials / unknown or inactive user → `401` with a generic
detail (no distinction between "unknown email" and "wrong password").
Password-reset requests **always** return success, even for unknown
emails (no user enumeration).

### 2.4 Organization context and the `X-Organization-Id` header

Every authenticated request must identify its organization:

- The **token's `org` claim is the default** org.
- The client sends the current org as the **`X-Organization-Id` header on
  every request** (including health probes, where it is simply ignored).
- The server resolves the org as **header value if present, else the token
  claim**, then **verifies an active membership server-side**. A header
  naming an org the user does not belong to → `403 "No active membership
  in this organization"` (and the attempt is audited). An invalid UUID in
  the header → `403 "Invalid organization header"`. No org at all (token
  without `org`, no header) → `401 "No organization selected"`.
- The header can therefore *request* an org switch, but it cannot *grant*
  one: membership is the authority, and the org-scoped routes additionally
  reject a path org id that differs from the resolved org (`403
  "Organization mismatch"`).

Org switching while signed in: `POST /api/v1/auth/switch-organization`
with `{refresh_token, organization_id}` — it issues a fresh token pair
scoped to the new org (and rotates the refresh token). The client updates
its stored org context to match.

### 2.5 MFA management (authenticated)

- `POST /auth/mfa/enroll` → `{secret, otpauth_uri}`. Render the URI as a
  QR code; the secret is shown once.
- `POST /auth/mfa/verify-enrollment` with `{code}` (6 digits) → enables MFA.
- `POST /auth/mfa/disable` → disables MFA.
- MFA codes are 6 digits, exactly (`min_length=6, max_length=6`).

### 2.6 Logout

`POST /api/v1/auth/logout` (authenticated) with `{refresh_token}` revokes
that refresh session server-side. The client clears local state even if
the call fails — local teardown must never depend on the network.

## 3. Authorization model

Authorization is **permission-based, per organization**:

- Permissions are codes of the form `<module>:<action>` (e.g.
  `tickets:create`, `roles:manage`). The full catalog is served by
  `GET /api/v1/users/permissions/catalog` and seeded in `app/permissions.py`.
- A caller's permissions are loaded from their roles **in the resolved
  org** on every request (`get_principal` → `require_permission(...)`).
  Missing permission → `403 "Missing permission: <code>"` (audited).
- **Grant scope:** an actor may only grant permissions they themselves
  hold. Assigning a role or configuring role permissions with codes the
  caller lacks → `403 "Cannot grant permissions you do not hold: …"`.
  The Organization Administrator role holds every org permission, so it passes.
- **System roles** (seeded per org: Organization Administrator, IT
  Operations, Service Desk Technician, Endpoint Administrator, Security
  Analyst, Change Manager, Auditor, Employee / Requester) cannot be
  deleted or have their names changed; custom roles can.
- **Elevated-access approvals:** when the org policy requires approval for
  elevated roles, assigning such a role creates a pending approval instead
  of granting it outright; an approver decides via
  `POST /roles/approvals/{id}/decide` with `{approve: true|false}`.
- **Two domains (not one directory):** organization users and platform
  admin users are separate identities with separate permission namespaces
  (see §7.8). The org catalog contains **no** `platform:*` code, so no org
  role can ever grant platform access; the org role editor rejects any
  `platform:`-prefixed code with 400. Platform roles cannot be assigned
  through the org role editor, and an org admin is never automatically a
  platform admin (and vice versa).

Permissions actually enforced by Phase 1 endpoints:

| Permission | Used by |
|---|---|
| `org:manage` | `PATCH /organizations/{org_id}` |
| `users:invite` | Invite / list / revoke invitations |
| `users:manage` | List members, update member, list/get users, get user roles |
| `roles:manage` | Policy get/set, access reviews, roles CRUD, assign/revoke, approvals |
| `permissions:manage` | `PUT /roles/{role_id}/permissions` (note: distinct from `roles:manage`) |
| `audit:read` | `GET /api/v1/audit` |
| `tickets:read` / `tickets:create` / `tickets:update` | Tickets list/get, create, update |

All other catalogued codes (endpoints, patching, vulnerabilities, changes,
CMDB, billing, …) exist in the catalog now but are **not
enforced by any Phase 1 endpoint** — they are granted by later-phase roles.

## 4. Error model

FastAPI's standard error shape; there is no custom envelope.

- **Simple errors** (401 / 403 / 404 / 400): `{"detail": "<message>"}`
  with a human-readable string.
- **Validation errors (422):** `{"detail": [{"loc": [...], "msg": "...",
  "type": "..."}, ...]}` — one entry per offending field. The browser
  client surfaces the first entry's `msg` and keeps the full list in
  `NullApiError.errors`.
- **Network failure:** no HTTP response at all. The browser client throws
  `NullApiError` with `status: 0`.

| Status | Meaning in this API |
|---|---|
| 200 | Success (GET, PATCH/PUT, POST actions) |
| 201 | Created (org, invitation, role, ticket, access review) |
| 204 | Deleted, no body (`DELETE /roles/{id}`) |
| 400 | Bad request — invalid enum value, invalid state transition, bad token payload (invitation accept, password reset, role ops) |
| 401 | Missing/invalid/expired token or refresh token; wrong credentials; MFA failure. Triggers the client's one-time refresh flow |
| 403 | Forbidden — missing permission, org mismatch, no membership in the requested org, grant-scope violation |
| 404 | Not found — **and deliberately also "exists in another org"** (see §6) |
| 422 | Request validation failed (missing/wrong-typed fields, bad email, password too short) |
| 429 | Rate limit exceeded (auth endpoints only, §5) |
| 500 | Unexpected server error (body still `{"detail": ...}`) |

Clients must treat `detail` as displayable text, but must not parse it
for control flow — branch on the status code (and, for login, on the
`status` field of the 200 response).

## 5. Rate limits

Applied with slowapi, per client IP (`X-Forwarded-For` first entry when
present, else the remote address). Redis-backed when available.

| Endpoint | Limit |
|---|---|
| `POST /api/v1/auth/login` | 10/minute |
| `POST /api/v1/auth/mfa/challenge` | 10/minute |
| `POST /api/v1/auth/password-reset/request` | 5/minute |

No other Phase 1 endpoint is rate-limited. Exceeding a limit returns
`429`. The client must surface the 429 message and not retry in a tight
loop; the sign-in UI should disable the submit button briefly after a
429 rather than letting the user hammer it.

## 6. Tenant isolation (RLS) contract

This is the contract Phase 1 exists to prove; every later phase inherits it.

1. **Server-side org resolution, always.** The org used for a request is
   resolved by the server from the token claim / `X-Organization-Id`
   header plus a membership lookup. The client never supplies the org as
   a body field to gain access, and no endpoint trusts a body-supplied
   org id.
2. **Row-level security (RLS) on tenant tables.** Each request runs with
   the Postgres session scoped to the resolved org (and user) before any
   tenant table is touched, so even a buggy query cannot return another
   org's rows.
3. **404s never reveal another org's records.** `GET /tickets/{id}` and
   `PATCH /tickets/{id}` return `404 "Ticket not found"` identically
   whether the ticket does not exist or belongs to another org.
   `GET /users/{id}` returns `404 "User not found in this organization"`
   for non-members. Callers must not distinguish the two cases.
4. **403s for org mismatch, not 404s.** The org-scoped routes
   (`/organizations/{org_id}/…`) return `403 "Organization mismatch"`
   when the path org differs from the resolved org, and `403 "No active
   membership in this organization"` when the header names an org the
   caller does not belong to. Cross-org access attempts are **audited**
   (`authz.denied` — exact action code lives in `app/audit.py`).
5. **Per-org numbering.** Ticket numbers are per-org sequences
   (`INC-000001`, …) via a row-locked counter; numbers are not globally
   unique and must always be displayed with their org context.
6. **Audit is append-only.** The audit log has exactly one endpoint:
   `GET /api/v1/audit` (read-only, `audit:read`). There is deliberately
   no update or delete endpoint for audit records anywhere in the API.
   Auth events (login, token refresh, logout, denied authorization) and
   ticket create/update are written server-side; clients cannot write
   audit rows.

## 7. Endpoint reference

`Auth` = Bearer access token required (plus `X-Organization-Id` where an
org is resolved). `Perm` = additional permission in the resolved org.
Bodies are JSON; `—` means no body. All paths are relative to the base
URL. Response shapes use the Pydantic schemas in `app/schemas.py`.

### 7.1 Auth — `POST /api/v1/auth/*`, `GET /api/v1/auth/me`

| Method | Path | Auth / Perm | Request body | Response |
|---|---|---|---|---|
| POST | `/api/v1/auth/login` | None (10/min) | `{email, password}` | `LoginResponse`: `{status: ok\|mfa_required\|org_required\|no_org, access_token?, refresh_token?, mfa_token?, org_select_token?, user_id?, organizations?}` |
| POST | `/api/v1/auth/mfa/challenge` | None (10/min) | `{mfa_token, code}` (6 digits) | `LoginResponse` (same shape as login) |
| POST | `/api/v1/auth/select-organization` | Bearer `org_select_token` | `{organization_id}` | `TokenResponse`: `{access_token, refresh_token, token_type: "bearer"}` |
| POST | `/api/v1/auth/switch-organization` | None (refresh token in body) | `{refresh_token, organization_id}` | `TokenResponse` |
| POST | `/api/v1/auth/refresh` | None (refresh token in body) | `{refresh_token}` | `TokenResponse` (rotated pair) |
| POST | `/api/v1/auth/logout` | Bearer | `{refresh_token}` | `{status: "ok"}` |
| POST | `/api/v1/auth/password-reset/request` | None (5/min) | `{email}` | `{status: "ok", detail: "If an account exists, a reset link was sent."}` — always, even for unknown emails |
| POST | `/api/v1/auth/password-reset/confirm` | None | `{token, new_password}` (min 12 chars) | `{status: "ok"}` |
| POST | `/api/v1/auth/invitations/accept` | None | `{token, full_name, password}` (password min 12) | `{status: "ok", user_id, organization_id, organization_slug}` |
| POST | `/api/v1/auth/mfa/enroll` | Bearer | — | `{secret, otpauth_uri}` |
| POST | `/api/v1/auth/mfa/verify-enrollment` | Bearer | `{code}` (6 digits) | `{status: "ok", mfa_enabled: true}` |
| POST | `/api/v1/auth/mfa/disable` | Bearer | — | `{status: "ok", mfa_enabled: false}` |
| GET | `/api/v1/auth/me` | Bearer | — | `{user_id, email, organization_id, organization_slug, is_org_owner, permissions: string[]}` |

### 7.2 Organizations — `/api/v1/organizations`

| Method | Path | Auth / Perm | Request body | Response |
|---|---|---|---|---|
| POST | `/api/v1/organizations` | Bearer (any authenticated user, incl. no-org) | `{name, slug?}` | `OrganizationOut` (201): `{id, name, slug, is_active, is_dev_fixture, created_at}` |
| GET | `/api/v1/organizations/mine` | Bearer | — | `OrganizationOut[]` (active memberships only) |
| GET | `/api/v1/organizations/{org_id}` | Bearer | — | `OrganizationOut` (403 on org mismatch) |
| PATCH | `/api/v1/organizations/{org_id}` | Bearer + `org:manage` | `{name?}` | `OrganizationOut` |
| GET | `/api/v1/organizations/{org_id}/members` | Bearer + `users:manage` | — | `MemberOut[]`: `{user_id, email, full_name, status, is_owner, expires_at, joined_at}` |
| PATCH | `/api/v1/organizations/{org_id}/members/{user_id}` | Bearer + `users:manage` | `{status: active\|suspended, expires_at?}` | `{status: "ok", membership_status}` |
| GET | `/api/v1/organizations/{org_id}/policy` | Bearer + `roles:manage` | — | Policy object (see below) |
| PUT | `/api/v1/organizations/{org_id}/policy` | Bearer + `roles:manage` | Any of `{enforce_least_privilege, require_approval_for_elevated, periodic_access_review, access_expiration, access_review_schedule}` | Updated policy object |
| POST | `/api/v1/organizations/{org_id}/invitations` | Bearer + `users:invite` | `{email, role_ids?: string[]}` | `InvitationOut` (201): `{id, email, status, expires_at, created_at}` — the invite token is emailed, never returned |
| GET | `/api/v1/organizations/{org_id}/invitations` | Bearer + `users:invite` | — | `InvitationOut[]`, newest first |
| POST | `/api/v1/organizations/{org_id}/invitations/{invitation_id}/revoke` | Bearer + `users:invite` | — | `{status: "ok"}` (404 when the invitation does not exist in this org) |
| POST | `/api/v1/organizations/{org_id}/access-reviews` | Bearer + `roles:manage` | — | `{id, status, created_at}` (201) |
| POST | `/api/v1/organizations/{org_id}/access-reviews/{review_id}/complete` | Bearer + `roles:manage` | — | `{id, status}` (404 when the review does not exist in this org) |

Policy object fields (all optional on write; read returns the org's
current values): `enforce_least_privilege`, `require_approval_for_elevated`,
`periodic_access_review`, `access_expiration` (booleans) and
`access_review_schedule` (string, e.g. a cadence label). Exact defaults
live in `app/services/org_service.py` (`get_policy` / `set_policy`).

### 7.3 Users — `/api/v1/users`

| Method | Path | Auth / Perm | Request body | Response |
|---|---|---|---|---|
| GET | `/api/v1/users` | Bearer + `users:manage` | — | `UserOut[]`: `{id, email, full_name, is_active, mfa_enabled, roles: string[]}` (role *names*), active members of the current org, ordered by name |
| GET | `/api/v1/users/permissions/catalog` | Bearer + `roles:manage` | — | `PermissionOut[]`: `{code, module, description}`, ordered by module then code |
| GET | `/api/v1/users/{user_id}` | Bearer + `users:manage` | — | `UserOut` (404 when the user has no membership in this org) |
| GET | `/api/v1/users/{user_id}/roles` | Bearer + `users:manage` | — | `string[]` (role names) |

Note the route order: `/permissions/catalog` is declared before
`/{user_id}`, so `catalog` is never mistaken for a user id.

### 7.4 Roles — `/api/v1/roles`

| Method | Path | Auth / Perm | Request body | Response |
|---|---|---|---|---|
| GET | `/api/v1/roles` | Bearer + `roles:manage` | — | `RoleOut[]`: `{id, name, description, access_level, is_system, permissions: string[]}` |
| POST | `/api/v1/roles` | Bearer + `roles:manage` | `{name, description?, access_level?, permission_codes?}` (defaults: `""`, `"Least Privilege"`, `[]`) | `RoleOut` (201) |
| GET | `/api/v1/roles/{role_id}` | Bearer + `roles:manage` | — | `RoleOut` (404 when not in this org) |
| PATCH | `/api/v1/roles/{role_id}` | Bearer + `roles:manage` | `{description?, access_level?}` (name is not editable here) | `RoleOut` |
| DELETE | `/api/v1/roles/{role_id}` | Bearer + `roles:manage` | — | 204 No Content (400 for system roles / roles that cannot be deleted) |
| PUT | `/api/v1/roles/{role_id}/permissions` | Bearer + `permissions:manage` | `{permission_codes: string[]}` (replaces the whole set) | `RoleOut` |
| POST | `/api/v1/roles/assign` | Bearer + `roles:manage` | `{user_id, role_id}` | Assignment result object from `role_service.assign_role` (may create a pending approval instead of granting, when policy requires it) |
| POST | `/api/v1/roles/revoke` | Bearer + `roles:manage` | `{user_id, role_id}` | `{status: "ok"}` |
| GET | `/api/v1/roles/approvals/pending` | Bearer + `roles:manage` | — | `ApprovalOut[]`: `{id, requested_by_id, target_user_id, role_id, status, created_at}` |
| POST | `/api/v1/roles/approvals/{approval_id}/decide` | Bearer + `roles:manage` | `{approve: boolean}` | `{status}` (approved/denied) |

### 7.5 Audit — `/api/v1/audit`

| Method | Path | Auth / Perm | Query params | Response |
|---|---|---|---|---|
| GET | `/api/v1/audit` | Bearer + `audit:read` | `action?`, `actor_id?`, `limit` (default 100, max 500), `offset` (default 0) | `AuditLogOut[]`, newest first: `{id, organization_id, actor_id?, action, resource_type, resource_id, outcome, metadata, created_at}` |

There are **no** POST / PATCH / DELETE audit endpoints. Audit is
append-only by design (§6).

### 7.6 Tickets — `/api/v1/tickets`

| Method | Path | Auth / Perm | Request body | Response |
|---|---|---|---|---|
| GET | `/api/v1/tickets` | Bearer + `tickets:read` | — | `TicketOut[]`, newest first |
| POST | `/api/v1/tickets` | Bearer + `tickets:create` | `{title, description?, priority?, category?}` (priority default `medium`, category default `General`) | `TicketOut` (201) |
| GET | `/api/v1/tickets/{ticket_id}` | Bearer + `tickets:read` | — | `TicketOut` (404 also when the ticket belongs to another org) |
| PATCH | `/api/v1/tickets/{ticket_id}` | Bearer + `tickets:update` | `{status?, priority?, assignee_id?}` (only supplied fields change) | `TicketOut` (404 also for another org's ticket) |

`TicketOut`: `{id, organization_id, number, title, description, status,
priority, category, requester_id?, assignee_id?, created_at, updated_at}`.
Valid statuses: `open`, `in_progress`, `pending`, `resolved`, `closed`.
Valid priorities: `low`, `medium`, `high`, `critical`. Invalid values →
400. `number` is assigned server-side (`INC-000001`, per-org sequence);
the requester is the caller; new tickets start `open`. Ticket create and
update write audit rows server-side.

### 7.7 Health (unversioned, unauthenticated)

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/health` | None | `{status: "ok", service: "null-itsm-api"}` — liveness, no dependencies |
| GET | `/health/ready` | None | `{status: "ok"\|"degraded", checks: {database: "ok"\| "error: …", redis: "ok" \| "error: …"}}` — **always HTTP 200**; callers must inspect `status`, not the HTTP code |

### 7.8 Platform Admin — `/api/v1/platform` (separate domain)

The Platform Admin Console API. Authenticated with **platform** tokens
only (type `platform_access`); org tokens get 401 here. `Perm` is a
`platform:*` permission. **MFA rule (enforced centrally): every
`*:manage` permission requires an MFA-verified token (`mfa: true` in the
JWT); every `*:read` works with `mfa: false`.** The platform refresh flow
preserves the `mfa` claim from the session row (`platform_sessions.
mfa_verified`, migration 0003), so a password-only login can never
escalate to a privileged token.

| Method | Path | Auth / Perm | Request body | Response |
|---|---|---|---|---|
| POST | `/api/v1/platform/auth/login` | None (10/min) | `{email, password}` | `{status: ok\|mfa_required, access_token?, refresh_token?, mfa_token?}` |
| POST | `/api/v1/platform/auth/mfa-challenge` | None (10/min) | `{mfa_token, code}` (6 digits) | Token pair, access token with `mfa: true` |
| POST | `/api/v1/platform/auth/refresh` | None (refresh token in body) | `{refresh_token}` | Rotated pair; `mfa` claim preserved from the session |
| POST | `/api/v1/platform/auth/logout` | Bearer (platform) | `{refresh_token}` | `{status: "ok"}` |
| POST | `/api/v1/platform/auth/mfa-enroll` | Bearer (platform) | — | `{secret, otpauth_uri}` |
| POST | `/api/v1/platform/auth/mfa-verify` | Bearer (platform) | `{code}` (6 digits) | `{status: "ok", mfa_enabled: true}` |
| GET | `/api/v1/platform/auth/me` | Bearer (platform) | — | `{platform_user_id, email, permissions: string[], mfa: boolean}` |
| GET | `/api/v1/platform/permissions` | Bearer + `platform:roles:read` | — | `PlatformPermissionOut[]`: `{code, module, description}` (17 codes) |
| GET | `/api/v1/platform/admins` | Bearer + `platform:users:read` | — | `PlatformUserOut[]`: `{id, email, full_name, is_active, mfa_enabled, source, review_status, roles: string[]}` |
| POST | `/api/v1/platform/admins` | Bearer + `platform:users:manage` (MFA) | `{email, full_name, password}` (min 12) | `PlatformUserOut` (201) |
| GET | `/api/v1/platform/admins/{id}` | Bearer + `platform:users:read` | — | `PlatformUserOut` |
| PATCH | `/api/v1/platform/admins/{id}/suspend` | Bearer + `platform:users:manage` (MFA) | — | `PlatformUserOut` (400 on self-suspend) |
| POST | `/api/v1/platform/admins/{id}/reactivate` | Bearer + `platform:users:manage` (MFA) | — | `PlatformUserOut` |
| POST | `/api/v1/platform/admins/{id}/roles` | Bearer + `platform:users:manage` (MFA) | `{role_id}` | `{status: "ok"}` (403 when assigning Platform Super Admin without `platform:roles:manage`; 400 on self-assignment) |
| DELETE | `/api/v1/platform/admins/{id}/roles/{role_id}` | Bearer + `platform:users:manage` (MFA) | — | `{status: "ok"}` (400 when revoking the last Super Admin's role or self-revoking a privileged role) |
| GET | `/api/v1/platform/roles` | Bearer + `platform:roles:read` | — | `PlatformRoleOut[]`: `{id, name, description, access_level, is_system, permissions: string[]}` (6 templates) |
| POST | `/api/v1/platform/roles` | Bearer + `platform:roles:manage` (MFA) | `{name, description?, access_level?, permission_codes?}` | `PlatformRoleOut` (201) |
| GET | `/api/v1/platform/roles/{id}` | Bearer + `platform:roles:read` | — | `PlatformRoleOut` |
| PATCH | `/api/v1/platform/roles/{id}` | Bearer + `platform:roles:manage` (MFA) | `{description?, access_level?}` | `PlatformRoleOut` |
| DELETE | `/api/v1/platform/roles/{id}` | Bearer + `platform:roles:manage` (MFA) | — | 204 No Content (400 for system roles / assigned roles) |
| PUT | `/api/v1/platform/roles/{id}/permissions` | Bearer + `platform:roles:manage` (MFA) | `{permission_codes: string[]}` | `PlatformRoleOut` |
| GET | `/api/v1/platform/tenants` | Bearer + `platform:tenants:read` | — | `TenantOut[]`: `{id, name, slug, is_active, is_dev_fixture, created_at}` |
| GET | `/api/v1/platform/tenants/{org_id}` | Bearer + `platform:tenants:read` | — | `TenantOut` (404 when the org does not exist) |
| GET | `/api/v1/platform/tenants/{org_id}/users` | Bearer + `platform:support:read` | — | `TenantUserOut[]`: `{id, email, full_name, is_active}` — **only with an active, unexpired support grant**; without one it returns `[]` (indistinguishable from an empty org). Every read is audited (`platform.tenant_users_read`). |
| POST | `/api/v1/platform/support-grants` | Bearer + `platform:support:manage` (MFA) | `{organization_id, purpose, expires_at}` | `SupportGrantOut` (201, status `pending`): `{id, platform_user_id, organization_id, purpose, status, expires_at, created_at}` |
| GET | `/api/v1/platform/support-grants` | Bearer + `platform:support:read` | — | `SupportGrantOut[]`, newest first |
| POST | `/api/v1/platform/support-grants/{id}/approve` | Bearer + `platform:support:manage` (MFA) | — | `SupportGrantOut` (status `active`; 403 when the approver is the requester, or holds neither Platform Super Admin nor Platform Administrator) |
| POST | `/api/v1/platform/support-grants/{id}/revoke` | Bearer + `platform:support:manage` (MFA) | — | `SupportGrantOut` (status `revoked`) |
| GET | `/api/v1/platform/audit` | Bearer + `platform:audit:read` | `action?`, `actor_id?`, `organization_id?`, `limit` (default 100, max 500), `offset` (default 0) | `PlatformAuditLogOut[]`, newest first. Append-only: no write endpoints exist. |

Platform roles (seeded): Platform Super Admin (Full Access, all 17
codes — the only role holding `platform:roles:manage`), Platform
Administrator (Privileged, all except `platform:roles:manage`), Platform
Support (Privileged), Security Administrator (Privileged), Billing
Administrator (Privileged), Platform Auditor (Read-Only, all `:read`
codes). Only a Platform Super Admin may grant/revoke the Platform Super
Admin role. The bootstrap script `scripts/bootstrap_platform_admin.py`
creates the first Platform Super Admin (env `NULL_PLATFORM_ADMIN_EMAIL` /
`NULL_PLATFORM_ADMIN_PASSWORD`, TOTP provisioning URI printed once).

### 7.9 ITSM engine — Requests, Catalog, Knowledge, Changes, Problems, Notifications (Phase 2)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET | `/api/v1/requests`, `/api/v1/requests/{id}` | Bearer + `requests:read` | List newest first |
| POST | `/api/v1/requests` | Bearer + `requests:create` | `{title, description?, priority?, catalog_item_id?, form_data?}` → number `REQ-000001`, status `submitted` |
| PATCH | `/api/v1/requests/{id}` | Bearer + `requests:create` | No `requests:update` code exists; update uses `requests:create` |
| POST | `/api/v1/requests/{id}/approve` | Bearer + `requests:approve` | Sets `approved_by/at`, status `approved` |
| POST | `/api/v1/requests/{id}/fulfill` | Bearer + `requests:fulfill` | Status `fulfilled` |
| POST | `/api/v1/requests/{id}/cancel` | Bearer + `requests:create` | Status `cancelled` |
| GET | `/api/v1/catalog/categories`, `/api/v1/catalog/categories/{id}` | Bearer + `catalog:read` | |
| POST/PATCH/DELETE | `/api/v1/catalog/categories[/{id}]` | Bearer + `catalog:manage` | |
| GET | `/api/v1/catalog/items`, `/api/v1/catalog/items/{id}` | Bearer + `catalog:read` | |
| GET | `/api/v1/catalog/items/published` | Bearer + `catalog:read` | Published items only |
| POST/PATCH/DELETE | `/api/v1/catalog/items[/{id}]` | Bearer + `catalog:manage` | |
| POST | `/api/v1/catalog/items/{id}/publish`, `/api/v1/catalog/items/{id}/retire` | Bearer + `catalog:manage` | |
| GET | `/api/v1/knowledge/articles`, `/api/v1/knowledge/articles/{id}` | Bearer + `knowledge:read` | Drafts visible only with `knowledge:create` or `knowledge:manage`; published GET increments `view_count` |
| POST | `/api/v1/knowledge/articles` | Bearer + `knowledge:create` | Slug unique per org |
| PATCH/DELETE | `/api/v1/knowledge/articles/{id}` | Bearer + `knowledge:manage` | |
| POST | `/api/v1/knowledge/articles/{id}/publish` | Bearer + `knowledge:publish` | |
| GET/POST | `/api/v1/knowledge/articles/{id}/feedback` | Bearer + `knowledge:read` | |
| GET | `/api/v1/changes`, `/api/v1/changes/{id}`, `/api/v1/changes/{id}/approvals`, `/api/v1/changes/{id}/tasks` | Bearer + `changes:read` | Number `CHG-000001` |
| POST/PATCH/DELETE | `/api/v1/changes[/{id}]` | Bearer + `changes:create` | No `changes:update` code exists |
| POST | `/api/v1/changes/{id}/submit` | Bearer + `changes:create` | `draft` → `pending_approval` |
| POST | `/api/v1/changes/{id}/approve`, `/api/v1/changes/{id}/reject` | Bearer + `changes:approve` | One decision per approver; reject returns the change to `draft` |
| POST | `/api/v1/changes/{id}/execute`, `/api/v1/changes/{id}/rollback` | Bearer + `changes:execute` | Execute only from `approved` |
| POST/PATCH/DELETE | `/api/v1/changes/{id}/tasks[/{task_id}]` | Bearer + `changes:create` | Implementation tasks |
| GET | `/api/v1/problems`, `/api/v1/problems/{id}` | Bearer + `problems:read` | Number `PRB-000001` |
| POST | `/api/v1/problems` | Bearer + `problems:create` | |
| PATCH/DELETE | `/api/v1/problems/{id}` | Bearer + `problems:manage` | |
| POST | `/api/v1/problems/{id}/link-known-error` | Bearer + `problems:manage` | Bidirectional link to a known error |
| GET/POST/PATCH/DELETE | `/api/v1/problems/known-errors[/{id}]` | Bearer + `problems:read` / `problems:manage` | Code unique per org (`KE-0001`) |
| GET/POST | `/api/v1/problems/incidents` | Bearer + `incidents:manage` | Major incidents (no `incidents:read` code exists) |
| GET/PATCH | `/api/v1/problems/incidents/{id}` | Bearer + `incidents:manage` | |
| GET | `/api/v1/notifications`, `/api/v1/notifications/{id}` | Bearer + `notifications:read` | Own notifications only |
| POST | `/api/v1/notifications/read-all`, `/api/v1/notifications/{id}/read` | Bearer + `notifications:read` | |
| GET | `/api/v1/tickets/{id}/comments`, `/api/v1/tickets/{id}/attachments`, `/api/v1/tickets/{id}/links` | Bearer + `tickets:read` | |
| POST | `/api/v1/tickets/{id}/comments` | Bearer + `tickets:comment` | `{body, is_internal}` — internal notes and public replies both appear in the list |
| POST | `/api/v1/tickets/{id}/attachments` | Bearer + `tickets:update` | **JSON, not multipart** (`python-multipart` is not installed): `{filename, content_type, size_bytes, content_base64?}`. Bytes go to storage when configured; when storage is unconfigured → **503 "storage not configured"** and nothing is stored. Metadata only. |
| POST/DELETE | `/api/v1/tickets/{id}/links[/{link_id}]` | Bearer + `tickets:update` | `{target_type: ticket\|request\|change\|problem, target_id, link_type: parent\|child\|related\|caused_by\|blocks}` — target must exist in-org |
| GET/POST/PATCH/DELETE | `/api/v1/tickets/templates[/{id}]` | Bearer + `templates:manage` | No `templates:read` code exists |
| GET/POST/PATCH/DELETE | `/api/v1/tickets/recurring[/{id}]` | Bearer + `templates:manage` | Schedule is frequency-based (`{frequency: daily\|weekly\|monthly, time: "HH:MM", weekday?}`); created by the `null.tasks.sweep_recurring_tickets` beat task |
| GET | `/api/v1/tickets/recurring/due` | Bearer + `templates:manage` | |
| GET/POST | `/api/v1/tickets/surveys` | Bearer + `surveys:read` | |
| GET/PATCH/DELETE | `/api/v1/tickets/surveys/{id}` | Bearer + `surveys:read` / `surveys:manage` | |
| POST | `/api/v1/tickets/surveys/{id}/responses` | Bearer + `surveys:read` | Any org member; target must exist in-org |
| GET | `/api/v1/tickets/surveys/{id}/responses` | Bearer + `surveys:read` | |

`TicketOut` (Phase 2): the Phase 1 fields plus `first_response_due_at?`,
`resolution_due_at?`, `first_response_at?`, `resolved_at?`,
`sla_policy_id?`, `sla_breached` (default `false`).

### 7.10 SLA engine — `/api/v1/sla` (Phase 2)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET/POST | `/api/v1/sla/business-hours` | Bearer + `sla:read` / `sla:manage` | Schedule: `{mon: [["09:00","17:00"]], ...}` (days `mon`–`sun`, empty list = closed); `timezone` must be a valid IANA name; `holidays`: `["YYYY-MM-DD"]` |
| GET/PATCH/DELETE | `/api/v1/sla/business-hours/{id}` | Bearer + `sla:read` / `sla:manage` | DELETE → 409 when a policy references the hours |
| POST | `/api/v1/sla/business-hours/{id}/set-default` | Bearer + `sla:manage` | |
| GET/POST | `/api/v1/sla/policies` | Bearer + `sla:read` / `sla:manage` | `response_minutes` / `resolution_minutes`: `{"critical": 30, "high": 60, "medium": 240, "low": 480}`; `applies_to`: `{"categories": [...], "priorities": [...]}` (empty = all) |
| GET/PATCH/DELETE | `/api/v1/sla/policies/{id}` | Bearer + `sla:read` / `sla:manage` | |
| POST | `/api/v1/sla/policies/{id}/set-default` | Bearer + `sla:manage` | |
| GET | `/api/v1/sla/breaches?status=&ticket_id=` | Bearer + `sla:read` | |
| GET | `/api/v1/sla/breaches/{id}` | Bearer + `sla:read` | |
| POST | `/api/v1/sla/breaches/{id}/acknowledge` | Bearer + `sla:manage` | |
| GET/POST | `/api/v1/sla/escalation-rules` | Bearer + `sla:read` / `sla:manage` | Trigger: `{event: sla_breach\|no_response\|no_update, after_minutes}`; actions: `[{type: priority_bump\|reassign\|notify, ...}]` |
| GET/PATCH/DELETE | `/api/v1/sla/escalation-rules/{id}` | Bearer + `sla:read` / `sla:manage` | |
| GET | `/api/v1/sla/escalation-rules/{id}/events` | Bearer + `sla:read` | |
| GET | `/api/v1/sla/tickets/{ticket_id}` | Bearer + `sla:read` | The ticket's SLA state (due dates, first response, breached, policy) |
| POST | `/api/v1/sla/tickets/{ticket_id}/recompute` | Bearer + `sla:manage` | Recompute due dates + stamp state |

Due dates are stamped at ticket creation (hook in `POST /api/v1/tickets`)
and re-derived by the `null.tasks.scan_sla_breaches` sweep (every 5 min),
which also creates breach rows (idempotent per ticket+type), notifies,
and evaluates escalation rules. Escalations are one-shot per
(rule, ticket). Due-date math is business-hours aware (timezone, split
windows, holidays) or calendar minutes when no business hours are set.

### 7.11 Email-to-ticket — `/api/v1/email` (Phase 2)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET | `/api/v1/email/mailboxes`, `/api/v1/email/mailboxes/{id}` | Bearer + `email:read` | Mailbox passwords are never returned |
| POST/PATCH/DELETE | `/api/v1/email/mailboxes[/{id}]` | Bearer + `email:manage` | `{name, host, port?, use_tls?, username, password, folder?}` — password is Fernet-encrypted at rest (`NULL_FIELD_ENCRYPTION_KEY`; 503 when unconfigured) |
| POST | `/api/v1/email/mailboxes/{id}/poll` | Bearer + `email:manage` | Poll one mailbox now |
| GET | `/api/v1/email/messages`, `/api/v1/email/messages/{id}` | Bearer + `email:read` | |
| POST | `/api/v1/email/messages/{id}/reply` | Bearer + `email:manage` | Sends via SMTP when configured, else logs (dev); records an outbound row + public ticket comment when linked |
| POST | `/api/v1/email/messages/{id}/convert` | Bearer + `email:manage` | Convert an unknown-sender message into a ticket |

Ingest rules (Celery `null.tasks.poll_mailboxes`, every 5 min, IMAP
UNSEEN): threading by `In-Reply-To`/`References` or `[INC-000123]` in the
subject; sender matching an active org member → new ticket with them as
requester; **unknown senders are stored with status `received` and NO
ticket** (manual triage via `/convert` — never auto-create tickets for
strangers); duplicate `Message-ID` per org is deduped. Mailbox passwords
and message bodies are never logged.

### 7.12 Employee self-service portal — `/api/v1/portal` (Phase 2)

Authenticated with a **portal token** (JWT type `portal_access`,
60-minute lifetime, issued by `POST /portal/auth/login`, recorded in
`portal_sessions` by SHA-256 hash). A portal token never authenticates a
non-portal endpoint and an org `access` token never authenticates a
portal endpoint. Portal login rejects MFA-enabled users with 401
("complete MFA via the main login") — the portal has no MFA challenge
step. Portal login defaults to the caller's earliest active membership,
or an explicit `organization_id` when the caller has an active
membership there.

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| POST | `/api/v1/portal/auth/login` | None | `{email, password, organization_id?}` → `{access_token, ...}` |
| POST | `/api/v1/portal/auth/logout` | Bearer (portal) | Revokes the portal session |
| GET | `/api/v1/portal/me` | Bearer (portal) + `portal:read` | Profile + org branding from `organizations.settings` |
| GET | `/api/v1/portal/tickets`, `/api/v1/portal/tickets/{id}` | Bearer (portal) + `portal:read` | **Own records only** — another user's ticket is 404 |
| POST | `/api/v1/portal/tickets` | Bearer (portal) + `portal:submit` | Requester is the caller |
| GET | `/api/v1/portal/requests`, `/api/v1/portal/requests/{id}` | Bearer (portal) + `portal:read` | Own records only |
| POST | `/api/v1/portal/requests` | Bearer (portal) + `portal:submit` | |
| POST | `/api/v1/portal/requests/{id}/approve` | Bearer (portal) + `portal:approve` | Only the assigned approver (`assignee_id`); 403 otherwise, 400 when not awaiting approval |
| GET | `/api/v1/portal/catalog` | Bearer (portal) + `portal:read` | Published items only |
| GET | `/api/v1/portal/knowledge` | Bearer (portal) + `portal:read` | Published articles only |
| GET | `/api/v1/portal/notifications` | Bearer (portal) + `portal:read` | Own notifications only |

### 7.13 Data import / export — `/api/v1/imports`, `/api/v1/exports` (Phase 2)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| POST | `/api/v1/imports` | Bearer + `imports:manage` | `{source_system: servicenow\|jira\|csv, rows: [...]}` — synchronous processing; returns the import with per-row outcomes |
| POST | `/api/v1/imports/{id}/reprocess` | Bearer + `imports:manage` | Re-run; already-`imported` rows are skipped (idempotent on `(import_id, source_id)`) |
| GET | `/api/v1/imports`, `/api/v1/imports/{id}` | Bearer + `imports:read` | Includes `import_records` outcomes |
| POST | `/api/v1/exports` | Bearer + `exports:manage` | `{export_type: tickets\|requests\|users\|audit\|full, format: csv\|json}` — `full` is JSON-only (400 for CSV) |
| GET | `/api/v1/exports`, `/api/v1/exports/{id}` | Bearer + `exports:read` | |
| GET | `/api/v1/exports/{id}/download` | Bearer + `exports:read` | Streams the file; when S3 is unconfigured the content is regenerated live from the DB |

Imported users are created as `User` + `invited` `Membership` + an
`invitations` row (the existing invite path — no second invite flow);
imported tickets/requests are created directly with source numbers
preserved in `raw_data`. Mapping profiles: ServiceNow (`number`,
`short_description`, `state`, `priority`, `caller_id` email), Jira
(`key`, `summary`, `status`, `priority`, `reporter`), CSV-generic
(`title`, `description`, `status`, `priority`, `requester_email`).

### 7.14 Identity & directory — `/api/v1/identity` (Phase 2)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET/POST | `/api/v1/identity/providers` | Bearer + `identity:read` / `identity:manage` | `{name, type: saml\|oidc, saml_entity_id?, saml_sso_url?, saml_certificate?, oidc_issuer?, oidc_client_id?, oidc_client_secret?}` — secrets Fernet-encrypted (503 when unconfigured) |
| GET/PATCH/DELETE | `/api/v1/identity/providers/{id}` | Bearer + `identity:read` / `identity:manage` | |
| POST | `/api/v1/identity/providers/{id}/set-default` | Bearer + `identity:manage` | |
| GET | `/api/v1/identity/providers/{id}/metadata` | Bearer + `identity:read` | Generated SP metadata XML from the org's config; no certificate is ever invented — an unconfigured cert omits the `KeyDescriptor` |
| POST | `/api/v1/identity/providers/{id}/acs` | **None (unauthenticated)** | Validates the SAML assertion with `python3-saml` (`OneLogin_Saml2_Auth`); garbage assertions → 400, provider without a certificate → 400, library missing → honest 501. **Validates and returns the subject but mints NO session** — SSO session issuance is out of scope for Phase 2 |
| GET | `/api/v1/identity/providers/{id}/discover` | Bearer + `identity:read` | Fetches `{issuer}/.well-known/openid-configuration` via httpx (1h in-process cache); 502 when the issuer is unreachable |
| GET/POST | `/api/v1/identity/scim-tokens` | Bearer + `identity:manage` | Create returns the token **once** (only the SHA-256 hash is stored) |
| POST | `/api/v1/identity/scim-tokens/{id}/revoke` | Bearer + `identity:manage` | |
| GET/POST | `/api/v1/identity/scim/v2/Users`, `/api/v1/identity/scim/v2/Groups` | **SCIM bearer token** (not JWT) | SCIM v2 subset: list (`filter`/`startIndex`/`count`), create, get, replace, patch, delete/deactivate. Auth is `Authorization: Bearer <raw SCIM token>` resolved by SHA-256 hash via a SECURITY DEFINER function; wrong/expired/revoked → 401; a token from org A can never touch org B. Provisioning = User (random unknowable password hash) + `invited` Membership + Invitation row; deactivate suspends the membership |
| GET/PUT/PATCH/DELETE | `/api/v1/identity/scim/v2/Users/{id}`, `/api/v1/identity/scim/v2/Groups/{id}` | **SCIM bearer token** | |
| POST | `/api/v1/identity/directory-sync` | Bearer + `identity:manage` | `{provider_id?, source: entra\|ad\|ldap\|scim}` — starts a recorded sync run |
| GET | `/api/v1/identity/directory-sync/runs`, `/api/v1/identity/directory-sync/runs/{id}` | Bearer + `identity:read` | |
| GET/POST | `/api/v1/identity/directory-groups` | Bearer + `identity:read` / `identity:manage` | `{provider_id?, external_id, name, role_id?}` — group→role mapping applied on sync |
| PATCH | `/api/v1/identity/directory-groups/{id}` | Bearer + `identity:manage` | |
| GET/POST | `/api/v1/identity/certifications` | Bearer + `identity:read` / `identity:manage` | Access-certification campaigns |
| GET | `/api/v1/identity/certifications/{id}`, `/api/v1/identity/certifications/{id}/items` | Bearer + `identity:read` | |
| POST | `/api/v1/identity/certifications/{id}/items/{item_id}/decide` | Bearer + `identity:manage` | `{decision: approved\|revoked}` — revoke removes the `user_roles` row; campaign completes when all items are decided |
| GET/POST | `/api/v1/identity/temp-grants` | Bearer + `identity:read` / `identity:manage` | `{user_id, role_id, reason?, expires_at}` |
| POST | `/api/v1/identity/temp-grants/{id}/revoke` | Bearer + `identity:manage` | Expired grants are revoked by the `null.tasks.expire_temp_grants` hourly sweep |
| GET/POST | `/api/v1/identity/service-accounts` | Bearer + `identity:read` / `identity:manage` | Create returns the secret **once** (only the SHA-256 hash is stored) |
| POST | `/api/v1/identity/service-accounts/{id}/rotate`, `/api/v1/identity/service-accounts/{id}/revoke` | Bearer + `identity:manage` | |
| GET/POST | `/api/v1/identity/api-credentials` | Bearer + `identity:read` / `identity:manage` | Create returns the credential **once** |
| POST | `/api/v1/identity/api-credentials/verify` | Bearer + `identity:read` | Proves a credential (hash match, unexpired, unrevoked → scopes); request-level API-key auth is Phase 4 |
| POST | `/api/v1/identity/api-credentials/{id}/rotate`, `/api/v1/identity/api-credentials/{id}/revoke` | Bearer + `identity:manage` | |

Directory sync: the SCIM source is a real local reconciliation (member
counts + role mapping). Entra is real MS Graph client code but fails
honestly (`not configured`) without tenant/client credentials. LDAP
raises honestly (`ldap3` not installed). Group→role mapping reconciles
`user_roles` against group membership on every sync.

### 7.15 Assets & licensing — `/api/v1/assets` (Phase 2)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET/POST | `/api/v1/assets` | Bearer + `assets:read` / `assets:manage` | `{asset_tag (unique per org), name, type: laptop\|desktop\|monitor\|phone\|server\|other, serial_number?, status?, department?, location?, purchase_order_id?, purchase_date?, purchase_price_cents?, depreciation_method?, depreciation_years?}` |
| GET/PATCH/DELETE | `/api/v1/assets/{id}` | Bearer + `assets:read` / `assets:manage` | |
| POST | `/api/v1/assets/{id}/assign`, `/api/v1/assets/{id}/check-out`, `/api/v1/assets/{id}/check-in`, `/api/v1/assets/{id}/transfer`, `/api/v1/assets/{id}/mark-lost`, `/api/v1/assets/{id}/mark-stolen`, `/api/v1/assets/{id}/recover`, `/api/v1/assets/{id}/retire`, `/api/v1/assets/{id}/dispose` | Bearer + `assets:manage` | Illegal transitions → 400; every transition writes an append-only `asset_lifecycle_events` row + audit |
| GET | `/api/v1/assets/{id}/lifecycle`, `/api/v1/assets/{id}/assignments` | Bearer + `assets:read` | |
| POST | `/api/v1/assets/offboard` | Bearer + `assets:manage` | `{user_id}` — one transaction: suspend membership → revoke sessions → one recovery ticket per assigned asset → assets to `in_repair` with lifecycle events + closed assignments → temp grants revoked → `asset.offboarding_completed` audit with the full report. Offboarding the org owner → 400 |
| GET/POST | `/api/v1/assets/vendors` | Bearer + `vendors:read` / `vendors:manage` | |
| GET/PATCH | `/api/v1/assets/vendors/{id}` | Bearer + `vendors:read` / `vendors:manage` | |
| GET/POST | `/api/v1/assets/purchase-orders` | Bearer + `vendors:read` / `vendors:manage` | `po_number` unique per org |
| GET/PATCH | `/api/v1/assets/purchase-orders/{id}` | Bearer + `vendors:read` / `vendors:manage` | |
| GET/POST | `/api/v1/assets/warranties` | Bearer + `vendors:read` / `vendors:manage` | |
| GET | `/api/v1/assets/warranties/{id}` | Bearer + `vendors:read` | |
| GET | `/api/v1/assets/licenses/compliance` | Bearer + `licenses:read` | Seats used/available, expiring licenses (30 days), over-allocated list |
| GET/POST | `/api/v1/assets/licenses` | Bearer + `licenses:read` / `licenses:manage` | `license_key` Fernet-encrypted (503 when unconfigured) |
| GET/PATCH/DELETE | `/api/v1/assets/licenses/{id}` | Bearer + `licenses:read` / `licenses:manage` | |
| POST | `/api/v1/assets/licenses/{id}/assign` | Bearer + `licenses:manage` | Blocked 400 at capacity; `override: true` assigns anyway and flips status to `exceeded` (explicit, never silent); revoking back under capacity restores `active` |
| GET | `/api/v1/assets/licenses/{id}/assignments` | Bearer + `licenses:read` | |
| POST | `/api/v1/assets/licenses/assignments/{id}/revoke` | Bearer + `licenses:manage` | |

Depreciation: straight-line = price × (1 − elapsed/years); declining =
double-declining fixed 2x rate; `none` = price. Recomputed on read; the
stored column is only a snapshot.

### 7.16 Agent API + endpoints — `/api/v1/agents`, `/api/v1/endpoints` (Phase 3)

Implements the §9 contract on the backend side. Device calls authenticate
with `X-Device-Id` + `X-Device-Token` (no user Bearer token); user-facing
calls use Bearer + the `endpoints:*` permissions.

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| POST | `/api/v1/endpoints/enrollment-tokens` | Bearer `endpoints:manage` | Issues a one-time token; response carries the raw token **once** (only its SHA-256 hash is stored) |
| GET | `/api/v1/endpoints/enrollment-tokens` | Bearer `endpoints:read` | Lists tokens incl. used/revoked state |
| POST | `/api/v1/endpoints/enrollment-tokens/{token_id}/revoke` | Bearer `endpoints:manage` | Revokes an unused token |
| POST | `/api/v1/agents/enroll` | Enrollment token (no Bearer) | `{enrollment_token, device: {hostname, os, os_version, arch, serial?}}` → 201 `{device_id, device_token, enrolled_organization_id}`; token consumed atomically, single-use; reuse → 401 |
| POST | `/api/v1/agents/{device_id}/heartbeat` | Device auth | `{status: "online", agent_version?, ip_address?}` → `{status: "ok", server_time, pending_jobs}` |
| POST | `/api/v1/agents/{device_id}/inventory` | Device auth | Strict section validation (§9.4): unknown top-level section → 422; 201 `{status: "ok", inventory_id, received_at}`; append-only |
| GET | `/api/v1/agents/{device_id}/jobs/next` | Device auth | `{job: null}` or `{job: {job_id, type, payload, issued_at, expires_at}}`; at-most-once delivery; expired jobs are never re-delivered under the same `job_id` |
| POST | `/api/v1/agents/{device_id}/jobs/{job_id}/result` | Device auth | `{status: "succeeded" \| "failed" \| "rejected", output?, error?, started_at, finished_at}` → `{status: "ok"}`; dispatches to the patching / vuln apply functions by job type; a failing downstream apply is audited (`agent.job_result_handler_failed`) and swallowed so the device's recorded result survives (apply functions are idempotent) |
| GET | `/api/v1/agents/updates/check?current_version=…&os=…&arch=…` | Device auth | `{update_available, version?, download_url?, sha256?, signature?, release_notes?}` — **`download_url` is always `null` in Phase 3**: no artifact storage is configured, so no update is ever offered and nothing is installed; the signed-update rule (§9.6) stands for when storage lands |
| GET/POST | `/api/v1/endpoints` | Bearer `endpoints:read` / `endpoints:manage` | List / create (manual registration, no device token) |
| GET/PATCH | `/api/v1/endpoints/{endpoint_id}` | Bearer `endpoints:read` / `endpoints:modify` | Rename / update; status `enrolled \| online \| offline \| stale \| unenrolled` |
| POST | `/api/v1/endpoints/{endpoint_id}/revoke` | Bearer `endpoints:manage` | Revokes the device credential; device gets 401 thereafter |
| GET | `/api/v1/endpoints/{endpoint_id}/inventory`, `/api/v1/endpoints/{endpoint_id}/jobs` | Bearer `endpoints:read` | Append-only inventory history; job history |
| POST | `/api/v1/endpoints/{endpoint_id}/jobs` | Bearer `endpoints:manage` (+ type-specific perm, e.g. `endpoints:deploy`) | Issue a job `{type, payload?}`; job types: `patch_scan`, `patch_deploy`, `vuln_scan`, `inventory_refresh` |
| GET/POST/PATCH/DELETE | `/api/v1/endpoints/releases` | Bearer `endpoints:read` / `endpoints:manage` | Agent release catalog — **global, not tenant data** (no org, no RLS); the source of truth for update checks |

### 7.17 Patching — `/api/v1/patching` (Phase 3)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET | `/api/v1/patching/patches`, `/api/v1/patching/patches/{patch_id}` | Bearer `patching:read` | Patch catalog (per org) |
| GET | `/api/v1/patching/findings` | Bearer `patching:read` | Missing-patch findings per endpoint; one open row per endpoint+patch (partial unique index) |
| GET/POST | `/api/v1/patching/scans` | Bearer `patching:read` / `endpoints:scan` | Scan records; a completed scan is treated as a **full inventory** — a previously-missing finding for a patch the scan does not report flips to `installed` |
| GET | `/api/v1/patching/scans/{scan_id}` | Bearer `patching:read` | |
| GET/POST | `/api/v1/patching/deployments` | Bearer `patching:read` / `patching:deploy` | Deployment lifecycle: created → approved → executed → verified; cancel allowed before execution |
| GET | `/api/v1/patching/deployments/{deployment_id}` | Bearer `patching:read` | |
| POST | `/api/v1/patching/deployments/{deployment_id}/approve` | Bearer `patching:approve` | |
| POST | `/api/v1/patching/deployments/{deployment_id}/execute` | Bearer `patching:deploy` | Issues a `patch_deploy` agent job per deployment item |
| POST | `/api/v1/patching/deployments/{deployment_id}/cancel` | Bearer `patching:deploy` | |
| POST | `/api/v1/patching/deployments/{deployment_id}/verify` | Bearer `patching:deploy` | Issues a `patch_scan` verification job; findings flip to `installed` only when the rescan confirms |

Scan/deploy results arrive through the agent job-result path (§7.16), never
by direct POST: `apply_patch_scan_result` / `apply_patch_deploy_result`
are idempotent per job, and malformed agent output returns
`{"status": "malformed_output"}` with state unchanged.

### 7.18 Vulnerabilities — `/api/v1/vulnerabilities` (Phase 3)

Real engine support (Greenbone/OpenVAS first, multi-engine by design)
plus a manual engine for operator-entered results. CVE data comes from
the real NVD API + CISA KEV feed (`null.tasks.sync_cve_kev`, daily beat;
NVD is bounded to one 2000-result page per run by design, KEV fully;
both feeds are fetched before any write, so a failed run leaves the
catalog unchanged). Nothing here invents findings.

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET/POST | `/api/v1/vulnerabilities/engines` | Bearer `vulnerabilities:read` / `vulnerabilities:manage` | `engine_type: greenbone \| manual \| ...`; engine passwords Fernet-encrypted, 503 when no field key (never plaintext); secrets never returned (`has_password` only) |
| GET/PATCH/DELETE | `/api/v1/vulnerabilities/engines/{engine_id}` | Bearer `vulnerabilities:read` / `vulnerabilities:manage` | Deleting the default engine promotes the oldest remaining engine to default |
| POST | `/api/v1/vulnerabilities/engines/{engine_id}/set-default` | Bearer `vulnerabilities:manage` | |
| GET | `/api/v1/vulnerabilities/cves`, `/api/v1/vulnerabilities/cves/{cve_id}` | Bearer `vulnerabilities:read` | Global public catalog (no RLS): `?kev=true`, `?severity=…`; `kev`, `cvss_score`, `kev_due_date`, `kev_ransomware_use` |
| GET/POST | `/api/v1/vulnerabilities/scans` | Bearer `vulnerabilities:read` / `vulnerabilities:manage` | |
| GET | `/api/v1/vulnerabilities/scans/{scan_id}` | Bearer `vulnerabilities:read` | |
| POST | `/api/v1/vulnerabilities/scans/{scan_id}/import-results` | Bearer `vulnerabilities:manage` | Manual-engine scans only — **except** a queued verification scan (see verify below), which exists to receive an imported rescan. Correlates by hostname/IP to endpoints (duplicate hostnames resolve to the most recently seen endpoint, never 500) and dedupes to one open finding per endpoint+CVE; re-detection of a remediated finding reopens it in place |
| POST | `/api/v1/vulnerabilities/scans/{scan_id}/poll` | Bearer `vulnerabilities:manage` | Polls a Greenbone engine for a running scan (GMP over TLS); unreachable engine at scan-create → 502, no scan row |
| POST | `/api/v1/vulnerabilities/scans/{scan_id}/cancel` | Bearer `vulnerabilities:manage` | |
| GET | `/api/v1/vulnerabilities/summary` | Bearer `vulnerabilities:read` | Derived counts only: `by_severity`, `by_status`, `open_kev`, `total_open` |
| GET | `/api/v1/vulnerabilities/findings`, `/api/v1/vulnerabilities/findings/{finding_id}` | Bearer `vulnerabilities:read` | Statuses: `open \| in_progress \| remediated \| verified \| accepted \| false_positive` |
| PATCH | `/api/v1/vulnerabilities/findings/{finding_id}` | Bearer `vulnerabilities:manage` | Status transitions; setting `remediated` directly is forbidden (400) — remediation goes through the remediate → verify flow |
| POST | `/api/v1/vulnerabilities/findings/{finding_id}/remediate` | Bearer `vulnerabilities:remediate` | Creates a **real ticket** via the ticket path + a `remediation_tickets` link (finding → ticket → patch → deployment → verification scan); finding → `in_progress` |
| POST | `/api/v1/vulnerabilities/findings/{finding_id}/verify` | Bearer `vulnerabilities:manage` | Requires `in_progress` with an open remediation link (or `remediated` for retry). Flips finding + open links to `remediated`; if the endpoint is agent-enrolled, issues a `vuln_scan` agent job with payload `{"verify_finding_id": …}` (job issuance is authorized by this call's `vulnerabilities:manage`); otherwise creates a queued `VulnScan` and links it immediately. When the verification scan's results arrive (agent job result or manual import), the finding becomes `verified` if its CVE is absent, or reopens to `open` if present |

### 7.19 CMDB + network — `/api/v1/cmdb`, `/api/v1/network` (Phase 3)

| Method | Path | Auth / Perm | Notes |
|---|---|---|---|
| GET/POST | `/api/v1/cmdb/items` | Bearer `cmdb:read` / `cmdb:manage` | Configuration items; may link to an asset or endpoint |
| GET/PATCH/DELETE | `/api/v1/cmdb/items/{ci_id}` | Bearer `cmdb:read` / `cmdb:manage` | |
| POST/GET | `/api/v1/cmdb/items/{ci_id}/relationships` | Bearer `cmdb:manage` / `cmdb:read` | No self-links (CHECK); relationship types e.g. `depends_on`, `hosts`, `runs_on` |
| DELETE | `/api/v1/cmdb/relationships/{rel_id}` | Bearer `cmdb:manage` | |
| GET | `/api/v1/cmdb/items/{ci_id}/graph` | Bearer `cmdb:read` | Depth-2 dependency graph |
| GET/POST | `/api/v1/network/devices` | Bearer `network:read` / `network:manage` | Switch/router/server inventory; SNMP community stored encrypted, never returned |
| GET/PATCH/DELETE | `/api/v1/network/devices/{device_id}` | Bearer `network:read` / `network:manage` | Status derived: `up \| down \| degraded \| unknown` |
| GET/POST | `/api/v1/network/devices/{device_id}/interfaces` | Bearer `network:read` / `network:manage` | |
| PATCH/DELETE | `/api/v1/network/interfaces/{interface_id}` | Bearer `network:manage` | |
| GET | `/api/v1/network/topology` | Bearer `network:read` | Devices + links for the topology map |
| POST/DELETE | `/api/v1/network/topology/links`, `/api/v1/network/topology/links/{link_id}` | Bearer `network:manage` | |
| GET/POST/PATCH/DELETE | `/api/v1/network/service-dependencies` | Bearer `network:read` / `network:manage` | Service dependency mapping (service → depends on → device/CI) |
| POST | `/api/v1/network/metrics` | Bearer `network:manage` | Append-only interface/bandwidth/CPU/memory samples; never updated in place |
| GET | `/api/v1/network/devices/{device_id}/metrics`, `/api/v1/network/devices/{device_id}/health` | Bearer `network:read` | Health is **derived** from the latest metrics + events, not stored |
| GET/POST | `/api/v1/network/events` | Bearer `network:read` / `network:manage` | Outage / threshold events |
| POST | `/api/v1/network/events/{event_id}/acknowledge` | Bearer `network:manage` | |
| GET | `/api/v1/network/certificates/expiring?days=…`, `/api/v1/network/certificates` | Bearer `network:read` | Expiry is derived from `not_after`, never a stored flag |
| POST/PATCH/DELETE | `/api/v1/network/certificates`, `/api/v1/network/certificates/{cert_id}` | Bearer `network:manage` | |
| POST | `/api/v1/network/discover` | Bearer `network:discover` | **Real** discovery: ICMP/TCP ping sweep bounded to a /24 (default) — `{"cidr": "127.0.0.1/32"}` in tests; SNMP only when `pysnmp` is installed (otherwise `snmp_unavailable`, honestly reported). Existing devices by IP are updated in place (duplicate IPs resolve to the most recently seen device); new live hosts are created. DNS/DHCP and syslog ingestion are **not** built (Tier 2, see register) |
| | `null.tasks.check_network_health` (Celery, hourly beat) | — | Marks stale `up` devices `down`, one outage event per downtime episode; idempotent per episode |

## 8. Browser client mapping

`frontend/null-api-client.js` (`NullApiClient`) implements every endpoint
in §7. Method names are camelCase versions of the operations (e.g.
`listTickets()`, `configureRolePermissions(roleId, codes)`,
`selectOrganization(orgSelectToken, orgId)`). The client also owns:
token storage (access in memory, refresh in `sessionStorage` under
`null-itsm-refresh-token`, org id under `null-itsm-org-id`), the
`X-Organization-Id` and `X-Request-Id` headers, the 401 → refresh → retry
once flow, the `onLoadingChange` in-flight counter, normalized
`NullApiError {status, detail, errors}`, and `requireAuth()` /
`getOrgContext()` / `setOrgContext()` for route protection and the org
switcher. See `docs/FRONTEND_INTEGRATION.md` for the screen wiring.

## 9. Agent API contract (Phase 3) — IMPLEMENTED (backend side; agent repo pending)

> **Status: the backend side is implemented and live-boot verified
> (Nov 26, 2026 — enroll → heartbeat → inventory → jobs → results, plus
> patch and vuln-verify flows end to end). The endpoint agent itself
> (`nullitsm/null-endpoint-agent`) does not exist yet — no real device has
> run these calls. The backend never claims an agent action ran on a real
> device when it did not.

The agent is a separately managed component (Go agent, per the Phase 3
scope). Its backend surface will live under `/api/v1/agents` and follows
the same conventions as §1–§6 (JSON, UUIDs, `X-Request-Id`, the §4 error
model, RLS tenant isolation by the org the device is enrolled into).

### 9.1 Enrollment (one-time enrollment token → device credential)

- `POST /api/v1/agents/enroll` — authenticated by a **one-time enrollment
  token** issued out-of-band by an org admin (e.g. from the Endpoints
  screen), not by a user session. Request:
  `{enrollment_token, device: {hostname, os, os_version, arch, serial?}}`.
  Response (201): `{device_id, device_token, enrolled_organization_id}`.
  The enrollment token is single-use and short-lived; a used or expired
  token returns 401. The returned `device_token` is shown **once** — the
  agent must store it in the OS credential store / protected local file
  (never in logs or plain-text config checked into a repo).

### 9.2 Device identity and agent authentication

- **Device identity:** `device_id` (UUID, assigned at enrollment) +
  `device_token` (opaque secret). The server stores **only the SHA-256
  hash** of the device token, exactly like refresh tokens.
- **Agent authentication:** every agent request sends
  `X-Device-Token: <device_token>` (and `X-Device-Id: <device_id>`).
  No user Bearer token is used by the agent. A wrong/unknown/revoked
  device token → 401. Device tokens are scoped to one device in one org;
  they confer no user permissions and cannot call any `/api/v1/*` user
  endpoint.
- **Revocation:** an org admin (or the agent itself on uninstall) can
  revoke a device credential; revoked devices get 401 on every call and
  must stop retrying and surface "unenrolled" locally.
- **Re-enrollment:** a device that is wiped/reinstalled must enroll again
  with a fresh enrollment token; the old `device_id` is not reused.

### 9.3 Heartbeats

- `POST /api/v1/agents/{device_id}/heartbeat` — `X-Device-Token` auth.
  Request: `{status: "online", agent_version, last_seen_at?, ip_address?}`.
  Response: `{status: "ok", server_time, pending_jobs: <count>}`.
  Expected cadence: every 30 minutes (and once at agent start). The
  server records `last_seen_at`; a device silent beyond the org's
  threshold is shown as stale/offline in the console. Heartbeats carry
  no inventory payload — inventory is separate (§9.4).

### 9.4 Inventory submission

- `POST /api/v1/agents/{device_id}/inventory` — `X-Device-Token` auth.
  Request: `{collected_at, os: {...}, hardware: {cpu, memory_mb, disks[]},
  network: {interfaces[], mac_addresses[]}, software: [{name, version,
  vendor?}], services: [{name, status}]}` (exact schema to be frozen
  when the agent repo lands; the backend will validate and reject
  unknown top-level sections rather than silently dropping them).
  Response: `{status: "ok", inventory_id, received_at}`.
  Inventory is submitted on enrollment, on agent start, and on a
  periodic schedule (no more often than hourly unless a scan is
  requested via a job). The backend stores inventory per device per org;
  inventory from a device never leaks across orgs (§6).

### 9.5 Remote job execution

Jobs are the only way the backend tells an agent to do something. The
agent **polls**; the server never initiates a connection to a device.

- `GET /api/v1/agents/{device_id}/jobs/next` — `X-Device-Token` auth.
  Called after each heartbeat (or on its own poll). Response is either
  `{job: null}` (nothing to do) or `{job: {job_id, type, payload,
  issued_at, expires_at}}`.
- `POST /api/v1/agents/{device_id}/jobs/{job_id}/result` —
  `X-Device-Token` auth. Request: `{status: "succeeded" | "failed" |
  "rejected", output?, error?, started_at, finished_at}`. Response:
  `{status: "ok"}`.
- **Command allowlisting (hard rule):** the agent executes only commands
  from an explicit allowlist shipped with the agent (e.g. patch scan,
  software inventory refresh, approved configuration apply). A job whose
  `type` is not allowlisted, or whose payload contains shell
  metacharacters / arguments outside the allowlisted shape, must be
  **rejected by the agent** with `status: "rejected"` and never executed.
  The backend never sends arbitrary shell strings.
- **Authenticated / authorized / auditable:** a job is only issued to the
  device it names, only when the issuing user held the relevant
  permission in that org at issue time (e.g. `endpoints:deploy`), and
  every job issue, delivery, and result is written to the audit log
  (actor = issuing user, resource = device/job). Job results are
  attributable to the device that ran them.
- **At-most-once delivery:** a job is delivered once; if the agent
  reports a result, the job is closed. If a job expires before a result
  arrives, the backend marks it expired and it is never re-delivered
  under the same `job_id`.

### 9.6 Agent updates (signed updates)

- `GET /api/v1/agents/updates/check?current_version=…&os=…&arch=…` —
  `X-Device-Token` auth. Response: `{update_available: boolean,
  version?, download_url?, sha256?, signature?, release_notes?}`.
  **Implemented with `download_url: null` (Phase 3): no artifact storage
  is configured, so the endpoint always reports no update available and
  never offers a download. The signed-update rule below stands for when
  artifact storage lands — an agent must not install an update it was
  not offered through this endpoint, and must verify signature + SHA-256
  when one is offered.

### 9.7 What the agent must never do

- Never call user endpoints (`/api/v1/tickets`, `/api/v1/users`, …) with
  a device token; they require a user Bearer token and will 401.
- Never send credentials, tokens, or inventory over plain HTTP.
- Never execute a job payload that is not allowlisted (§9.5).
- Never invent inventory, scan results, or vulnerability findings — only
  report what the device actually observed (the same real-data-only rule
  as the rest of NULL).
