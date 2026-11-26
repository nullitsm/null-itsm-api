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

## 9. Agent API contract (Phase 3) — CONTRACT ONLY, NOT IMPLEMENTED

> **Status: this section defines the contract the separate endpoint-agent
> repo (`nullitsm/null-endpoint-agent`) will implement against. None of
> these endpoints exist in Phase 1. Do not call them against the Phase 1
> API — they will 404. Do not present them as available.**

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
- **Signed updates (hard rule):** an update is installed only when the
  agent verifies the detached signature against the pinned NULL public
  key **and** the SHA-256 of the downloaded artifact matches `sha256`.
  A failed verification aborts the update and is reported as a job
  result / heartbeat field, never retried silently in a loop.
- `download_url` is a short-lived, per-device URL (not a public listing
  of releases). The agent must not install an update it was not offered
  through this endpoint.

### 9.7 What the agent must never do

- Never call user endpoints (`/api/v1/tickets`, `/api/v1/users`, …) with
  a device token; they require a user Bearer token and will 401.
- Never send credentials, tokens, or inventory over plain HTTP.
- Never execute a job payload that is not allowlisted (§9.5).
- Never invent inventory, scan results, or vulnerability findings — only
  report what the device actually observed (the same real-data-only rule
  as the rest of NULL).
