# Frontend Integration — wiring the static NULL ITSM screens to the API

> **DEFERRED — do not edit the live frontend until the parent says its
> rounds have settled.** The live frontend repo is NOT to be edited.
> This document describes how the existing static NULL ITSM screens will
> be wired to the Phase 1 API (`nullitsm/null-itsm-api`) when their live
> frontend rounds settle. The client it describes lives in this backend
> repo at `frontend/null-api-client.js` so the wiring work can be reviewed
> against the real contract (`docs/API_CONTRACT.md`) before it touches
> any live screen.

Scope: the screens named here are the ones that exist today — **sign-in,
Command Center, Platform Settings, Users & Roles, and the shared
navigation / top bar**. Anything not named here (Tickets screens beyond
the Command Center list, Service Desk, Endpoints, CMDB, Analytics, and
all Phase 2+ modules) is out of scope for this round and gets its own
wiring plan when its backend lands.

---

## 1. The client, in one paragraph

`frontend/null-api-client.js` exports `NullApiClient` (framework-free ES
module, no dependencies, no build step). One instance per page load:

```js
import { NullApiClient, NullApiError } from './null-api-client.js';

export const api = new NullApiClient({
  baseUrl: 'http://localhost:8000', // or window.location.origin when served from the API host
  onLoadingChange: (loading) => { /* show/hide the global spinner */ },
  onUnauthorized: () => { window.location.href = '/sign-in.html'; },
});
```

The client owns: token storage (access token in memory only; refresh
token in `sessionStorage` under `null-itsm-refresh-token`; org id in
memory + `sessionStorage` under `null-itsm-org-id`), the
`X-Organization-Id` header on every request, the `X-Request-Id` header
per call, JSON in/out, the 401 → one refresh → one retry flow, the
`onLoadingChange` in-flight counter, and normalized `NullApiError
{status, detail, errors}`. Screens never call `fetch` directly and never
touch tokens — they call client methods and handle `NullApiError`.

## 2. Sign-in → org-select → Command Center flow

The sign-in screen is the only page that does not require auth. Its
logic branches on the `status` field of the login response — never on
token presence alone:

```
sign-in form submit
  └─ api.login(email, password)
       ├─ status "ok"            → tokens stored → go to Command Center
       ├─ status "mfa_required"  → show MFA step (6-digit code)
       │     └─ api.mfaChallenge(mfa_token, code)
       │          ├─ status "ok"           → Command Center
       │          └─ status "org_required" → org-select step (below)
       ├─ status "org_required"  → org-select step: list result.organizations,
       │     user picks one
       │     └─ api.selectOrganization(org_select_token, orgId)
       │          → tokens stored, org context set → Command Center
       └─ status "no_org"        → "create your organization" step
             └─ api.createOrganization({name})
                   └─ api.selectOrganization(org_select_token, newOrg.id)
                         → Command Center
```

Rules for the sign-in screen:

- **Wrong credentials → 401.** Show a generic "Email or password is
  incorrect." Never distinguish unknown email from wrong password (the
  API doesn't either).
- **Rate limits:** login and MFA challenge are limited to 10/minute per
  IP, password-reset requests to 5/minute. On a `429`, show the API's
  message and disable the submit button briefly — do not let the user
  hammer it, and do not auto-retry.
- **Password reset:** a "Forgot password?" link calls
  `api.requestPasswordReset(email)`. The API always returns success, so
  the UI must always show the same message ("If an account exists, a
  reset link was sent.") and never reveal whether the address exists.
  The reset link lands on a confirm page that calls
  `api.confirmPasswordReset(token, newPassword)` (new password: minimum
  12 characters; the API rejects shorter ones with 422 — surface the
  first validation message).
- **Invitation accept:** the invite link lands on an accept page that
  calls `api.acceptInvitation(token, fullName, password)` (password
  minimum 12), then sends the user to the sign-in screen to log in with
  the new credentials. The accept page needs no session.
- **MFA enrollment** is not part of sign-in; it lives in Platform
  Settings (§5), using `enrollMfa` / `verifyMfaEnrollment` /
  `disableMfa`.

## 3. Org context in the top bar + org switcher

The top bar (shared navigation) owns the org context:

- On every internal page load, after the auth guard (§6) passes, call
  `api.me()` once and render: the user's email, the current org name
  (from `organization_slug`, or `api.getOrganization(orgId)` for the
  display name), and the org switcher.
- **Org switcher:** populate from `api.myOrganizations()` (active
  memberships only). Selecting a different org calls
  `api.switchOrganization(orgId)` — it issues a fresh token pair scoped
  to the new org and updates the stored org context — then reloads the
  current page's data (or navigates to Command Center) so nothing from
  the old org lingers on screen. Never render data fetched under the
  previous org after a switch.
- **Org mismatch:** if a page is opened with a stale org id (e.g. a
  bookmark from another org), API calls return 403; the page must show
  the 403 state (§7) and offer the switcher, not silently fall back to
  another org.
- **No org yet:** a signed-in user with no org (`no_org` at login) has no
  Command Center to show. Route them to the create-organization step
  (§2) instead of an empty dashboard.

## 4. Session state: refresh, expiry, sign-out

- **Access tokens live 15 minutes, in memory only.** A page reload loses
  the access token by design. The first API call after reload gets a
  401, the client refreshes transparently from the `sessionStorage`
  refresh token, retries once, and the page works. Screens must not
  treat a post-reload 401 as an error — the client handles it.
- **Refresh rotation:** every refresh revokes the old refresh token and
  issues a new pair. The client stores the new pair automatically.
  Screens never store or read refresh tokens themselves.
- **Refresh failure → signed out.** When the refresh token is expired
  (7 days), revoked, or missing, the client's refresh fails, it clears
  all local state and calls `onUnauthorized` (default: redirect to the
  sign-in page). Screens must not catch this and show their own "session
  expired" page instead — the redirect is the behavior.
- **Proactive refresh (optional, later):** a long-lived page (Command
  Center left open) may call `api.refreshToken()` before the 15-minute
  mark to avoid a mid-interaction 401. Not required for this round —
  the reactive 401 flow covers it.
- **Sign-out:** the top bar's sign-out calls `api.logout()`, which
  revokes the refresh token server-side (`POST /api/v1/auth/logout`)
  and then clears local state even if the network call fails. After
  logout, navigate to the sign-in page. Never leave the refresh token
  in `sessionStorage` after sign-out.
- **Tab lifetime:** refresh tokens live in `sessionStorage`, so closing
  the tab ends the session (a new tab must sign in again). This is
  deliberate — do not "fix" it by moving the refresh token to
  `localStorage`.

## 5. What each screen calls

### 5.1 Sign-in

| Need | Client method |
|---|---|
| Sign in | `login(email, password)` → branch on `status` |
| MFA step | `mfaChallenge(mfaToken, code)` |
| Multi-org step | `selectOrganization(orgSelectToken, orgId)` |
| No-org step | `createOrganization({name, slug?})` then `selectOrganization(...)` |
| Forgot password | `requestPasswordReset(email)` |
| Reset confirm page | `confirmPasswordReset(token, newPassword)` |
| Invite accept page | `acceptInvitation(token, fullName, password)` |

### 5.2 Command Center

The Command Center is the post-login landing page. Phase 1 data is thin
by design — it shows what the API can actually prove, and nothing else:

| Need | Client method |
|---|---|
| Who is signed in / what can they do | `me()` — permissions array drives which cards/buttons render |
| Ticket list (the Phase 1 proof domain) | `listTickets()`; open one with `getTicket(id)`; create with `createTicket({title, description, priority, category})`; change status/priority/assignee with `updateTicket(id, patch)` |
| Org context for the header | `getOrganization(orgId)` / `myOrganizations()` (top bar, §3) |
| Health of the platform (ops corner, if shown) | `readiness()` — remember it always answers HTTP 200; render `status` (`ok` vs `degraded`) and the `checks` map, not the HTTP code |

Do **not** render counts, charts, or stats the API does not return.
There is no Phase 1 endpoint for ticket counts by status, SLA, or
recent activity — if the Command Center mock shows them, they stay
empty / hidden until a later phase adds the endpoint. Never invent
numbers to fill a card.

### 5.3 Platform Settings

| Need | Client method |
|---|---|
| Org details / rename | `getOrganization(orgId)`, `updateOrganization(orgId, {name})` — requires `org:manage`; hide the rename control without it |
| MFA enrollment | `enrollMfa()` → render `otpauth_uri` as a QR code (secret shown once) → `verifyMfaEnrollment(code)`; `disableMfa()` to turn it off. Show current MFA state from `me()` or the Users list (`mfa_enabled`) |
| Audit log view (if surfaced in Settings) | `listAuditLogs({action?, actor_id?, limit?, offset?})` — requires `audit:read`; read-only, no edit/delete UI exists or should be built |

### 5.4 Users & Roles

This screen maps 1:1 onto real endpoints. All of them require
permissions — the screen must hide or disable controls the caller
lacks, using the `permissions` array from `me()` (see §7 for the
fallback when the server disagrees).

| Screen element | Client method(s) | Permission |
|---|---|---|
| Users table | `listUsers()` — `UserOut[]` with role names | `users:manage` |
| User detail / roles for a user | `getUser(userId)`, `getUserRoles(userId)` | `users:manage` |
| Members table (status, owner, expiry) | `listMembers(orgId)` | `users:manage` |
| Suspend / reactivate member, set expiry | `updateMember(orgId, userId, {status: 'active' \| 'suspended', expires_at?})` | `users:manage` |
| Invite technician (+ pre-assign roles) | `inviteTechnician(orgId, {email, role_ids})` | `users:invite` |
| Pending invitations list | `listInvitations(orgId)` | `users:invite` |
| Revoke invitation | `revokeInvitation(orgId, invitationId)` | `users:invite` |
| Roles table | `listRoles()` — `RoleOut[]` with permission codes | `roles:manage` |
| Create role | `createRole({name, description, access_level, permission_codes})` | `roles:manage` |
| Edit role (description / access level) | `updateRole(roleId, {description?, access_level?})` — name is not editable here | `roles:manage` |
| Delete custom role | `deleteRole(roleId)` — 204, no body; system roles return 400, show the message | `roles:manage` |
| Configure role permissions | `permissionCatalog()` for the checkbox list; `configureRolePermissions(roleId, codes)` to save (replaces the whole set) | `permissions:manage` — note: **different** from `roles:manage` |
| Assign role to user | `assignRole(userId, roleId)` | `roles:manage` |
| Revoke role from user | `revokeRole(userId, roleId)` | `roles:manage` |
| Pending elevated-access approvals | `pendingApprovals()` | `roles:manage` |
| Approve / deny an approval | `decideApproval(approvalId, approve)` | `roles:manage` |
| Least-privilege policy panel | `getPolicy(orgId)`, `setPolicy(orgId, policy)` | `roles:manage` |
| Start / complete access review | `startAccessReview(orgId)`, `completeAccessReview(orgId, reviewId)` | `roles:manage` |

Screen notes:

- **Role names, not ids, in the users table:** `listUsers()` returns
  role *names* per user. Role *ids* (needed for assign/revoke/invite)
  come from `listRoles()`. Join them client-side by name only for
  display; use ids for every write.
- **Permission checkboxes:** render from `permissionCatalog()` (code,
  module, description), grouped by module — never hard-code the list,
  it grows with later phases. `configureRolePermissions` replaces the
  whole set, so the save must send the full checked list, not a diff.
- **Grant scope is server-side:** the API rejects granting permissions
  the caller doesn't hold (403). The UI should also disable checkboxes
  for permissions the caller lacks (from `me().permissions`), but the
  server's 403 is the authority — surface its message if it fires.
- **Elevated roles may need approval:** `assignRole` can return a
  pending-approval outcome instead of granting immediately when the org
  policy requires it. The UI must handle that response (show "approval
  requested", link to the pending approvals list) rather than assuming
  the role was granted.
- **Invite tokens are never returned:** `inviteTechnician` returns the
  invitation record only. The invitee gets the token by email. Do not
  build UI that expects to display or copy an invite link.
- **Departments / access levels in the mock:** the static screen may
  show department or access-level columns. Phase 1 has no department
  field (`MemberOut` has status/owner/expiry only; `RoleOut` has
  `access_level`). Show what the API returns; do not invent department
  values to fill the column.

### 5.5 Shared navigation / top bar

| Need | Client method |
|---|---|
| Auth guard on every internal page | `requireAuth()` (§6) |
| Current user + permissions (show/hide nav items) | `me()` |
| Org name + switcher | `getOrganization(orgId)` / `myOrganizations()` + `switchOrganization(orgId)` (§3) |
| Sign-out | `logout()` (§4) |
| Global loading state | `onLoadingChange` callback (§7) |

Nav items the caller may not use must be hidden based on `me()`
permissions (e.g. Users & Roles needs `users:manage` or `roles:manage`;
audit needs `audit:read`). Hiding is UX only — the server enforces it.

## 6. Route protection for every internal page

Every internal page (Command Center, Platform Settings, Users & Roles,
and any later internal page) runs this guard **before rendering
anything** (in the page's module script, first thing):

```js
import { api } from './api-instance.js'; // one shared NullApiClient

if (!api.requireAuth()) {
  // No access token, or it is expired per its `exp` claim.
  // Note: after a reload there is no access token by design (memory
  // only) but a refresh token may exist — try a silent refresh first
  // so a reload doesn't bounce the user to sign-in.
  try {
    await api.refreshToken();
  } catch {
    window.location.href = '/sign-in.html';
  }
  if (!api.requireAuth()) window.location.href = '/sign-in.html';
}
// Also require an org context for org-scoped pages:
if (!api.getOrgContext()) window.location.href = '/sign-in.html'; // or org-select
```

Notes:

- `requireAuth()` returns true only when an access token exists **and**
  its `exp` claim is in the future (30s skew allowance). It is a UI
  gate only — the server re-verifies on every request, and a token that
  passes here can still 401 (revoked, wrong org). The client's refresh
  flow covers that case; the page must not add its own retry loop.
- The sign-in, password-reset, and invitation-accept pages are the only
  public pages. Everything else redirects when unauthenticated.
- Do not cache a "logged in" flag in `localStorage` and skip the guard —
  the guard is the check.

## 7. Loading and error states

- **Loading:** the client's `onLoadingChange(loading)` fires from an
  in-flight counter — it stays `true` while *any* request is outstanding,
  so overlapping calls (e.g. `me()` + `listTickets()` on Command Center
  load) keep one spinner up until the last finishes. Wire it to a single
  global spinner / skeleton state. Do not build a per-button spinner
  that fights the global one; for destructive actions (delete role,
  revoke invitation) disable the button while its own call is in flight.
- **Errors — one pattern everywhere:** every client method throws
  `NullApiError {status, detail, errors}`. Catch it at the call site
  (or one shared handler) and render by status:
  - `0` — network failure: "Could not reach the API. Check your
    connection and try again." with a Retry button. Never show a stack
    trace.
  - `400` — show `detail` verbatim (e.g. "Invalid priority", system
    role delete refusal).
  - `401` — the client already tried a refresh; if it reaches the page,
    the session is gone and `onUnauthorized` has redirected. Pages must
    not show a second "session expired" dialog.
  - `403` — "You don't have permission to do that." plus `detail` when
    it helps (e.g. "Missing permission: roles:manage"). Offer the org
    switcher when the cause is an org mismatch. Never retry a 403.
  - `404` — "Not found." Note the API returns 404 for another org's
    records too, so the message must never claim "this belongs to
    someone else" — just that it isn't available here.
  - `422` — validation: show the first entry of `errors` (field +
    message) next to the offending field where possible; fall back to
    `detail`.
  - `429` — rate limit: show `detail`, disable the submit button
    briefly, do not auto-retry.
  - `5xx` — "Something went wrong on our side. Try again in a moment."
    with `X-Request-Id` available for a bug report (the client sends
    one per call; surface it in a details line, not the headline).
- **Empty states:** an empty tickets/users/roles list is a valid state
  ("No tickets yet", "No roles yet") — not an error. An empty result
  after a filter is also valid.
- **Optimistic updates:** do not optimistically apply writes. Wait for
  the API response (ticket numbers, role ids, and approval outcomes are
  all assigned server-side) and then re-fetch or apply the returned
  object.

## 8. What is deliberately not in this round

- **No live-frontend edits.** Nothing in this document authorizes
  changing the live frontend repo. The wiring happens only when the
  parent says the frontend rounds have settled.
- **No Tickets detail screen, no Endpoints/CMDB/Analytics wiring** —
  those need Phase 2/3 endpoints that do not exist yet.
- **No Agent UI** — the endpoint-agent contract is defined in
  `docs/API_CONTRACT.md` §9 for Phase 3; no agent endpoints exist in
  Phase 1 and no screen should call them.
- **No counts, charts, or SLA figures** on the Command Center until an
  endpoint returns them (§5.2).
- **No `localStorage` for tokens.** Refresh token stays in
  `sessionStorage`; access token stays in memory (§4).
- **No client-side permission invention.** The permission catalog comes
  from `permissionCatalog()`; the caller's permissions come from
  `me()`. Never hard-code either list into a screen.

## 9. Registration, onboarding, and invitations (backend ready, Nov 26, 2026)

The frontend wizard for these flows is a separate track; the API below
is the source of truth. Full curl examples live in
`docs/DEV_SETUP.md` (§4–§8).

### 9.1 Organization registration

- `POST /api/v1/auth/register` (public, 5/min) with
  `{org_name, org_email, website?, industry?, org_size?, admin_name,
  admin_email, password}` (password min 12). Returns `201` with
  `{organization, user_id, access_token, refresh_token}` — the admin is
  signed in immediately; store the tokens exactly as §4 describes.
- 409 when the admin email already exists: send the user to sign-in
  instead (they create another org from the authenticated
  `POST /api/v1/organizations`).
- Registration never creates a platform administrator; do not offer
  any platform path from the registration screen.
- The response's `organization` includes the slug (auto-suffixed on
  collision) and the profile fields; the onboarding record already
  exists with `profile` complete and `current_step: "departments"`.

### 9.2 Onboarding wizard

- `GET /api/v1/organizations/{org_id}/onboarding` → current step +
  per-step status. `PATCH` the same path with
  `{step, status: complete|skipped|in_progress, data?}`.
- Steps: `profile`, `departments`, `invite_technicians`,
  `service_desk`, `business_hours_sla`, `assets_endpoints`, `finish`.
  All but `profile`/`finish` are skippable. `finish` 400s while any
  other step is still pending, and locks the record once complete.
- Step data the wizard should send: `departments` →
  `{departments: [{name, description}]}` (creates them);
  `service_desk` → `{service_desk: {...}}` (merged into org settings);
  `business_hours_sla` → `{business_hours?, sla_policy?}` or `{}`
  (empty data creates the Mon–Fri 09:00–17:00 default calendar +
  default SLA policy). `invite_technicians` / `assets_endpoints`
  carry no data — the real work happens on the invitations / endpoints
  screens; marking them complete just records progress.

### 9.3 Technician invitations

- Invite: `POST /api/v1/organizations/{org_id}/invitations` with
  `{email, full_name, department, team, role_ids}` (org roles only).
  The `201` response includes `accept_url` — ONLY in dev mode (no
  email provider configured) is this how the admin reaches the link
  (no real email is sent; the message is also in
  `GET /organizations/{org_id}/outbox`). In configured mode
  `accept_url` is `null` — the invitee gets the link by email. Never
  log the URL.
- Every invitation response carries `delivery`:
  `{status: sent|failed|dev_recorded, provider, provider_message_id,
  attempts, last_error, delivered, dev_recorded}`. Show the delivery
  state on the invitations list (sent / failed / recorded locally).
  A failed send still creates the pending invitation — surface "email
  failed to send — resend it" with the error, never a success message.
  A misconfigured provider answers 503 and creates nothing.
- The invitee's accept page calls `GET /api/v1/auth/invitations/{token}`
  (public) for the pre-filled, **locked** name/email/org/roles, then
  `POST /api/v1/auth/invitations/accept` with `{token, full_name,
  password}`. After acceptance, offer TOTP enrollment
  (`POST /api/v1/auth/mfa/enroll`) before sign-in.
- Resend: `POST .../invitations/{id}/resend` (new link, old link
  dies). Revoke: `POST .../invitations/{id}/revoke`.
- Invitations expire after 48 hours; an expired/used/revoked token
  returns 400 on accept and 404 on lookup. Surface "this invitation
  is no longer valid — ask your admin to resend it", not the raw error.

### 9.4 Platform invitations (separate screen, separate flow)

- `POST /api/v1/platform/admin-invitations` (platform token +
  `platform:users:manage`, MFA) with `{email, full_name, role_id}`
  (platform role only). Accept via
  `POST /api/v1/platform/auth/invitations/accept`.
- Never mix the two invitation UIs: an org invitation must never
  offer a platform role, and a platform invitation must never mention
  an organization. Only a Platform Super Admin may invite to the
  Platform Super Admin role (403 otherwise).

### 9.5 Remove a technician (Organization Users)

- Remove action per row: `POST
  /api/v1/organizations/{org_id}/members/{user_id}/remove` with
  optional `{"reason"}`. Confirm first with a dialog showing the
  consequences: **access revoked immediately, assigned devices
  flagged for recovery, pending invites cancelled**.
- The `200` response is the removal report — render it in the
  confirmation result: `{user_id, email, full_name,
  membership_status: "deactivated", reason,
  invitations_cancelled: string[],
  assets_recovered: string[] (asset tags),
  tickets_created: [{ticket_id, number, asset_tag}],
  sessions_revoked, temp_grants_revoked}`.
- The member stays in the list with status `deactivated` (never
  deleted); re-adding requires a fresh invitation.
- Refusals (400, show the message): the organization owner, the last
  Organization Administrator, an already-removed member. 403 for a
  non-admin or cross-org call. Platform users are removed from the
  Platform Admin Users screen via the existing suspend action
  (`PATCH /api/v1/platform/admins/{user_id}/suspend`).

## 10. Phase 4 — enterprise operations (backend ready, Nov 26, 2026)

Full endpoint tables are in `docs/API_CONTRACT.md` §7.20–§7.27. Screen
mapping for the frontend track:

- **Workflows / automation** (`/api/v1/workflows`, `/api/v1/workflows/automation-rules`):
  workflow builder (versioned; publish needs ≥ 1 step; runs show
  per-step outcomes; retry re-runs only failed steps) and automation
  rules (ticket-scoped triggers `ticket.created` / `ticket.updated` /
  `ticket.priority_changed` / `sla_breach`; conditions on status,
  priority, category, assignee, sla_breached; actions assign,
  set_priority, set_status, add_comment, notify). Rules also fire
  automatically on ticket create/update — the rule list shows runs
  with what actually ran, including partial failures.
- **Custom forms** (`/api/v1/forms`): form builder (fields carry
  `key`, `label`, `field_type`, `required`, `options`); values are
  submitted per ticket (`POST /forms/{id}/tickets/{ticket_id}/values`)
  and validated server-side — show the 422 field errors inline.
- **Dashboards / reports** (`/api/v1/dashboards`, `/api/v1/reports`):
  dashboard builder with live widget data
  (`GET /dashboards/{id}/data`); report builder over `tickets` /
  `endpoints` / `vulnerabilities` with generate + CSV download
  (`xlsx` returns 501 — do not offer it); scheduled reports take a
  5-field cron + recipient emails and email a CSV per recipient.
- **Webhooks** (`/api/v1/webhooks`): create with `name`, `target_url`,
  `event_type`; the secret is returned **once** at creation — show it
  in a copy-once dialog and never fetch it again. Delivery history +
  test + manual retry are available. Events: `ticket.created`,
  `ticket.updated`, `ticket.resolved`, `change.created`,
  `change.approved`, `incident.declared`, `endpoint.enrolled`,
  `vulnerability.found`.
- **Integrations** (`/api/v1/integrations`): provider list first
  (`GET /integrations/providers`), then create + set credentials
  (never returned) + test connection.
- **API keys** (`/api/v1/api-keys`): create with `name` + `scopes`
  (permission codes); the raw key is returned **once** — copy-once
  dialog. Keys authenticate with the `X-Api-Key` header instead of a
  Bearer token; they cannot call user-identity endpoints (`/auth/me`,
  notifications list, org switcher, change approve) — those 403 for
  keys, so do not offer key auth for them.
- **GRC** (`/api/v1/grc`): controls (framework `soc2` / `iso27001` /
  `nist_csf` / `cis`, `code`, `title`), mappings, evidence (metadata
  only — no file upload), assessments, exceptions. Control status is
  derived server-side; never present `satisfied` as certification.
- **Links / releases / feature flags / status page** (`/api/v1/links`,
  `/api/v1/releases`, `/api/v1/feature-flags`, `/api/v1/status`):
  link builder over allow-listed entity types; release list (duplicate
  version → 409); flag list with per-org evaluate; status incidents +
  updates, and the public page `GET /status/public/{org_slug}`
  (no auth) for embedding.
