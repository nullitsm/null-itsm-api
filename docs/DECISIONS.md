# NULL ITSM API — Architectural Decisions

Decisions are recorded here when they are made, with the reason and the
date. A later decision supersedes an earlier one explicitly (never silently).

## 2026-11-25 — Modular monolith, not microservices
FastAPI + PostgreSQL + SQLAlchemy + Alembic + Redis/Celery, one deployable.
Reason: a small team ships a coherent product faster; module boundaries are
enforced by packages, not network calls. Revisit only if a module needs
independent scaling.

## 2026-11-25 — RLS enabled, NOT forced
`ENABLE ROW LEVEL SECURITY` without `FORCE`. Reason: the owner-owned
SECURITY DEFINER pre-auth lookup functions must bypass RLS to read a
credential row before any context exists; PostgreSQL refuses that under
FORCE ("query would be affected by row-level security policy"). The
security boundary is the application role: `null_app` owns nothing and
has no BYPASSRLS, so RLS always applies to it. An earlier
`SET row_security = off` attempt was removed for the same reason.

## 2026-11-25 — INSERT … RETURNING is checked against the SELECT policy
PostgreSQL checks an INSERT's RETURNING output against the SELECT policy.
A newly inserted row is invisible until its visibility condition exists
(e.g. an org row has no membership yet; a user row has no membership yet).
Consequences, applied everywhere:
- `organizations.created_by_id` + a creator clause in the org SELECT/UPDATE policies.
- Seed creates the admin user BEFORE the org; `accept_invitation` sets RLS
  context to the new user's id before inserting them.
- A new user's id must be client-generated (`uuid.uuid4()`) BEFORE the
  context is set — SQLAlchemy applies the uuid default only at flush.
- Responses are built BEFORE `session.commit()` in mutating routes: the
  SET LOCAL context dies at commit, and server-computed columns
  (`updated_at` with `onupdate`) expire on flush and re-fetch after commit
  → `ObjectDeletedError` if the response is built after commit.

## 2026-11-25 — No UPDATE/DELETE policy means silent zero rows, not an error
With no policy for a command, PostgreSQL's default-deny updates/deletes
ZERO rows instead of raising. The append-only audit guarantee is therefore
verified by row counts (nothing changes), not by an exception. Tests assert
`rowcount == 0` and the row unchanged.

## 2026-11-25 — One shared slowapi Limiter
`app/rate_limit.py` holds the single `Limiter` instance used by the app and
every router decorator. Reason: the auth router originally created its own
instance, so `limiter.enabled = False` in tests never disabled the login
limit (429s in the full suite). Tests disable rate limiting via that one object.

## 2026-11-25 — Two independent administrative domains
Organization users and platform admin users are separate models, separate
identity/membership relationships, separate permission namespaces, and
separate JWT types (`access` vs `platform_access`). Never a single role
column, never a filter on one directory. Rules:
- Org catalog contains no `platform:*` code (removed in migration 0002);
  the org role editor rejects `platform:`-prefixed codes explicitly.
- Only Platform Super Admin holds `platform:roles:manage` and may
  grant/revoke the Platform Super Admin role.
- Platform `*:manage` permissions require an MFA-verified token;
  `*:read` works without MFA.
- Platform access to tenant data requires an explicit, time-boxed grant,
  enforced in the database (`platform_support_list_org_users`) and audited.
- Migration preserves existing accounts/credentials; no existing user is
  assumed to be a platform admin; unclassifiable accounts are flagged
  `review_status='pending_review'` for manual review. Downgrade restores
  the org catalog rows.
- RLS for platform tables gates on `app.current_platform_user_id`; a
  platform session sets NO org context, so org tables are invisible to it
  through the ORM — tenant reads go only through the grant-checked
  SECURITY DEFINER functions.

## 2026-11-25 — Test fixtures: session-scoped auth, one shared DB
The suite shares one test DB and session-scoped login fixtures. Rules learned:
- `conftest._setup_database` must run exactly once per process: pytest loads
  the file as `conftest` AND as `tests.conftest` (from in-test imports), and
  a second run drops the DB mid-test. Guarded by the `NULL_TEST_DB_READY`
  env flag.
- Tests that mutate shared state (password reset, refresh rotation) leak
  into later tests. Prefer per-test users; never assume a fixture password
  is unchanged after a test that resets it.
- Count assertions on shared tables must assert scoping (all rows belong to
  the org, sets disjoint), not exact counts — other tests create rows too.

## 2026-11-25 — Real data only; no invented findings
Vulnerability findings come from real engines and real CVE/KEV data with
stored evidence. Simulated agent states are clearly labelled. The same
honesty rule applies to GRC: mappings and evidence help customers manage
compliance; they do NOT make NULL certified. Never claim certification.
Payments: integration architecture only until the provider + production
credentials are approved. AWS: code only, nothing provisioned, nothing spent.

## 2026-11-25 — Frontend integration is deferred; contracts live here
The live frontend (`nullitsm/nullitsm.github.io`, baseline head
`be38333228373760cad736a876b8305c150c79f6`) is built by separate rounds.
This repo ships the API contract (`docs/API_CONTRACT.md`) and a shared JS
client (`frontend/null-api-client.js`); pages are wired only when the
parent says their rounds have settled. Never edit the frontend from here.

## 2026-11-26 — Phase 2: SLA state is derived, not trusted
`first_response_at` comes from the earliest non-requester comment,
`resolved_at` from status transitions; due dates come from the resolved
policy through business-hours math. The ticket-create hook stamps due
dates immediately; the 5-minute breach sweep re-derives state for every
open ticket, so a missed hook can never leave a ticket unstamped
forever. Escalations are one-shot per (rule, ticket) — a rule never
re-fires for the same ticket, so a bad rule cannot repeatedly bump
priority.

## 2026-11-26 — Phase 2: sweeps enumerate orgs through a SECURITY DEFINER function
The application role cannot read `organizations` without an RLS context,
so the SLA and recurring-ticket sweeps enumerate through
`list_organization_ids()` (migration 0008, owner-owned, ids only),
and the mail poller through its own narrower function. Per-org work is
always RLS-scoped to the enumerated id. The old `Membership DISTINCT`
enumeration pattern (same as Phase 1 `expire_memberships`) returns zero
rows under `null_app` and must not be used for sweeps.

## 2026-11-26 — Phase 2: unknown email senders never get auto-created tickets
Inbound mail from an address that matches no active org member is stored
with status `received` and no ticket, for manual triage via `/convert`.
Auto-creating tickets for strangers would let anyone file tickets into
any org whose mailbox address they know.

## 2026-11-26 — Phase 2: attachments are JSON metadata, not multipart
`python-multipart` is not installed, so `POST /tickets/{id}/attachments`
takes JSON (`{filename, content_type, size_bytes, content_base64?}`).
Bytes go to storage only when configured; otherwise 503 and nothing is
stored. File content is never in the database. Multipart upload can be
added later by installing `python-multipart` and switching the endpoint.

## 2026-11-26 — Phase 2: SAML ACS validates but mints no session
The ACS endpoint validates the assertion with `python3-saml` and returns
the subject; it does not issue a session. SSO session issuance is a
separate decision (session binding, MFA step-up for SAML logins). Portal
login likewise rejects MFA-enabled users — the portal has no MFA
challenge step. Neither gap is papered over with a fake login.

## 2026-11-26 — Phase 2: license override is explicit, never silent
Seat assignment at capacity is blocked (400). An admin may pass
`override: true`, which assigns the seat AND flips the license status to
`exceeded`. Over-allocation is therefore always visible in the
compliance view, never silently permitted.

## 2026-11-26 — Phase 2: asset lifecycle pulled forward from Phase 3
The Phase 2 brief put asset lifecycle + software licensing in Tier 1,
so migrations 0007 implements them in Phase 2. Endpoints, patching,
vulnerabilities, and CMDB configuration items stay in Phase 3. The
register and data model record the move so Phase 3 is not double-scoped.

## 2026-11-26 — Phase 2: parallel builders, one shared test DB
Four builders worked the same repo in parallel with a filesystem test
lock (`scripts/run_tests_locked.sh` — bare `pytest` while siblings work
recreates the shared test DB mid-run and produces noise). Rules learned:
migrations first (the chain 0004→0007 must exist before anyone's suite
can run), shared files owned by the coordinator only, cross-workstream
imports lazy inside functions, and tests that mutate shared fixture
state (e.g. suspending the fixture technician) must use a fresh user or
restore the fixture — order-dependent failures are environmental, not
code, until proven otherwise by an isolated re-run.
