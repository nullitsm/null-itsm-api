# NULL ITSM API — Architectural Decisions

Decisions are recorded here when they are made, with the reason and the
date. A later decision supersedes an earlier one explicitly (never silently).

## 2026-11-26 — All sample data removed; tests build their own data
At the user's direction (Nov 25, 2026) every dev fixture and sample
record was removed: `app/seed.py` and `scripts/seed_dev.py` deleted, the
`NULL_SEED_DEV_FIXTURES` setting removed, the live-boot scripts rewired
to provision a real org through the public API from an empty database.
Tests create their own organizations/users fresh in the test database
via `tests/factories.py` (same RLS mechanics, no shipped fixtures). The
`organizations.is_dev_fixture` column and its API field stay in the
schema/contract untouched (always `false` now) so no migration or
contract change was needed. The `seed_org_roles` / `seed_platform_roles`
role-catalog seeders are NOT sample data — they define the permission
catalog — and stay.

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
- Org provisioning creates the admin user BEFORE the org; `accept_invitation` sets RLS
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

## 2026-11-26 — Phase 3: a completed patch scan is a full inventory
A completed `patch_scan` is treated as a full inventory of the
endpoint's patch state: a previously-missing finding for a patch the
scan does not report flips to `installed`. The alternative (findings
persist until explicitly cleared) would leave stale "missing" rows
forever after a patch is installed out-of-band. Scans that fail or are
cancelled change nothing.

## 2026-11-26 — Phase 3: failing job-result handlers audit and continue
When a downstream apply function (patch/vuln) fails while recording an
agent job result, the dispatch audits `agent.job_result_handler_failed`
(outcome failure) and swallows the error so the device's recorded
result survives. The alternative (500 the result call and roll it
back) would lose the device's ground-truth result and invite the agent
to re-report. Apply functions are idempotent, so a later re-application
stays safe.

## 2026-11-26 — Phase 3: the verify flow closes the remediate gap
PATCH forbade setting a finding to `remediated`, and nothing produced
that state, so verification could never run. The coordinator added
`POST /vulnerabilities/findings/{id}/verify`: it requires `in_progress`
with an open remediation link (or `remediated` for retry), flips finding
+ open links to `remediated`, and triggers verification — an agent
`vuln_scan` job (`{"verify_finding_id": …}`) when the endpoint is
enrolled, otherwise a queued `VulnScan` linked immediately. The job
issuance is authorized by the verify call's `vulnerabilities:manage`
permission. Importing results into a queued verification scan is
allowed even though it has no manual engine (it exists precisely to
receive an imported rescan); importing into any other non-manual scan
is still 400.

## 2026-11-26 — Phase 3: global tables have no RLS by design
`agent_releases` (release catalog) and `cve_catalog` (public CVE/KEV
data) are global, not tenant data: they carry no `organization_id` and
no RLS policy. Everything org-scoped in Phase 3 uses the standard RLS
ALL policy. The distinction is documented in the model files so a
missing policy is never "fixed" by adding tenant scoping to public data.

## 2026-11-26 — Phase 3: duplicate hostnames resolve, never 500
Hostnames are not unique (enrollment allows two machines to share one),
so `resolve_endpoint` used `scalar_one_or_none()` and raised
`MultipleResultsFound` on import — found by the live boot, where
re-enrolling the same hostname created duplicates. Correlation now
takes the most recently seen endpoint for the host (deterministic
ordering, `limit(1)`); a host with no match stays host-only rather than
being dropped. The same fix was applied to network discovery's
IP lookup (DHCP reuse) and to `delete_engine`'s default-promotion query
(`scalar_one_or_none()` over an unordered multi-row select).

## 2026-11-26 — Phase 3: parallel builders, coordinator integration
Four builders (A agent/endpoints, B patching, C vulnerabilities, D
CMDB/network) worked in parallel with strict file ownership; shared
files (`app/main.py`, `app/audit.py`, Celery beat) belonged to the
coordinator. The coordinator centralized audit-action literals into
`app/audit.py` constants, registered routers, wired beat entries, and
added the verify endpoint + tests. Two real bugs surfaced only in
full-suite / live-boot conditions: the `delete_engine` default
promotion (`scalar_one_or_none` without `limit(1)`) and the duplicate
hostname correlation above — both fixed at integration, with regression
tests, rather than dismissed as order noise.

## 2026-11-26 — Registration: duplicate email means "sign in", not "attach"

Public registration refuses an admin email that already belongs to an
account (409): the owner signs in and creates another org through the
authenticated endpoint. The alternative — attaching a new org to an
existing account from an unauthenticated endpoint — would let anyone
claim an org under someone else's email. Registration also never
creates a platform administrator: the org and platform domains share
no tables, roles, or invitation flows, and that separation is enforced
server-side, not by the frontend.

## 2026-11-26 — Registration: the accept link is a testing aid, not a secret

With no SMTP configured, invitation mail goes to the `dev_email_outbox`
table and the `accept_url` is returned to the inviting admin in the
create/resend response. The token itself is never logged and is stored
only as a SHA-256 hash. The link is single-use, bound to the invited
email + org, and expires in 48 hours; knowing an email address alone
never activates an account. Resend rotates the token (the old link
404s); revoke blocks acceptance outright.

## 2026-11-26 — Registration: RLS-blind reads need SECURITY DEFINER, not ORM selects

Two lookups that must work with no tenant context cannot use ORM
selects (RLS hides the rows): slug uniqueness at registration
(`org_slug_exists()`) and the public invitation lookup
(`auth_get_invitation_by_token`, extended with org name/slug, profile
fields, and role names). The same class of bug hid the platform
invitation row from `accept_platform_invitation` until the platform
context was set before the ORM read. Rule: any unauthenticated or
pre-context read goes through a SECURITY DEFINER function or sets its
context first — never a bare ORM query.

## 2026-11-26 — Phase 4: SLA sweep order is detect → escalate → automate

`scan_breaches` detects breaches only and returns `breached_ticket_ids`;
it never fires automation. The Celery sweep (`scan_sla_breaches`, every
5 min) evaluates Phase 2 escalation rules first, then fires
`sla_breach` automation rules for the tickets that breached. The order
matters: an automation action that changes a ticket (e.g. sets priority
critical) would otherwise defeat an escalation rule's conditions for
the same breach. Found when an unscoped `sla_breach` rule in the
integration suite made `test_escalation_actions` see 0 events.

## 2026-11-26 — Phase 4: API keys share the permission gates, not a parallel auth system

API keys authenticate through the same `get_principal` dependency:
bearer token wins when present, otherwise `X-Api-Key`. Key scopes are
permission codes, so `require_permission` applies unchanged, and the
key is RLS-scoped to its org. Endpoints that need a user identity get
an explicit `get_user_principal` guard (403 for keys) instead of
letting `principal.user_id == None` silently widen a query — the
notification list filter `== principal.user_id` would have become
`IS NULL` without it.

## 2026-11-26 — Phase 4: scheduled-report delivery has no retry by design

A scheduled report's CSV bytes are not stored (the delivery row holds
the rendered HTML/text bodies, but not the attachment). `deliver_email(..., retry=False)` skips the retry
enqueue for reports, so a failed delivery is recorded in
`email_deliveries` + the `report.generated` audit metadata and the
next scheduled run re-sends. `last_status` reflects generation only;
a delivery failure never rewrites it.

## 2026-11-26 — Phase 4: same-named return keys are a collision, not a contract

`apply_patch_scan_result` returns `{"new_findings": <int>}` (a count)
while `apply_vuln_scan_result` returns `{"new_findings": [<payloads>]}`.
The agent job-result endpoint iterated the key unconditionally and
500'd on every patch result in live boot. The fix iterates only the
list shape and is covered by `test_patch_job_result_still_accepted`.
Lesson: dispatch return values are per-handler shapes — consumers
must check the shape, not the key name.

## 2026-11-26 — Phase 4: webhook delivery is synchronous in-process for now

`emit_event` fans out post-commit in the request process (bounded by
the 10s httpx timeout, max 3 attempts) and never raises. A slow or
failing subscriber delays the response. Async delivery (a Celery
fan-out task) is the documented future improvement; it was not built
because the delivery semantics (HMAC signing, retry, append-only
delivery rows) are the same either way and the sync path is
observable and testable today.
