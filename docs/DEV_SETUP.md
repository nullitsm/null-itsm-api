# NULL ITSM — Local Development Setup

Local multi-organization testing environment. **No AWS, no spend, no
real email.** PostgreSQL 16 + Redis 7 on this machine, the FastAPI
backend, and the static frontend served locally. This environment is
completely separate from the live site at https://nullitsm.github.io —
nothing here touches production data, and no sample/fixture data
exists anywhere in the repo: every org, user, ticket, and asset you
see is one you created through the API.

## 1. Prerequisites

- PostgreSQL 16 running locally (database `null_itsm_live` for manual
  testing; the test suite uses its own `null_itsm_test` database).
- Redis 7 running locally.
- Python 3.12 with the repo virtualenv (`.venv`).
- The frontend screens in `~/workspace/itsm-push/` (separate repo
  track; this doc only covers pointing them at the local backend).

## 2. Start the backend

```bash
cd ~/workspace/null-itsm-api

# Fresh empty database (drops and recreates null_itsm_live, runs
# alembic to head — migration 0013, registration + onboarding):
.venv/bin/python scripts/live_boot_setup.py

# Backend on :8001 (dev settings; CORS allows the local frontend):
NULL_ENV=dev \
NULL_DATABASE_URL="postgresql+psycopg://null_app:dev_app_password@127.0.0.1:5432/null_itsm_live" \
NULL_DATABASE_OWNER_URL="postgresql+psycopg://null_owner:dev_owner_password@127.0.0.1:5432/null_itsm_live" \
NULL_REDIS_URL="redis://127.0.0.1:6379/0" \
NULL_JWT_SECRET="dev-only-jwt-secret" \
NULL_FIELD_ENCRYPTION_KEY="$(.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Health check: `curl http://127.0.0.1:8001/health` → `{"status":"ok"}`.
API docs: http://127.0.0.1:8001/docs

`NULL_FIELD_ENCRYPTION_KEY` is a Fernet key (generate one with
`python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`).
Webhook secrets and integration credentials are Fernet-encrypted at
rest and creation **fails closed without it** (`"field encryption is
not configured"`) — there is no plaintext fallback. The key must be
stable across restarts for stored secrets to remain decryptable; a
fresh dev key per boot is fine for throwaway local databases only.
The live-boot check script generates one per run automatically.

The dev-only credentials above are the local defaults from
`tests/conftest.py`. Never use them anywhere else; production values
come from environment variables, never from the repo.

## 3. Serve the frontend locally

```bash
cd ~/workspace/itsm-push
python3 -m http.server 8124
```

Open http://127.0.0.1:8124/null-itsm-sign-in.html. Point the frontend
API client at `http://127.0.0.1:8001` (see `docs/FRONTEND_INTEGRATION.md`).
The live site keeps its demo sign-in (any non-empty credentials);
the local backend requires real accounts created through the API below.

## 4. Register your first organization

```bash
curl -s -X POST http://127.0.0.1:8001/api/v1/auth/register \
  -H 'Content-Type: application/json' -d '{
    "org_name": "NULL Demo Corporation",
    "org_email": "admin@nulldemo.example",
    "website": "https://example.com",
    "industry": "Technology",
    "org_size": "11-50",
    "admin_name": "Demo Admin",
    "admin_email": "admin@nulldemo.example",
    "password": "ChangeMe123!@#"
  }'
```

Returns `201` with the organization (including its slug), the admin
`user_id`, and `access_token` / `refresh_token` — the admin is signed
in immediately. Registration also creates the owner membership, the
Organization Administrator role grant, default settings, the three
default departments (IT Operations, Service Desk, Security), and the
onboarding record (profile step already complete).

Rules:
- The admin email must be new. An existing account signs in and
  creates another org via `POST /api/v1/organizations` instead.
- Registration **never** creates a platform administrator. Org admin
  credentials return `401` on `/api/v1/platform/auth/login`.
- Same org name twice → the second org gets a suffixed slug
  (`genesee-test-organization-2`).
- Rate limited: 5 registrations/minute per IP.

Save the token: `TOKEN=<access_token from the response>`.

## 5. Invite a technician (email-based, local)

```bash
curl -s -X POST http://127.0.0.1:8001/api/v1/organizations/<org_id>/invitations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
    "email": "tech@nulldemo.example",
    "full_name": "Tech One",
    "department": "Service Desk",
    "team": "Tier 1",
    "role_ids": ["<service-desk-technician-role-id>"]
  }'
```

The response (`201`) contains the invitation **and its `accept_url`** —
the link the invitee would receive by email. No real email is sent:
when SMTP is unconfigured, the backend writes the message to the dev
outbox instead, and the link is also returned to the inviting admin
for testing.

**Configured mode (real email).** Set `NULL_EMAIL_PROVIDER=resend`
with either `NULL_RESEND_API_KEY` in the environment, or — on this VM
— no key at all: the backend fetches the key as an authd surrogate
per send (see `docs/EMAIL.md`). Then the invite is sent for real,
`accept_url` is `null`, and the response carries `delivery`
(`{status, provider, provider_message_id, attempts, last_error,
delivered, dev_recorded}`). The sender must be
`NULL_EMAIL_FROM=onboarding@resend.dev` until a domain is verified
in Resend (that sender can only mail the account owner's inbox).

Read the outbox any time:

```bash
curl -s http://127.0.0.1:8001/api/v1/organizations/<org_id>/outbox \
  -H "Authorization: Bearer $TOKEN"
```

The invitation link is in the message body. Invitations are
single-use, bound to the invited email AND organization, and expire
after **48 hours**. The accept page pre-fills name + email (locked —
the invitee cannot change org or roles).

Accept the invitation (as the invitee):

```bash
# 1. Look the invitation up (public, no auth):
curl -s "http://127.0.0.1:8001/api/v1/auth/invitations/<token>"

# 2. Accept it — creates the account, activates the membership:
curl -s -X POST http://127.0.0.1:8001/api/v1/auth/invitations/accept \
  -H 'Content-Type: application/json' -d '{
    "token": "<token>",
    "full_name": "Tech One",
    "password": "ChangeMe123!@#"
  }'

# 3. Sign in, then set up TOTP MFA (existing Phase 1 endpoints):
curl -s -X POST http://127.0.0.1:8001/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"email":"tech@nulldemo.example","password":"ChangeMe123!@#"}'
curl -s -X POST http://127.0.0.1:8001/api/v1/auth/mfa/enroll \
  -H "Authorization: Bearer <tech-token>"
```

Resend regenerates the token (the old link dies immediately):
`POST /api/v1/organizations/<org_id>/invitations/<id>/resend`.
Revoke blocks acceptance:
`POST /api/v1/organizations/<org_id>/invitations/<id>/revoke`.

## 6. Multi-organization testing

Register a second and third org the same way (e.g. Acme Technology
Group, Genesee Test Organization), invite different technicians into
each, and verify isolation: cross-org reads return `403` (org-scoped
endpoints) or `404` (records — existence is never revealed), and
cross-org writes are rejected. Each org has its own users, tickets,
assets/endpoints, departments/teams, roles, and settings.

A user who belongs to several orgs gets `status: "org_required"` at
login, with an `org_select_token` and the org list:

```bash
# Select the active org (token in the Authorization header):
curl -s -X POST http://127.0.0.1:8001/api/v1/auth/select-organization \
  -H "Authorization: Bearer <org_select_token>" \
  -H 'Content-Type: application/json' -d '{"organization_id": "<org_id>"}'

# Switch later, with a refresh token (server-side, never frontend-only):
curl -s -X POST http://127.0.0.1:8001/api/v1/auth/switch-organization \
  -H 'Content-Type: application/json' -d '{"refresh_token": "<refresh_token>", "organization_id": "<other_org_id>"}'
```

## 7. Onboarding

Progress is stored per org in `org_onboarding` and driven by the API
(the frontend wizard is a separate track):

```bash
# Current progress:
curl -s http://127.0.0.1:8001/api/v1/organizations/<org_id>/onboarding \
  -H "Authorization: Bearer $TOKEN"

# Complete / skip a step (profile is already complete at registration):
curl -s -X PATCH http://127.0.0.1:8001/api/v1/organizations/<org_id>/onboarding \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
    "step": "business_hours_sla", "status": "complete", "data": {}
  }'
```

Steps: `profile` → `departments` → `invite_technicians` →
`service_desk` → `business_hours_sla` → `assets_endpoints` →
`finish`. All except `profile` and `finish` are skippable. Completing
`business_hours_sla` with empty data creates the default calendar
(Mon–Fri 09:00–17:00) and default SLA policy; completing
`departments` with `{"departments": [{"name": ...}]}` creates them;
`service_desk` data merges into org settings. `finish` requires every
other step complete or skipped, then locks onboarding.

## 8. Platform invitations (separate workflow)

Platform administrators are invited through a **separate** flow with
separate authorization — org invitations can never create one:

```bash
# As a platform admin (platform@null.example.com in the test DB;
# create platform admins via scripts/bootstrap_platform_admin.py):
curl -s -X POST http://127.0.0.1:8001/api/v1/platform/admin-invitations \
  -H "Authorization: Bearer <platform-token>" -H 'Content-Type: application/json' -d '{
    "email": "ops@null.example", "full_name": "Ops Person",
    "role_id": "<platform-administrator-role-id>"
  }'

# Accept (public): creates the platform admin with the invited role.
curl -s -X POST http://127.0.0.1:8001/api/v1/platform/auth/invitations/accept \
  -H 'Content-Type: application/json' -d '{"token": "<token>", "password": "ChangeMe123!@#"}'
```

Only a Platform Super Admin may invite someone to the Platform Super
Admin role. The platform outbox is `GET /api/v1/platform/outbox`.

## 9. Real devices, no fabricated results

The only real endpoints in this environment are the ones you enroll.
Miah's real devices (MacBook Air "Jamiahs-MacBook-Air-2", iPhone 17
Pro Max) are **not** enrolled here — enroll an endpoint through the
agent flow (`POST /api/v1/endpoints/enrollment-tokens`, then the agent
handshake) and its inventory comes from the device itself. The backend
never invents vulnerability findings and never claims an action ran
on a device when it did not.

## 10. Resetting

```bash
# Wipe the manual-test database and start over (empty):
.venv/bin/python scripts/live_boot_setup.py

# Drop it entirely when done:
psql "postgresql://postgres:dev_postgres_password@127.0.0.1:5432/postgres" \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='null_itsm_live'"
psql "postgresql://postgres:dev_postgres_password@127.0.0.1:5432/postgres" \
  -c "DROP DATABASE null_itsm_live"
```

## 11. Tests

```bash
# Full suite — ALWAYS the locked script (order-dependence is real):
bash scripts/run_tests_locked.sh -q
# Registration / invitation / onboarding / switching only:
bash scripts/run_tests_locked.sh -q tests/test_registration.py
```
