# NULL ITSM API

Multi-tenant enterprise ITSM platform backend — modular monolith in
Python (FastAPI + PostgreSQL + SQLAlchemy + Alembic + Redis/Celery).
This repo is the **backend** component of the NULL platform. The live
frontend is `nullitsm/nullitsm.github.io` (do not edit it from here);
the master repo is `nullitsm/null-platform`.

## Architecture

```
FastAPI app (app/main.py, /api/v1)
  ├─ Routers: health, auth, organizations, users, roles, audit, tickets, platform
  ├─ Services: auth_service, org_service, role_service, platform_service, email, storage
  ├─ Models: platform (orgs/users/memberships), rbac, auth, audit, ticket, access,
  │           platform_admin (second administrative domain)
  ├─ RLS: organization_id on every tenant row; SET LOCAL context per transaction
  ├─ Celery: tenant-aware workers (expire memberships, invitation email, audit export)
  └─ Infra (code only): infra/terraform + infra/ci-cd — NOTHING PROVISIONED
```

Key docs: `docs/API_CONTRACT.md` (endpoint reference), `docs/DATA_MODEL.md`
(unified model, all phases), `docs/SECURITY.md` (security model),
`docs/DECISIONS.md` (why things are the way they are),
`docs/DEVELOPMENT_REGISTER.md` (phase plan + status),
`docs/FRONTEND_INTEGRATION.md` (wiring guide, deferred).

## Quickstart (local dev)

Prerequisites: Python 3.12, PostgreSQL 16, Redis 7. (Docker is NOT
available in this VM; `docker-compose.yml` is code-only — see below.)

```bash
# 1. Database roles (dev only — run once as the postgres superuser)
#    Passwords below are the dev values used by the test suite.
psql -U postgres -c "CREATE ROLE null_app LOGIN PASSWORD 'dev_app_password';"
psql -U postgres -c "CREATE ROLE null_owner LOGIN PASSWORD 'dev_owner_password';"
psql -U postgres -c "CREATE DATABASE null_itsm OWNER null_owner;"

# 2. Environment
cp .env.example .env        # then set DATABASE_URL / secrets (see below)

# 3. Install + migrate (no sample data — a fresh database is empty)
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/alembic upgrade head

# 4. Run the API + worker
.venv/bin/uvicorn app.main:app --reload --port 8000
.venv/bin/celery -A app.tasks.celery_app worker --loglevel=info

# 5. Tests — ALWAYS the locked script (full-suite order-dependence is real)
bash scripts/run_tests_locked.sh -q
```

No sample data: there are no dev fixtures or demo records anywhere in
this repo. A fresh database is empty; organizations are created through
the public registration API (`POST /api/v1/auth/register` — see
`docs/DEV_SETUP.md` for the full local setup, registration, invitation,
and onboarding walkthrough). Tests create their own data fresh in the
test database via `tests/factories.py`.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `NULL_DATABASE_URL` | PostgreSQL DSN for the app (as `null_app`) | `postgresql+psycopg://null_app:dev_app_password@127.0.0.1:5432/null_itsm` |
| `NULL_OWNER_DATABASE_URL` | DSN for migrations/seed (as `null_owner`) | `postgresql+psycopg://null_owner:dev_owner_password@127.0.0.1:5432/null_itsm` |
| `NULL_REDIS_URL` | Redis (Celery broker + rate limiting) | `redis://127.0.0.1:6379/0` |
| `NULL_JWT_SECRET` | HS256 signing secret (dev issuer) | — (required; use a long random value) |
| `NULL_FIELD_ENCRYPTION_KEY` | Fernet key for webhook secrets, integration credentials, engine passwords | — (required for webhook/integration-credential creation; fails closed without it — generate with `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`) |
| `NULL_EMAIL_PROVIDER` | `none` (dev outbox) / `resend` (real sending) | `none` |
| `NULL_RESEND_API_KEY` | Resend key (env-key path; on this VM the authd surrogate is used instead — see `docs/EMAIL.md`) | — |
| `NULL_OIDC_ISSUER` | OIDC issuer URL (production: Cognito). When set, tokens are verified RS256 via JWKS | unset (dev JWT issuer) |
| `NULL_CORS_ORIGINS` | Allowed origins (production: the GitHub Pages origin) | dev localhost origins |
| `NULL_ENV` | `development` / `production` | `development` |
| `NULL_PLATFORM_ADMIN_EMAIL` / `NULL_PLATFORM_ADMIN_PASSWORD` | Bootstrap script (`scripts/bootstrap_platform_admin.py`) | — |

## Deployment order

1. Provision the database and the `null_app` / `null_owner` roles.
2. Run `alembic upgrade head` as `null_owner`.
3. Create the first Platform Super Admin with
   `scripts/bootstrap_platform_admin.py`.
4. Start the API, then the Celery worker.

## What is AWS-gated (nothing provisioned, nothing spent)

Staging deployment (ECS Fargate), Cognito provisioning, RDS/ElastiCache/S3
provisioning, Secrets Manager, backups/DR testing — all require explicit
user infrastructure approval. The Terraform in `infra/terraform/` and the
CI/CD pipeline in `infra/ci-cd/` are code only; run `terraform validate` /
`plan` before any apply, and store remote state encrypted (secret values
land in Terraform state).

## What is deferred

- **Frontend integration** — the API contract and JS client
  (`frontend/null-api-client.js`) live here; pages are wired only when
  the parent says the live frontend rounds have settled.
- **Payments** — billing integration architecture only (Phase 5); no real
  payments until the provider + production credentials are approved.
- **Endpoint agent** — its own repo (`nullitsm/null-endpoint-agent`,
  Phase 3); this repo defines only the agent API contract
  (`docs/API_CONTRACT.md` §9).

## Honesty rules (absolute)

- No placeholder functionality presented as production. No fabricated
  auth, API responses, persistence, or security results.
- Vulnerability findings: real engines, real CVE/KEV data, real stored
  evidence; simulated states clearly labelled.
- GRC features help customers manage compliance; they do NOT make NULL
  certified — never claim certification.
- No sample data anywhere in the repo: a fresh database is empty
  (`organizations.is_dev_fixture` stays in the schema and is always
  `false` now). Test data is built fresh per run and never shipped.
- If Docker or anything else cannot actually run, report it as a blocker
  — do not fake a passing result. (Docker is unavailable in this VM.)
