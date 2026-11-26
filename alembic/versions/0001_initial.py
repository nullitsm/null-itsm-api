"""Initial schema: platform tables, permission catalog, RLS policies.

Revision ID: 0001
Revises:
Create Date: 2026-11-25

This migration creates every Phase 1 table, seeds the permission catalog,
creates the controlled SECURITY DEFINER lookup functions used by the
authentication flows, and enables Row-Level Security on every
tenant-owned table (enabled, not forced — see the RLS comment in
upgrade() for why the owner must bypass RLS).

Deployment order (see README.md):
  1. Provision the database and the null_app / null_owner roles.
  2. Run `alembic upgrade head` as null_owner.
  3. Seed dev fixtures only in development (scripts/seed_dev.py).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models import Base
from app.permissions import PERMISSIONS

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# (table, policy_name, command, using_expr, check_expr)
# command is one of SELECT | INSERT | UPDATE | DELETE | ALL.
# A None expr means "not applicable for this command".
POLICIES = [
    # organizations: readable by active members, or by the user who created
    # the organization. The creator clause matters at creation time:
    # INSERT ... RETURNING is checked against the SELECT policy, and no
    # membership row exists yet when the org row is first inserted.
    (
        "organizations",
        "org_select",
        "SELECT",
        "(EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id = organizations.id "
        "AND m.user_id::text = current_setting('app.current_user_id', true) AND m.status = 'active') "
        "OR organizations.created_by_id::text = current_setting('app.current_user_id', true))",
        None,
    ),
    ("organizations", "org_insert", "INSERT", None, "current_setting('app.current_user_id', true) <> ''"),
    (
        "organizations",
        "org_update",
        "UPDATE",
        "(EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id = organizations.id "
        "AND m.user_id::text = current_setting('app.current_user_id', true) AND m.status = 'active') "
        "OR organizations.created_by_id::text = current_setting('app.current_user_id', true))",
        "(EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id = organizations.id "
        "AND m.user_id::text = current_setting('app.current_user_id', true) AND m.status = 'active') "
        "OR organizations.created_by_id::text = current_setting('app.current_user_id', true))",
    ),
    # users: own row, or users who share an organization with the caller.
    (
        "users",
        "users_select",
        "SELECT",
        "id::text = current_setting('app.current_user_id', true) OR EXISTS ("
        "SELECT 1 FROM memberships m1 JOIN memberships m2 ON m1.organization_id = m2.organization_id "
        "WHERE m1.user_id::text = current_setting('app.current_user_id', true) AND m1.status = 'active' "
        "AND m2.user_id = users.id AND m2.status = 'active')",
        None,
    ),
    ("users", "users_insert", "INSERT", None, "current_setting('app.current_org_id', true) <> ''"),
    (
        "users",
        "users_update",
        "UPDATE",
        "id::text = current_setting('app.current_user_id', true)",
        "id::text = current_setting('app.current_user_id', true)",
    ),
    # memberships: a user reads their own; an org context reads the org's.
    (
        "memberships",
        "memberships_select",
        "SELECT",
        "user_id::text = current_setting('app.current_user_id', true) "
        "OR organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    (
        "memberships",
        "memberships_insert",
        "INSERT",
        None,
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "memberships",
        "memberships_update",
        "UPDATE",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "memberships",
        "memberships_delete",
        "DELETE",
        "organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    # roles: org roles, plus the NULL-org system templates (read-only use).
    (
        "roles",
        "roles_select",
        "SELECT",
        "organization_id::text = current_setting('app.current_org_id', true) OR organization_id IS NULL",
        None,
    ),
    ("roles", "roles_insert", "INSERT", None, "organization_id::text = current_setting('app.current_org_id', true)"),
    (
        "roles",
        "roles_update",
        "UPDATE",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    ("roles", "roles_delete", "DELETE", "organization_id::text = current_setting('app.current_org_id', true)", None),
    # role_permissions: same scoping as roles.
    (
        "role_permissions",
        "role_permissions_select",
        "SELECT",
        "organization_id::text = current_setting('app.current_org_id', true) OR organization_id IS NULL",
        None,
    ),
    (
        "role_permissions",
        "role_permissions_insert",
        "INSERT",
        None,
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "role_permissions",
        "role_permissions_delete",
        "DELETE",
        "organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    # user_roles: strictly org-scoped.
    (
        "user_roles",
        "user_roles_select",
        "SELECT",
        "organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    (
        "user_roles",
        "user_roles_insert",
        "INSERT",
        None,
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "user_roles",
        "user_roles_delete",
        "DELETE",
        "organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    # invitations / invitation_roles / sessions / password_resets
    (
        "invitations",
        "invitations_all",
        "ALL",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "invitation_roles",
        "invitation_roles_all",
        "ALL",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "sessions",
        "sessions_select",
        "SELECT",
        "user_id::text = current_setting('app.current_user_id', true) "
        "OR organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    (
        "sessions",
        "sessions_insert",
        "INSERT",
        None,
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "sessions",
        "sessions_update",
        "UPDATE",
        "user_id::text = current_setting('app.current_user_id', true) "
        "OR organization_id::text = current_setting('app.current_org_id', true)",
        "user_id::text = current_setting('app.current_user_id', true) "
        "OR organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "password_resets",
        "password_resets_all",
        "ALL",
        "user_id::text = current_setting('app.current_user_id', true)",
        "user_id::text = current_setting('app.current_user_id', true)",
    ),
    # audit_logs: SELECT + INSERT only. No UPDATE/DELETE policy exists, so
    # those statements are denied — the append-only guarantee.
    (
        "audit_logs",
        "audit_logs_select",
        "SELECT",
        "organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    (
        "audit_logs",
        "audit_logs_insert",
        "INSERT",
        None,
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    # tickets + counters: strictly org-scoped.
    (
        "tickets",
        "tickets_all",
        "ALL",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "ticket_counters",
        "ticket_counters_select",
        "SELECT",
        "organization_id::text = current_setting('app.current_org_id', true)",
        None,
    ),
    (
        "ticket_counters",
        "ticket_counters_insert",
        "INSERT",
        None,
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "ticket_counters",
        "ticket_counters_update",
        "UPDATE",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    # access governance: strictly org-scoped.
    (
        "access_approvals",
        "access_approvals_all",
        "ALL",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
    (
        "access_reviews",
        "access_reviews_all",
        "ALL",
        "organization_id::text = current_setting('app.current_org_id', true)",
        "organization_id::text = current_setting('app.current_org_id', true)",
    ),
]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

FUNCTIONS_SQL = """
-- Controlled bypass surface for pre-authentication lookups. Each function
-- is SECURITY DEFINER, owned by the migration role, with a locked
-- search_path. They return exactly one row for a credential (email / token
-- hash) and are the ONLY way the application reads users, invitations,
-- password resets, or sessions before an RLS context exists. They work
-- because RLS is enabled but NOT forced on these tables: the owner role
-- bypasses RLS, so an owner-owned SECURITY DEFINER function can read the
-- credential row. The application role (null_app) can never call these
-- functions to enumerate anything — each takes an exact credential and
-- returns at most the one matching row.
CREATE OR REPLACE FUNCTION auth_get_user_by_email(p_email text)
RETURNS TABLE (id uuid, email text, password_hash text, full_name text,
               is_active boolean, email_verified boolean,
               mfa_enabled boolean, mfa_secret text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.email, u.password_hash, u.full_name, u.is_active,
         u.email_verified, u.mfa_enabled, u.mfa_secret
  FROM users u WHERE u.email = p_email;
$$;

CREATE OR REPLACE FUNCTION auth_get_invitation_by_token(p_hash text)
RETURNS TABLE (id uuid, organization_id uuid, email text, token_hash text,
               invited_by_id uuid, status text, expires_at timestamptz,
               accepted_at timestamptz, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT i.id, i.organization_id, i.email, i.token_hash, i.invited_by_id,
         i.status, i.expires_at, i.accepted_at, i.created_at
  FROM invitations i WHERE i.token_hash = p_hash;
$$;

CREATE OR REPLACE FUNCTION auth_get_password_reset_by_token(p_hash text)
RETURNS TABLE (id uuid, user_id uuid, token_hash text, expires_at timestamptz,
               used_at timestamptz, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT r.id, r.user_id, r.token_hash, r.expires_at, r.used_at, r.created_at
  FROM password_resets r WHERE r.token_hash = p_hash;
$$;

CREATE OR REPLACE FUNCTION auth_get_session_by_token_hash(p_hash text)
RETURNS TABLE (id uuid, user_id uuid, organization_id uuid,
               refresh_token_hash text, expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT s.id, s.user_id, s.organization_id, s.refresh_token_hash,
         s.expires_at, s.revoked_at
  FROM sessions s WHERE s.refresh_token_hash = p_hash;
$$;
"""

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_user_by_email(text) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_invitation_by_token(text) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_password_reset_by_token(text) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_session_by_token_hash(text) TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    Base.metadata.create_all(bind)

    # Seed the permission catalog.
    for code, module, description in PERMISSIONS:
        bind.execute(
            sa.text(
                "INSERT INTO permissions (id, code, module, description) "
                "VALUES (gen_random_uuid(), :code, :module, :description) "
                "ON CONFLICT (code) DO NOTHING"
            ),
            {"code": code, "module": module, "description": description},
        )

    # Controlled pre-auth lookup functions.
    op.execute(FUNCTIONS_SQL)
    op.execute(GRANT_SQL)

    # Row-Level Security: enabled (not forced) on every tenant table, then
    # policies. Deliberately NOT forced: the table owner (null_owner) must
    # bypass RLS, because the SECURITY DEFINER pre-auth lookup functions
    # are owned by it and must be able to read the exact credential row
    # before any RLS context exists. PostgreSQL refuses to let even an
    # owner-owned SECURITY DEFINER function bypass a FORCED policy
    # ("query would be affected by row-level security policy"), so forcing
    # would make login, password reset, and invitation acceptance
    # impossible. The security boundary is the application role: the app
    # connects as null_app (never as the owner), null_app owns nothing
    # and has no BYPASSRLS, so RLS always applies to it. The owner role
    # is used only for migrations, seeding, and those lookup functions —
    # never by application request handling.
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    for table, name, command, using, check in POLICIES:
        sql = f"CREATE POLICY {name} ON {table} FOR {command}"
        if using:
            sql += f" USING ({using})"
        if check:
            sql += f" WITH CHECK ({check})"
        op.execute(sql)

    # Application-role privileges. The app connects as null_app (never as
    # the owner). Grants are applied here so they cover every table this
    # migration creates, and ALTER DEFAULT PRIVILEGES covers future ones.
    # Skipped when the role does not exist yet (deployment order creates
    # roles before running migrations — see README.md).
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
            EXECUTE 'GRANT USAGE ON SCHEMA public TO null_app';
            EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO null_app';
            EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO null_app';
            EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
                    'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO null_app';
            EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
                    'GRANT USAGE, SELECT ON SEQUENCES TO null_app';
          END IF;
        END $$;
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS auth_get_user_by_email(text)")
    op.execute("DROP FUNCTION IF EXISTS auth_get_invitation_by_token(text)")
    op.execute("DROP FUNCTION IF EXISTS auth_get_password_reset_by_token(text)")
    op.execute("DROP FUNCTION IF EXISTS auth_get_session_by_token_hash(text)")
    Base.metadata.drop_all(bind)
