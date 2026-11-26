"""Registration + onboarding + invitations (migration 0013).

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-26

- Registration profile columns on organizations (contact_email,
  website, industry, size) and invitation form fields on invitations
  (full_name, department, team).
- New tables: departments, teams, org_onboarding, platform_invitations,
  dev_email_outbox (append-only telemetry: SELECT + INSERT only).
- SECURITY DEFINER function auth_get_platform_invitation_by_token for
  the public platform-invitation accept lookup (mirrors
  auth_get_invitation_by_token from 0001).

Follows the 0012 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS policies, permission catalog re-seeded
idempotently, grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.
platform_invitations is platform-scoped (RLS gates on the platform user
context, like platform_users in 0002). dev_email_outbox is readable by
the owning org OR by any authenticated platform user (scope='platform'
rows have no org).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.registration import (
    Department,
    DevEmailOutbox,
    OrgOnboarding,
    PlatformInvitation,
    Team,
)
from app.permissions import PERMISSIONS

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

TABLES = [
    Department,
    Team,
    OrgOnboarding,
    PlatformInvitation,
    DevEmailOutbox,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"
_PLATFORM = "current_setting('app.current_platform_user_id', true) <> ''"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = [
    ("departments", "departments_all", "ALL", _ORG, _ORG),
    ("teams", "teams_all", "ALL", _ORG, _ORG),
    ("org_onboarding", "org_onboarding_all", "ALL", _ORG, _ORG),
    ("platform_invitations", "platform_invitations_select", "SELECT", _PLATFORM, None),
    ("platform_invitations", "platform_invitations_insert", "INSERT", None, _PLATFORM),
    ("platform_invitations", "platform_invitations_update", "UPDATE", _PLATFORM, _PLATFORM),
    ("platform_invitations", "platform_invitations_delete", "DELETE", _PLATFORM, None),
    (
        "dev_email_outbox",
        "dev_email_outbox_select",
        "SELECT",
        f"({_ORG} OR (scope = 'platform' AND {_PLATFORM}))",
        None,
    ),
    (
        "dev_email_outbox",
        "dev_email_outbox_insert",
        "INSERT",
        None,
        f"({_ORG} OR (scope = 'platform' AND {_PLATFORM}))",
    ),
]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'departments, teams, org_onboarding, platform_invitations, dev_email_outbox TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT USAGE, SELECT ON SEQUENCES TO null_app';
  END IF;
END $$;
"""

ORG_SLUG_FN_SQL = """
-- Slug uniqueness must be checked without RLS: at registration time the
-- caller belongs to no organization yet, so an ORM organizations SELECT
-- sees nothing and a duplicate slug would surface as a 500
-- UniqueViolation instead of a clean suffix/409. The SECURITY DEFINER
-- function answers the existence question only — it reveals nothing else.
CREATE OR REPLACE FUNCTION org_slug_exists(p_slug text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM organizations WHERE slug = p_slug);
$$;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION org_slug_exists(text) TO null_app';
  END IF;
END $$;
"""

INVITATION_FN_SQL = """
-- The 0001 lookup predates the invitation profile columns; replace it
-- (DROP first: CREATE OR REPLACE cannot change the return type) so the
-- public accept page can show org name/slug, the pre-filled name,
-- department/team, and the assigned role names. accept_invitation only
-- reads id/organization_id/email from it, so the extra columns are safe.
DROP FUNCTION IF EXISTS auth_get_invitation_by_token(text);
CREATE OR REPLACE FUNCTION auth_get_invitation_by_token(p_hash text)
RETURNS TABLE (id uuid, organization_id uuid, organization_name text,
               organization_slug text, email text, full_name text,
               department text, team text, invited_by_id uuid, status text,
               expires_at timestamptz, accepted_at timestamptz,
               created_at timestamptz, roles text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT i.id, i.organization_id, o.name, o.slug, i.email, i.full_name,
         i.department, i.team, i.invited_by_id, i.status, i.expires_at,
         i.accepted_at, i.created_at,
         COALESCE(array_agg(r.name) FILTER (WHERE r.id IS NOT NULL), '{}')
  FROM invitations i
  JOIN organizations o ON o.id = i.organization_id
  LEFT JOIN invitation_roles ir ON ir.invitation_id = i.id
  LEFT JOIN roles r ON r.id = ir.role_id
  WHERE i.token_hash = p_hash
  GROUP BY i.id, o.name, o.slug;
$$;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_invitation_by_token(text) TO null_app';
  END IF;
END $$;
"""

PLATFORM_INVITATION_FN_SQL = """
CREATE OR REPLACE FUNCTION auth_get_platform_invitation_by_token(p_hash text)
RETURNS TABLE (id uuid, email text, full_name text, token_hash text,
               invited_by_id uuid, role_id uuid, status text,
               expires_at timestamptz, accepted_at timestamptz,
               created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT i.id, i.email, i.full_name, i.token_hash, i.invited_by_id,
         i.role_id, i.status, i.expires_at, i.accepted_at, i.created_at
  FROM platform_invitations i WHERE i.token_hash = p_hash;
$$;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_platform_invitation_by_token(text) TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    for model in TABLES:
        model.__table__.create(bind, checkfirst=True)

    # Registration profile columns on organizations.
    op.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS contact_email VARCHAR(320)")
    op.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS website VARCHAR(255)")
    op.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS industry VARCHAR(100)")
    op.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS size VARCHAR(20)")
    # Invitation form fields.
    op.execute("ALTER TABLE invitations ADD COLUMN IF NOT EXISTS full_name VARCHAR(255) NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE invitations ADD COLUMN IF NOT EXISTS department VARCHAR(100) NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE invitations ADD COLUMN IF NOT EXISTS team VARCHAR(100) NOT NULL DEFAULT ''")

    # Re-seed the permission catalog (idempotent — ON CONFLICT DO NOTHING).
    for code, module, description in PERMISSIONS:
        bind.execute(
            sa.text(
                "INSERT INTO permissions (id, code, module, description) "
                "VALUES (gen_random_uuid(), :code, :module, :description) "
                "ON CONFLICT (code) DO NOTHING"
            ),
            {"code": code, "module": module, "description": description},
        )

    op.execute(GRANT_SQL)
    op.execute(ORG_SLUG_FN_SQL)
    op.execute(INVITATION_FN_SQL)
    op.execute(PLATFORM_INVITATION_FN_SQL)

    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    for table, name, command, using, check in POLICIES:
        sql = f"CREATE POLICY {name} ON {table} FOR {command}"
        if using:
            sql += f" USING ({using})"
        if check:
            sql += f" WITH CHECK ({check})"
        op.execute(sql)


def downgrade() -> None:
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS auth_get_platform_invitation_by_token(text)")
    op.execute("DROP FUNCTION IF EXISTS org_slug_exists(text)")
    # Restore the 0001 invitation lookup (the 0013 version adds columns
    # for the public accept page; the 0001 shape is the downgrade target).
    op.execute("DROP FUNCTION IF EXISTS auth_get_invitation_by_token(text)")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth_get_invitation_by_token(p_hash text)
        RETURNS TABLE (id uuid, organization_id uuid, email text, token_hash text,
                       invited_by_id uuid, status text, expires_at timestamptz,
                       accepted_at timestamptz, created_at timestamptz)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
          SELECT i.id, i.organization_id, i.email, i.token_hash, i.invited_by_id,
                 i.status, i.expires_at, i.accepted_at, i.created_at
          FROM invitations i WHERE i.token_hash = p_hash;
        $$;
        """
    )
    for table in (
        "dev_email_outbox",
        "platform_invitations",
        "org_onboarding",
        "teams",
        "departments",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS contact_email")
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS website")
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS industry")
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS size")
    op.execute("ALTER TABLE invitations DROP COLUMN IF EXISTS full_name")
    op.execute("ALTER TABLE invitations DROP COLUMN IF EXISTS department")
    op.execute("ALTER TABLE invitations DROP COLUMN IF EXISTS team")
