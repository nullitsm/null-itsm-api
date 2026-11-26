"""Two-domain separation: platform administration domain (migration 0002).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-25

Creates the platform administration domain — a separate identity and
authorization boundary from the organization domain:
- platform_users / platform_sessions (own identities + refresh sessions)
- platform_permissions / platform_roles / platform_role_permissions /
  platform_user_roles (separate ``platform:*`` permission namespace)
- platform_access_grants (explicit, time-boxed cross-tenant support access)
- platform_audit_logs (append-only, like the org audit log)

Also removes the four ``platform:*`` codes from the ORGANIZATION
permission catalog (``permissions``). From this migration on, no
organization role can hold a platform permission: the org catalog
contains no such code, and the org role editor rejects ``platform:``-
prefixed codes explicitly. Existing organization users, roles, and
audit history are untouched — no existing user is converted into a
platform administrator, and no elevated permission is silently granted.

Migration strategy notes (per the Nov 25, 2026 spec):
- Platform tables are created with ``checkfirst=True``: on a fresh
  install migration 0001's ``Base.metadata.create_all`` already created
  them (the models are registered), so 0002 only adds the seeds,
  functions, RLS, and grants. On an existing DB, 0002 creates them.
- Platform roles/permissions are seeded here (production) AND by
  ``seed_platform_roles`` (idempotent, dev safety net).
- RLS on platform tables gates on ``app.current_platform_user_id``
  (set by ``set_rls_context``); org tables stay invisible to a platform
  session (no org context), so tenant reads go only through the
  grant-checked SECURITY DEFINER function below.
- downgrade() drops the platform tables and restores the four org
  ``platform:*`` catalog rows, so rollback is possible.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.platform_admin import (
    PlatformAccessGrant,
    PlatformAuditLog,
    PlatformPermission,
    PlatformRole,
    PlatformRolePermission,
    PlatformSession,
    PlatformUser,
    PlatformUserRole,
)
from app.permissions import PLATFORM_PERMISSIONS, PLATFORM_ROLE_TEMPLATES, resolve_template_permissions

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

# The four org-catalog codes removed by this migration (restored on downgrade).
REMOVED_ORG_PLATFORM_CODES = [
    ("platform:tenants", "platform", "Manage customer organizations"),
    ("platform:health", "platform", "View tenant health and platform status"),
    ("platform:support", "platform", "Use platform support tools"),
    ("platform:audit", "platform", "Read platform audit logs"),
]

PLATFORM_TABLES = [
    PlatformUser,
    PlatformPermission,
    PlatformRole,
    PlatformRolePermission,
    PlatformUserRole,
    PlatformSession,
    PlatformAccessGrant,
    PlatformAuditLog,
]

# (table, policy_name, command, using_expr, check_expr)
# Platform RLS gates on the platform identity only: any authenticated
# platform user can read the platform directory; granular permission
# checks (who may manage roles, read audit, approve grants) are enforced
# by the API layer (get_platform_principal). Org tables are NOT visible
# to a platform session at all — no org context is ever set for one.
_PLATFORM_ID = "current_setting('app.current_platform_user_id', true) <> ''"
PLATFORM_POLICIES = [
    ("platform_users", "platform_users_select", "SELECT", _PLATFORM_ID, None),
    ("platform_users", "platform_users_insert", "INSERT", None, _PLATFORM_ID),
    ("platform_users", "platform_users_update", "UPDATE", _PLATFORM_ID, _PLATFORM_ID),
    ("platform_users", "platform_users_delete", "DELETE", _PLATFORM_ID, None),
    ("platform_permissions", "platform_permissions_select", "SELECT", _PLATFORM_ID, None),
    ("platform_roles", "platform_roles_select", "SELECT", _PLATFORM_ID, None),
    ("platform_roles", "platform_roles_insert", "INSERT", None, _PLATFORM_ID),
    ("platform_roles", "platform_roles_update", "UPDATE", _PLATFORM_ID, _PLATFORM_ID),
    ("platform_roles", "platform_roles_delete", "DELETE", _PLATFORM_ID, None),
    ("platform_role_permissions", "platform_role_permissions_select", "SELECT", _PLATFORM_ID, None),
    ("platform_role_permissions", "platform_role_permissions_insert", "INSERT", None, _PLATFORM_ID),
    ("platform_role_permissions", "platform_role_permissions_delete", "DELETE", _PLATFORM_ID, None),
    ("platform_user_roles", "platform_user_roles_select", "SELECT", _PLATFORM_ID, None),
    ("platform_user_roles", "platform_user_roles_insert", "INSERT", None, _PLATFORM_ID),
    ("platform_user_roles", "platform_user_roles_delete", "DELETE", _PLATFORM_ID, None),
    ("platform_sessions", "platform_sessions_select", "SELECT", _PLATFORM_ID, None),
    ("platform_sessions", "platform_sessions_insert", "INSERT", None, _PLATFORM_ID),
    ("platform_sessions", "platform_sessions_update", "UPDATE", _PLATFORM_ID, _PLATFORM_ID),
    ("platform_access_grants", "platform_access_grants_select", "SELECT", _PLATFORM_ID, None),
    ("platform_access_grants", "platform_access_grants_insert", "INSERT", None, _PLATFORM_ID),
    ("platform_access_grants", "platform_access_grants_update", "UPDATE", _PLATFORM_ID, _PLATFORM_ID),
    # platform_audit_logs: append-only — SELECT and INSERT only, no
    # UPDATE/DELETE policy (same rule as the org audit log).
    ("platform_audit_logs", "platform_audit_logs_select", "SELECT", _PLATFORM_ID, None),
    ("platform_audit_logs", "platform_audit_logs_insert", "INSERT", None, _PLATFORM_ID),
]

PLATFORM_RLS_TABLES = sorted({table for table, _, _, _, _ in PLATFORM_POLICIES})

PLATFORM_FUNCTIONS_SQL = """
-- Controlled bypass surface for the platform domain. Same pattern as the
-- org auth functions in 0001: SECURITY DEFINER, owner-owned, locked
-- search_path, exact-credential lookups only. The tenant-read functions
-- are the ONLY way a platform session reads organization data: the org
-- tables' RLS policies never pass for a platform identity (no org
-- membership), so a platform admin cannot read tenant rows through the
-- ORM at all. platform_support_list_org_users additionally enforces the
-- grant in the database itself: it returns rows only when an active,
-- unexpired grant exists for that platform user and organization.
CREATE OR REPLACE FUNCTION platform_get_user_by_email(p_email text)
RETURNS TABLE (id uuid, email text, password_hash text, full_name text,
               is_active boolean, mfa_enabled boolean, mfa_secret text,
               source text, review_status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.email, u.password_hash, u.full_name, u.is_active,
         u.mfa_enabled, u.mfa_secret, u.source, u.review_status
  FROM platform_users u WHERE u.email = p_email;
$$;

CREATE OR REPLACE FUNCTION platform_get_session_by_token_hash(p_hash text)
RETURNS TABLE (id uuid, platform_user_id uuid,
               refresh_token_hash text, expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT s.id, s.platform_user_id, s.refresh_token_hash,
         s.expires_at, s.revoked_at
  FROM platform_sessions s WHERE s.refresh_token_hash = p_hash;
$$;

CREATE OR REPLACE FUNCTION platform_list_organizations()
RETURNS TABLE (id uuid, name text, slug text, is_active boolean,
               is_dev_fixture boolean, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT o.id, o.name, o.slug, o.is_active, o.is_dev_fixture, o.created_at
  FROM organizations o ORDER BY o.created_at;
$$;

CREATE OR REPLACE FUNCTION platform_get_organization(p_id uuid)
RETURNS TABLE (id uuid, name text, slug text, is_active boolean,
               is_dev_fixture boolean, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT o.id, o.name, o.slug, o.is_active, o.is_dev_fixture, o.created_at
  FROM organizations o WHERE o.id = p_id;
$$;

CREATE OR REPLACE FUNCTION platform_support_list_org_users(p_org_id uuid, p_platform_user_id uuid)
RETURNS TABLE (id uuid, email text, full_name text, is_active boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.email, u.full_name, u.is_active
  FROM users u
  JOIN memberships m ON m.user_id = u.id AND m.organization_id = p_org_id AND m.status = 'active'
  WHERE EXISTS (
    SELECT 1 FROM platform_access_grants g
    WHERE g.platform_user_id = p_platform_user_id
      AND g.organization_id = p_org_id
      AND g.status = 'active'
      AND g.expires_at > now()
  );
$$;
"""

PLATFORM_GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION platform_get_user_by_email(text) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION platform_get_session_by_token_hash(text) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION platform_list_organizations() TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION platform_get_organization(uuid) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION platform_support_list_org_users(uuid, uuid) TO null_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'platform_users, platform_permissions, platform_roles, '
            'platform_role_permissions, platform_user_roles, platform_sessions, '
            'platform_access_grants, platform_audit_logs TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    # Tables (no-op on a fresh install where 0001's create_all made them).
    for model in PLATFORM_TABLES:
        model.__table__.create(bind, checkfirst=True)

    # Seed the platform permission catalog.
    for code, module, description in PLATFORM_PERMISSIONS:
        bind.execute(
            sa.text(
                "INSERT INTO platform_permissions (id, code, module, description) "
                "VALUES (gen_random_uuid(), :code, :module, :description) "
                "ON CONFLICT (code) DO NOTHING"
            ),
            {"code": code, "module": module, "description": description},
        )

    # Seed the six platform role templates.
    perm_rows = bind.execute(sa.text("SELECT id, code FROM platform_permissions")).fetchall()
    perm_by_code = {code: pid for pid, code in perm_rows}
    for name, template in PLATFORM_ROLE_TEMPLATES.items():
        role_id = bind.execute(
            sa.text(
                "INSERT INTO platform_roles (id, name, description, access_level, is_system) "
                "VALUES (gen_random_uuid(), :name, :description, :access_level, true) "
                "ON CONFLICT (name) DO NOTHING RETURNING id"
            ),
            {"name": name, "description": template["description"], "access_level": template["access_level"]},
        ).scalar()
        if role_id is None:
            role_id = bind.execute(sa.text("SELECT id FROM platform_roles WHERE name = :name"), {"name": name}).scalar()
        for code in resolve_template_permissions(template, catalog=PLATFORM_PERMISSIONS):
            perm_id = perm_by_code.get(code)
            if perm_id is not None:
                bind.execute(
                    sa.text(
                        "INSERT INTO platform_role_permissions (id, role_id, permission_id) "
                        "VALUES (gen_random_uuid(), :role_id, :perm_id) "
                        "ON CONFLICT (role_id, permission_id) DO NOTHING"
                    ),
                    {"role_id": role_id, "perm_id": perm_id},
                )

    # Remove the platform:* codes from the ORGANIZATION permission
    # catalog. Role-permission rows referencing them are cleared by the
    # FK CASCADE, so no org role keeps a platform permission.
    bind.execute(sa.text("DELETE FROM permissions WHERE code LIKE 'platform:%'"))

    op.execute(PLATFORM_FUNCTIONS_SQL)
    op.execute(PLATFORM_GRANT_SQL)

    for table in PLATFORM_RLS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    for table, name, command, using, check in PLATFORM_POLICIES:
        sql = f"CREATE POLICY {name} ON {table} FOR {command}"
        if using:
            sql += f" USING ({using})"
        if check:
            sql += f" WITH CHECK ({check})"
        op.execute(sql)


def downgrade() -> None:
    bind = op.get_bind()
    for table in PLATFORM_RLS_TABLES:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS platform_get_user_by_email(text)")
    op.execute("DROP FUNCTION IF EXISTS platform_get_session_by_token_hash(text)")
    op.execute("DROP FUNCTION IF EXISTS platform_list_organizations()")
    op.execute("DROP FUNCTION IF EXISTS platform_get_organization(uuid)")
    op.execute("DROP FUNCTION IF EXISTS platform_support_list_org_users(uuid, uuid)")
    # Drop in dependency order (children first).
    for table in (
        "platform_user_roles",
        "platform_role_permissions",
        "platform_sessions",
        "platform_access_grants",
        "platform_audit_logs",
        "platform_roles",
        "platform_permissions",
        "platform_users",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    # Restore the org-catalog platform:* rows removed in upgrade().
    for code, module, description in REMOVED_ORG_PLATFORM_CODES:
        bind.execute(
            sa.text(
                "INSERT INTO permissions (id, code, module, description) "
                "VALUES (gen_random_uuid(), :code, :module, :description) "
                "ON CONFLICT (code) DO NOTHING"
            ),
            {"code": code, "module": module, "description": description},
        )
