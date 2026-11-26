"""Agent + endpoint tables (migration 0009).

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-26

Creates the Phase 3 agent/endpoint tables (enrollment_tokens, endpoints,
endpoint_inventory, agent_jobs, agent_releases).

Follows the 0007 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS policies (``endpoint_inventory`` is append-only:
SELECT + INSERT only, like the audit log), the permission catalog
re-seeded idempotently, two SECURITY DEFINER lookup functions
(``auth_get_enrollment_token_by_hash`` and
``auth_get_endpoint_by_device_token`` — the only way to resolve agent
credentials before an RLS context exists), and grants via the 0001 ALTER
DEFAULT PRIVILEGES pattern.

``agent_releases`` is a global release catalog (no tenant data), so it
carries no ``organization_id`` and no RLS policy — documented in
``app/models/endpoints.py``.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.endpoints import (
    AgentJob,
    AgentRelease,
    Endpoint,
    EndpointInventory,
    EnrollmentToken,
)
from app.permissions import PERMISSIONS

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

TABLES = [
    Endpoint,
    EnrollmentToken,
    EndpointInventory,
    AgentJob,
    AgentRelease,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = []
for _model in TABLES:
    _table = _model.__tablename__
    if _table == "agent_releases":
        # Global catalog — no tenant data, no RLS.
        continue
    if _table == "endpoint_inventory":
        # Append-only: SELECT + INSERT, no UPDATE/DELETE policy.
        POLICIES.append((_table, "endpoint_inventory_select", "SELECT", _ORG, None))
        POLICIES.append((_table, "endpoint_inventory_insert", "INSERT", None, _ORG))
    else:
        POLICIES.append((_table, f"{_table}_all", "ALL", _ORG, _ORG))

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

FUNCTIONS_SQL = """
-- Controlled bypass surface for agent authentication. Same pattern as the
-- org auth functions in 0001 and the SCIM functions in 0007: SECURITY
-- DEFINER, owner-owned, locked search_path, exact-credential lookup only.
-- An agent request arrives with X-Device-Id / X-Device-Token (or an
-- enrollment token) and no JWT and no RLS context, so the credential row
-- must be resolved before any tenant context exists; these functions
-- return at most the one row whose hash matches exactly. They never
-- enumerate.
CREATE OR REPLACE FUNCTION auth_get_enrollment_token_by_hash(p_hash text)
RETURNS TABLE (id uuid, organization_id uuid, token_hash text,
               created_by_id uuid, expires_at timestamptz,
               used_at timestamptz, used_endpoint_id uuid,
               revoked_at timestamptz, created_at timestamptz,
               updated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT t.id, t.organization_id, t.token_hash, t.created_by_id,
         t.expires_at, t.used_at, t.used_endpoint_id, t.revoked_at,
         t.created_at, t.updated_at
  FROM enrollment_tokens t WHERE t.token_hash = p_hash;
$$;

CREATE OR REPLACE FUNCTION auth_get_endpoint_by_device_token(p_device_id uuid, p_token_hash text)
RETURNS TABLE (id uuid, organization_id uuid, hostname text,
               status text, device_token_hash text,
               token_revoked_at timestamptz, last_seen_at timestamptz,
               agent_version text, ip_address text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT e.id, e.organization_id, e.hostname, e.status,
         e.device_token_hash, e.token_revoked_at, e.last_seen_at,
         e.agent_version, e.ip_address
  FROM endpoints e WHERE e.id = p_device_id AND e.device_token_hash = p_token_hash;
$$;
"""

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_enrollment_token_by_hash(text) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_endpoint_by_device_token(uuid, text) TO null_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'enrollment_tokens, endpoints, endpoint_inventory, agent_jobs, agent_releases TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT USAGE, SELECT ON SEQUENCES TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    for model in TABLES:
        model.__table__.create(bind, checkfirst=True)

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

    op.execute(FUNCTIONS_SQL)
    op.execute(GRANT_SQL)

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
    op.execute("DROP FUNCTION IF EXISTS auth_get_enrollment_token_by_hash(text)")
    op.execute("DROP FUNCTION IF EXISTS auth_get_endpoint_by_device_token(uuid, text)")
    # Drop in dependency order (children first).
    for table in (
        "agent_jobs",
        "endpoint_inventory",
        "enrollment_tokens",
        "agent_releases",
        "endpoints",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
