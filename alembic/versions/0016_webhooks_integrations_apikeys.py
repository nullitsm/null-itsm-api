"""Webhooks, integrations framework, and API keys (migration 0016).

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-26

- New tables: webhooks, webhook_deliveries (append-only: SELECT + INSERT
  only), integrations, integration_credentials, api_keys.
- SECURITY DEFINER function auth_get_api_key_by_token-hash
  (``auth_get_api_key_by_hash`` — the only way to resolve an API key
  before an RLS context exists, mirroring auth_get_scim_token_by_hash
  from 0007).

Follows the 0013 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS policies, permission catalog re-seeded
idempotently, grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.integrations import (
    ApiKey,
    Integration,
    IntegrationCredential,
    Webhook,
    WebhookDelivery,
)
from app.permissions import PERMISSIONS

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

TABLES = [
    Webhook,
    WebhookDelivery,
    Integration,
    IntegrationCredential,
    ApiKey,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = [
    ("webhooks", "webhooks_all", "ALL", _ORG, _ORG),
    ("webhook_deliveries", "webhook_deliveries_select", "SELECT", _ORG, None),
    ("webhook_deliveries", "webhook_deliveries_insert", "INSERT", None, _ORG),
    ("integrations", "integrations_all", "ALL", _ORG, _ORG),
    ("integration_credentials", "integration_credentials_all", "ALL", _ORG, _ORG),
    ("api_keys", "api_keys_all", "ALL", _ORG, _ORG),
]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'webhooks, webhook_deliveries, integrations, integration_credentials, api_keys TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT USAGE, SELECT ON SEQUENCES TO null_app';
  END IF;
END $$;
"""

API_KEY_FN_SQL = """
-- auth_get_api_key_by_hash serves API-key authentication: the raw key's
-- SHA-256 hash is the only identifier the caller presents, so the key row
-- must be resolvable before any session exists. It returns the row's
-- metadata (org, name, scopes, expiry, revocation, last use) — never a
-- secret: only the hash is stored, and the hash itself is not returned.
CREATE OR REPLACE FUNCTION auth_get_api_key_by_hash(p_hash text)
RETURNS TABLE (id uuid, organization_id uuid, name text,
               scopes jsonb, expires_at timestamptz, revoked_at timestamptz,
               last_used_at timestamptz, created_by_id uuid,
               created_at timestamptz, updated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT k.id, k.organization_id, k.name, k.scopes,
         k.expires_at, k.revoked_at, k.last_used_at, k.created_by_id,
         k.created_at, k.updated_at
  FROM api_keys k WHERE k.key_hash = p_hash;
$$;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_api_key_by_hash(text) TO null_app';
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

    op.execute(GRANT_SQL)
    op.execute(API_KEY_FN_SQL)

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
    op.execute("DROP FUNCTION IF EXISTS auth_get_api_key_by_hash(text)")
    for table in (
        "api_keys",
        "integration_credentials",
        "integrations",
        "webhook_deliveries",
        "webhooks",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
