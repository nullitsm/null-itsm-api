"""Identity / directory + asset-lifecycle tables (migration 0007).

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-25

Creates the Phase 2 identity/directory tables (identity_providers,
scim_tokens, directory_sync_runs, directory_groups,
directory_group_memberships, service_accounts, api_credentials,
access_certifications, certification_items, temporary_access_grants)
and the asset-lifecycle tables (vendors, purchase_orders, warranties,
assets, asset_lifecycle_events, asset_assignments, licenses,
license_assignments).

Follows the 0002 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS policies (``asset_lifecycle_events`` is
append-only: SELECT + INSERT only, like the audit log), the permission
catalog re-seeded idempotently, one SECURITY DEFINER lookup function
(``auth_get_scim_token_by_hash`` — the only way to resolve a SCIM bearer
token before an RLS context exists) plus ``auth_get_identity_provider_by_id``
(the unauthenticated SAML ACS endpoint's controlled provider lookup),
and grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.identity_assets import (
    AccessCertification,
    ApiCredential,
    Asset,
    AssetAssignment,
    AssetLifecycleEvent,
    CertificationItem,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectorySyncRun,
    IdentityProvider,
    License,
    LicenseAssignment,
    PurchaseOrder,
    ScimToken,
    ServiceAccount,
    TemporaryAccessGrant,
    Vendor,
    Warranty,
)
from app.permissions import PERMISSIONS

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

TABLES = [
    IdentityProvider,
    ScimToken,
    DirectorySyncRun,
    DirectoryGroup,
    DirectoryGroupMembership,
    ServiceAccount,
    ApiCredential,
    AccessCertification,
    CertificationItem,
    TemporaryAccessGrant,
    Vendor,
    PurchaseOrder,
    Asset,
    Warranty,
    AssetLifecycleEvent,
    AssetAssignment,
    License,
    LicenseAssignment,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = []
for _model in TABLES:
    _table = _model.__tablename__
    if _table == "asset_lifecycle_events":
        # Append-only: SELECT + INSERT, no UPDATE/DELETE policy.
        POLICIES.append((_table, "asset_lifecycle_events_select", "SELECT", _ORG, None))
        POLICIES.append((_table, "asset_lifecycle_events_insert", "INSERT", None, _ORG))
    else:
        POLICIES.append((_table, f"{_table}_all", "ALL", _ORG, _ORG))

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

FUNCTIONS_SQL = """
-- Controlled bypass surface for SCIM authentication. Same pattern as the
-- org auth functions in 0001: SECURITY DEFINER, owner-owned, locked
-- search_path, exact-credential lookup only. A SCIM bearer token arrives
-- with no JWT and no RLS context, so the token row must be resolved
-- before any tenant context exists; this function returns at most the
-- one row whose SHA-256 hash matches exactly. It never enumerates.
--
-- auth_get_identity_provider_by_id serves the unauthenticated SAML ACS
-- endpoint: the provider id in the ACS URL is the only identifier the
-- IdP posts, so the provider row (entity id, SSO URL, certificate) must
-- be resolvable before any session exists. It returns the provider's
-- public SAML configuration only — never secrets.
CREATE OR REPLACE FUNCTION auth_get_scim_token_by_hash(p_hash text)
RETURNS TABLE (id uuid, organization_id uuid, name text, token_hash text,
               scopes jsonb, expires_at timestamptz, revoked_at timestamptz,
               last_used_at timestamptz, created_by_id uuid,
               created_at timestamptz, updated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT t.id, t.organization_id, t.name, t.token_hash, t.scopes,
         t.expires_at, t.revoked_at, t.last_used_at, t.created_by_id,
         t.created_at, t.updated_at
  FROM scim_tokens t WHERE t.token_hash = p_hash;
$$;

CREATE OR REPLACE FUNCTION auth_get_identity_provider_by_id(p_id uuid)
RETURNS TABLE (id uuid, organization_id uuid, name text, type text,
               status text, saml_entity_id text, saml_sso_url text,
               saml_certificate text, oidc_issuer text, oidc_client_id text,
               is_default boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT p.id, p.organization_id, p.name, p.type, p.status,
         p.saml_entity_id, p.saml_sso_url, p.saml_certificate,
         p.oidc_issuer, p.oidc_client_id, p.is_default
  FROM identity_providers p WHERE p.id = p_id;
$$;

-- SCIM directory reads. The org users SELECT policy only exposes users
-- with an ACTIVE membership, but SCIM provisioning creates memberships
-- with status "invited" — and a SCIM client that just provisioned a user
-- must be able to read it back. These functions return org members of
-- ANY membership status, but only for the organization id supplied by
-- the server (taken from the validated SCIM token, never from the
-- client), so a token from org A can never list org B's users.
CREATE OR REPLACE FUNCTION scim_list_org_users(p_org_id uuid)
RETURNS TABLE (id uuid, email text, full_name text, is_active boolean,
               membership_status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.email, u.full_name, u.is_active, m.status
  FROM users u JOIN memberships m ON m.user_id = u.id AND m.organization_id = p_org_id
  ORDER BY u.email;
$$;

CREATE OR REPLACE FUNCTION scim_get_org_user(p_org_id uuid, p_user_id uuid)
RETURNS TABLE (id uuid, email text, full_name text, is_active boolean,
               membership_status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.email, u.full_name, u.is_active, m.status
  FROM users u JOIN memberships m ON m.user_id = u.id AND m.organization_id = p_org_id
  WHERE u.id = p_user_id;
$$;
"""

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_scim_token_by_hash(text) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION auth_get_identity_provider_by_id(uuid) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION scim_list_org_users(uuid) TO null_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION scim_get_org_user(uuid, uuid) TO null_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'identity_providers, scim_tokens, directory_sync_runs, directory_groups, '
            'directory_group_memberships, service_accounts, api_credentials, '
            'access_certifications, certification_items, temporary_access_grants, '
            'vendors, purchase_orders, warranties, assets, asset_lifecycle_events, '
            'asset_assignments, licenses, license_assignments TO null_app';
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
    # This covers identity:read/manage, assets:read/manage, licenses and
    # vendors codes if no earlier migration seeded them.
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
    op.execute("DROP FUNCTION IF EXISTS auth_get_scim_token_by_hash(text)")
    op.execute("DROP FUNCTION IF EXISTS auth_get_identity_provider_by_id(uuid)")
    op.execute("DROP FUNCTION IF EXISTS scim_list_org_users(uuid)")
    op.execute("DROP FUNCTION IF EXISTS scim_get_org_user(uuid, uuid)")
    # Drop in dependency order (children first).
    for table in (
        "license_assignments",
        "licenses",
        "asset_assignments",
        "asset_lifecycle_events",
        "warranties",
        "assets",
        "purchase_orders",
        "vendors",
        "temporary_access_grants",
        "certification_items",
        "access_certifications",
        "api_credentials",
        "service_accounts",
        "directory_group_memberships",
        "directory_groups",
        "directory_sync_runs",
        "scim_tokens",
        "identity_providers",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
