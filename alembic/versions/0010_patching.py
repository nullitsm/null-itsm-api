"""Patching tables (migration 0010).

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-26

Creates the Phase 3 patching tables (patches, patch_scans,
patch_findings, patch_deployments, patch_deployment_items).

Follows the 0007 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS policies (ALL), the permission catalog re-seeded
idempotently, and grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.

One open ``patch_findings`` row per (endpoint, patch) is enforced by a
partial unique index (``status = 'missing'``): installing the patch flips
the row to ``installed``; a later scan that still finds it missing
re-opens it.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.patching import (
    Patch,
    PatchDeployment,
    PatchDeploymentItem,
    PatchFinding,
    PatchScan,
)
from app.permissions import PERMISSIONS

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

TABLES = [
    Patch,
    PatchScan,
    PatchFinding,
    PatchDeployment,
    PatchDeploymentItem,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = []
for _model in TABLES:
    _table = _model.__tablename__
    POLICIES.append((_table, f"{_table}_all", "ALL", _ORG, _ORG))

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'patches, patch_scans, patch_findings, patch_deployments, patch_deployment_items TO null_app';
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

    # One open (missing) finding per (org, endpoint, patch).
    op.create_index(
        "uq_patch_finding_open",
        "patch_findings",
        ["organization_id", "endpoint_id", "patch_id"],
        unique=True,
        postgresql_where=sa.text("status = 'missing'"),
    )

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
    op.execute("DROP INDEX IF EXISTS uq_patch_finding_open")
    # Drop in dependency order (children first).
    for table in (
        "patch_deployment_items",
        "patch_findings",
        "patch_deployments",
        "patch_scans",
        "patches",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
