"""CMDB + network operations tables (migration 0012).

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-26

Creates the Phase 3 CMDB + network tables (configuration_items,
ci_relationships, network_devices, network_interfaces, topology_links,
service_dependencies, network_metrics, network_events, certificates).

Follows the 0007 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS policies (``network_metrics`` is append-only
telemetry: SELECT + INSERT only), the permission catalog re-seeded
idempotently, and grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.

On-call schedules/rotations are NOT in this migration — they were listed
under Phase 3 in the data model but are out of the Phase 3 brief scope
(Tier 2, deferred).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.cmdb_network import (
    Certificate,
    CiRelationship,
    ConfigurationItem,
    NetworkDevice,
    NetworkEvent,
    NetworkInterface,
    NetworkMetric,
    ServiceDependency,
    TopologyLink,
)
from app.permissions import PERMISSIONS

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

TABLES = [
    ConfigurationItem,
    CiRelationship,
    NetworkDevice,
    NetworkInterface,
    TopologyLink,
    ServiceDependency,
    NetworkMetric,
    NetworkEvent,
    Certificate,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = []
for _model in TABLES:
    _table = _model.__tablename__
    if _table == "network_metrics":
        # Append-only telemetry: SELECT + INSERT, no UPDATE/DELETE policy.
        POLICIES.append((_table, "network_metrics_select", "SELECT", _ORG, None))
        POLICIES.append((_table, "network_metrics_insert", "INSERT", None, _ORG))
    else:
        POLICIES.append((_table, f"{_table}_all", "ALL", _ORG, _ORG))

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'configuration_items, ci_relationships, network_devices, network_interfaces, topology_links, '
            'service_dependencies, network_metrics, network_events, certificates TO null_app';
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
    # Drop in dependency order (children first).
    for table in (
        "network_metrics",
        "network_events",
        "topology_links",
        "network_interfaces",
        "service_dependencies",
        "ci_relationships",
        "certificates",
        "network_devices",
        "configuration_items",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
