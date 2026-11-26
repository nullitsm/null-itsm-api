"""SLA engine: business hours, policies, breaches, escalation rules.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-25

Creates the Phase 2 SLA tables (business_hours, sla_policies,
sla_breaches, escalation_rules, escalation_events), enables RLS on them
with the standard org-scoped ALL policy, and adds the SLA state columns
to the pre-existing ``tickets`` table.

Migration strategy notes:
- Tables are created with ``checkfirst=True`` (0002 pattern).
- The ticket columns use ``ADD COLUMN IF NOT EXISTS``: on a fresh
  install migration 0001's ``Base.metadata.create_all`` already creates
  them (the ORM model maps them), so a plain add_column would fail with
  a DuplicateColumn there (same hazard 0003 documents).
- ``tickets.sla_policy_id`` is a plain UUID column with NO foreign key
  (per the Phase 2 spec): the policies table is created in this same
  migration and the column is added to a pre-existing table; existence
  is validated in the SLA service, not by the database.
- The permission catalog is re-seeded idempotently (``ON CONFLICT (code)
  DO NOTHING``, mirror of 0001) so ``sla:read`` / ``sla:manage`` exist
  even if this migration runs before any other seeding pass.
- downgrade() drops the five tables and the six added ticket columns.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.sla import (
    BusinessHours,
    EscalationEvent,
    EscalationRule,
    SlaBreach,
    SlaPolicy,
)
from app.permissions import PERMISSIONS

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

SLA_TABLES = [
    BusinessHours,
    SlaPolicy,
    SlaBreach,
    EscalationRule,
    EscalationEvent,
]

_ORG_EXPR = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr) — standard
# org-scoped ALL policy, one per table.
POLICIES = [(table.__tablename__, f"{table.__tablename__}_all", "ALL", _ORG_EXPR, _ORG_EXPR) for table in SLA_TABLES]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

TICKET_SLA_COLUMNS = [
    ("first_response_due_at", "TIMESTAMPTZ"),
    ("resolution_due_at", "TIMESTAMPTZ"),
    ("first_response_at", "TIMESTAMPTZ"),
    ("resolved_at", "TIMESTAMPTZ"),
    ("sla_policy_id", "UUID"),
    ("sla_breached", "BOOLEAN NOT NULL DEFAULT false"),
]

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'business_hours, sla_policies, sla_breaches, '
            'escalation_rules, escalation_events TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    for model in SLA_TABLES:
        model.__table__.create(bind, checkfirst=True)

    for column, coltype in TICKET_SLA_COLUMNS:
        op.execute(f"ALTER TABLE tickets ADD COLUMN IF NOT EXISTS {column} {coltype}")

    # Re-seed the permission catalog idempotently (mirror of 0001).
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
        "escalation_events",
        "sla_breaches",
        "escalation_rules",
        "sla_policies",
        "business_hours",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    for column, _coltype in TICKET_SLA_COLUMNS:
        op.execute(f"ALTER TABLE tickets DROP COLUMN IF EXISTS {column}")
