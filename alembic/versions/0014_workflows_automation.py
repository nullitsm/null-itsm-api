"""Workflow designer + automation rules (migration 0014).

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-26

- New tables: workflows, workflow_versions, workflow_runs,
  workflow_run_steps, automation_rules, automation_runs.
- Follows the 0013 pattern: tables via ``__table__.create(checkfirst=True)``,
  standard org-scoped RLS ALL policies on every org table, permission
  catalog re-seeded idempotently, grants via the 0001 ALTER DEFAULT
  PRIVILEGES pattern.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.workflows import (
    AutomationRule,
    AutomationRun,
    Workflow,
    WorkflowRun,
    WorkflowRunStep,
    WorkflowVersion,
)
from app.permissions import PERMISSIONS

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

TABLES = [
    Workflow,
    WorkflowVersion,
    WorkflowRun,
    WorkflowRunStep,
    AutomationRule,
    AutomationRun,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = [
    ("workflows", "workflows_all", "ALL", _ORG, _ORG),
    ("workflow_versions", "workflow_versions_all", "ALL", _ORG, _ORG),
    ("workflow_runs", "workflow_runs_all", "ALL", _ORG, _ORG),
    ("workflow_run_steps", "workflow_run_steps_all", "ALL", _ORG, _ORG),
    ("automation_rules", "automation_rules_all", "ALL", _ORG, _ORG),
    ("automation_runs", "automation_runs_all", "ALL", _ORG, _ORG),
]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'workflows, workflow_versions, workflow_runs, workflow_run_steps, '
            'automation_rules, automation_runs TO null_app';
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
    for table in (
        "automation_runs",
        "automation_rules",
        "workflow_run_steps",
        "workflow_runs",
        "workflow_versions",
        "workflows",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
