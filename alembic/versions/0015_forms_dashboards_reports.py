"""Custom forms / dashboards / reports (migration 0015).

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-26

- New tables: custom_forms, custom_fields, field_values,
  dashboards, dashboard_widgets, reports, scheduled_reports.
- Follows the 0012/0013 pattern: tables via
  ``__table__.create(checkfirst=True)``, standard org-scoped RLS
  policies, permission catalog re-seeded idempotently, grants via the
  0001 ALTER DEFAULT PRIVILEGES pattern.
- Widgets store a query definition only — counts are computed from
  live rows at request time, never stored.
- Scheduled reports store a cron expression + recipients; the Celery
  task ``reporting.generate_scheduled_report`` (defined in
  app/services/reporting_service.py) generates the report and records
  the run outcome. The beat schedule is wired by the coordinator at
  integration.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.forms import CustomField, CustomForm, FieldValue
from app.models.reporting import Dashboard, DashboardWidget, Report, ScheduledReport
from app.permissions import PERMISSIONS

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

TABLES = [
    CustomForm,
    CustomField,
    FieldValue,
    Dashboard,
    DashboardWidget,
    Report,
    ScheduledReport,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = [
    ("custom_forms", "custom_forms_all", "ALL", _ORG, _ORG),
    ("custom_fields", "custom_fields_all", "ALL", _ORG, _ORG),
    ("field_values", "field_values_all", "ALL", _ORG, _ORG),
    ("dashboards", "dashboards_all", "ALL", _ORG, _ORG),
    ("dashboard_widgets", "dashboard_widgets_all", "ALL", _ORG, _ORG),
    ("reports", "reports_all", "ALL", _ORG, _ORG),
    ("scheduled_reports", "scheduled_reports_all", "ALL", _ORG, _ORG),
]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'custom_forms, custom_fields, field_values, dashboards, '
            'dashboard_widgets, reports, scheduled_reports TO null_app';
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
        "scheduled_reports",
        "reports",
        "dashboard_widgets",
        "dashboards",
        "field_values",
        "custom_fields",
        "custom_forms",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
