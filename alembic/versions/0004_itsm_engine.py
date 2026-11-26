"""Phase 2 ITSM engine (migration 0004).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-25

Creates the ITSM engine tables: service requests (+ counters), service
catalog (categories + items), knowledge base (articles + feedback),
changes (+ approvals, tasks, counters), problems (+ known errors,
counters), notifications, ticket comments / attachments / links,
ticket templates + recurring tickets, major incidents, surveys (+
responses).

Migration strategy notes (0002 pattern):
- Tables are created with ``checkfirst=True`` via ``Base.metadata.
  create_all(tables=[...])``: ``create_all`` (unlike per-model
  ``__table__.create``) resolves the circular foreign keys between
  ``problems.known_error_id`` and ``known_errors.problem_id`` by
  deferring one of them to an ALTER TABLE after both tables exist.
- RLS: the standard org-scoped ALL policy on every tenant table,
  except the audit-style tables (``knowledge_feedback``,
  ``survey_responses``) which get SELECT + INSERT only — same rule as
  the audit log — and the counters, which follow the ``ticket_counters``
  pattern in 0001 (SELECT / INSERT / UPDATE, no DELETE).
- The permission catalog is re-seeded idempotently (``ON CONFLICT
  (code) DO NOTHING``, mirror of 0001) so the Phase 2 codes exist even
  if this migration runs before any other seeding pass.
- downgrade() drops the tables (CASCADE) and disables RLS.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.base import Base
from app.models.itsm import ITSM_TABLES
from app.permissions import PERMISSIONS

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_ORG_EXPR = "organization_id::text = current_setting('app.current_org_id', true)"

# Tables whose RLS policy set is SELECT + INSERT only (append-only,
# same rule as the audit log).
AUDIT_STYLE_TABLES = {"knowledge_feedback", "survey_responses"}

# Counter tables follow the ticket_counters pattern from 0001:
# SELECT / INSERT / UPDATE, no DELETE.
COUNTER_TABLES = {"request_counters", "change_counters", "problem_counters"}

POLICIES: list[tuple[str, str, str, str | None, str | None]] = []
for _model in ITSM_TABLES:
    _table = _model.__tablename__
    if _table in AUDIT_STYLE_TABLES:
        POLICIES.append((_table, f"{_table}_select", "SELECT", _ORG_EXPR, None))
        POLICIES.append((_table, f"{_table}_insert", "INSERT", None, _ORG_EXPR))
    elif _table in COUNTER_TABLES:
        POLICIES.append((_table, f"{_table}_select", "SELECT", _ORG_EXPR, None))
        POLICIES.append((_table, f"{_table}_insert", "INSERT", None, _ORG_EXPR))
        POLICIES.append((_table, f"{_table}_update", "UPDATE", _ORG_EXPR, _ORG_EXPR))
    else:
        POLICIES.append((_table, f"{_table}_all", "ALL", _ORG_EXPR, _ORG_EXPR))

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

# Reverse dependency order for downgrade (children first; CASCADE
# covers the problems <-> known_errors cycle either way).
DOWNGRADE_TABLES = [
    "survey_responses",
    "surveys",
    "major_incidents",
    "recurring_tickets",
    "ticket_templates",
    "ticket_links",
    "ticket_attachments",
    "ticket_comments",
    "notifications",
    "known_errors",
    "problem_counters",
    "problems",
    "change_tasks",
    "change_approvals",
    "change_counters",
    "changes",
    "knowledge_feedback",
    "knowledge_articles",
    "catalog_items",
    "catalog_categories",
    "request_counters",
    "requests",
]

# Grants: the ALTER DEFAULT PRIVILEGES pattern copied from 0001 (the
# app connects as null_app, never as the owner).
GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA public TO null_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO null_app';
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT USAGE, SELECT ON SEQUENCES TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    # create_all with an explicit table list: handles the circular FK
    # between problems and known_errors (one FK is deferred to ALTER).
    Base.metadata.create_all(bind, tables=[m.__table__ for m in ITSM_TABLES], checkfirst=True)

    # Seed the permission catalog (idempotent).
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
    for table in DOWNGRADE_TABLES:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
