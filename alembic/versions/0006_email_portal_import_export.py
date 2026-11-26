"""Email / portal / import / export tables (migration 0006).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-25

Creates the Phase 2 email-to-ticket, employee-portal, and data
portability tables:
- email_mailboxes / email_messages (IMAP ingest + SMTP replies)
- portal_sessions (employee self-service sessions; token hashes only)
- imports / import_records (ServiceNow / Jira / CSV, idempotent)
- exports (tickets / requests / users / audit / full)

Every table is tenant-owned and RLS-scoped with the standard
org-scoped ALL policy. The permission catalog is seeded idempotently
(``ON CONFLICT (code) DO NOTHING``) — another migration may already
have seeded it.

Also adds ``email_list_active_mailbox_orgs()``, a SECURITY DEFINER
function (same controlled-bypass pattern as 0001): the Celery mailbox
poller must discover which organizations have active mailboxes before
any RLS context exists, and it cannot enumerate tenant rows through
the ORM. The function returns only organization ids with an active
mailbox — no credentials, no message content.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.email_portal import DataExport, DataImport, EmailMailbox, EmailMessage, ImportRecord, PortalSession
from app.permissions import PERMISSIONS

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

TABLES = [EmailMailbox, EmailMessage, PortalSession, DataImport, ImportRecord, DataExport]

_ORG = "organization_id::text = current_setting('app.current_org_id', true)"
POLICIES = [
    (table, f"{table}_all", "ALL", _ORG, _ORG)
    for table in (
        "email_mailboxes",
        "email_messages",
        "portal_sessions",
        "imports",
        "import_records",
        "exports",
    )
]
RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

FUNCTIONS_SQL = """
-- Controlled bypass surface for the mailbox poller (see module docstring).
-- SECURITY DEFINER, owner-owned, locked search_path, returns org ids only.
CREATE OR REPLACE FUNCTION email_list_active_mailbox_orgs()
RETURNS TABLE (organization_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT DISTINCT m.organization_id FROM email_mailboxes m WHERE m.is_active;
$$;
"""

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION email_list_active_mailbox_orgs() TO null_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'email_mailboxes, email_messages, portal_sessions, imports, '
            'import_records, exports TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    for model in TABLES:
        model.__table__.create(bind, checkfirst=True)

    # Seed the org permission catalog (idempotent).
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
    op.execute("DROP FUNCTION IF EXISTS email_list_active_mailbox_orgs()")
    # Drop in dependency order (children first).
    for table in (
        "import_records",
        "imports",
        "exports",
        "email_messages",
        "email_mailboxes",
        "portal_sessions",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    # NOTE: the permission-catalog rows seeded in upgrade() are NOT
    # removed: the catalog is shared across migrations and other
    # migrations / role templates may reference these codes.
