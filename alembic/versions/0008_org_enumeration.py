"""Organization enumeration for background sweeps (migration 0008).

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-26

The Celery sweeps (SLA breach scan, recurring-ticket dispatcher) run as
the application role (``null_app``), which cannot read the
``organizations`` table without an RLS context — the org SELECT policy
requires an active membership or the creator. The sweeps therefore
enumerate organizations through this grant-checked SECURITY DEFINER
function, following the same pattern as the pre-auth lookup functions
in 0001 and the SCIM functions in 0007: owner-owned, locked
``search_path``, returns ids only (no names, no settings, no member
data). Per-org work itself is always RLS-scoped to the enumerated id,
so the function cannot leak tenant data — it only answers "which orgs
exist" to the worker that already needs to sweep them.

The email poller (0006) has its own narrower function
(``email_list_active_mailbox_orgs``) and is untouched.
"""

from __future__ import annotations

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

FUNCTIONS_SQL = """
CREATE OR REPLACE FUNCTION list_organization_ids()
RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT id FROM organizations;
$$;
"""

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION list_organization_ids() TO null_app';
  END IF;
END $$;
"""


def upgrade() -> None:
    op.execute(FUNCTIONS_SQL)
    op.execute(GRANT_SQL)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS list_organization_ids()")
