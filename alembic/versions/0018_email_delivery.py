"""Email delivery records (migration 0018).

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-26

- New table: email_deliveries (one row per delivery attempt batch for one
  outbound email). The rendered bodies are stored so a failed provider
  submission can be retried by the Celery task without re-rendering —
  and without ever needing the raw invitation token again.
- RLS: standard org-scoped ALL policy for org rows; a platform-gated
  ALL policy for platform rows (scope='platform' + an authenticated
  platform identity). Postgres ORs the two policies; an org session can
  never see platform rows and vice versa.
- Idempotency backstop: partial unique indexes — at most one pending
  invitation per (organization_id, email) and at most one pending
  platform invitation per email. Stale pending rows are retired to
  status 'expired' at invite time (org_service / platform_service), so
  a re-invite after expiry inserts cleanly.
- Grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.email import EmailDelivery

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

TABLES = [EmailDelivery]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"
# Platform rows: only when the caller is an authenticated platform
# identity (0002 pattern); granular checks stay in the API layer.
_PLATFORM = (
    "scope = 'platform' "
    "AND current_setting('app.current_platform_user_id', true) <> ''"
)

# (table, policy_name, command, using_expr, check_expr)
POLICIES = [
    ("email_deliveries", "email_deliveries_org_all", "ALL", _ORG, _ORG),
    ("email_deliveries", "email_deliveries_platform_all", "ALL", _PLATFORM, _PLATFORM),
]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'email_deliveries TO null_app';
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

    # Idempotency backstop: at most one live pending invitation per
    # (organization, email) and per platform email. Expired rows are
    # retired to status 'expired' at invite time, so they never block a
    # re-invite.
    op.create_index(
        "uq_invitations_pending_email",
        "invitations",
        ["organization_id", "email"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "uq_platform_invitations_pending_email",
        "platform_invitations",
        ["email"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_index("uq_platform_invitations_pending_email", table_name="platform_invitations")
    op.drop_index("uq_invitations_pending_email", table_name="invitations")
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TABLE IF EXISTS email_deliveries CASCADE")
