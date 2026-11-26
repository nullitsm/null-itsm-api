"""Vulnerability management tables (migration 0011).

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-26

Creates the Phase 3 vulnerability tables (vuln_engines, cve_catalog,
vuln_scans, scan_results, vulnerability_findings, remediation_tickets).

Follows the 0007 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS policies (``scan_results`` is append-only raw
engine evidence: SELECT + INSERT only), the permission catalog re-seeded
idempotently, and grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.

``cve_catalog`` is a global CVE + CISA KEV catalog (no tenant data), so
it carries no ``organization_id`` and no RLS policy — documented in
``app/models/vulnerabilities.py``.

One open ``vulnerability_findings`` row per (endpoint, CVE) is enforced
by a partial unique index (``status IN ('open', 'in_progress')``).
Findings with a NULL endpoint (unenrolled hosts) are not deduplicated
by the index — PostgreSQL treats NULLs as distinct — and are correlated
by host at the service layer instead.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.vulnerabilities import (
    CveCatalog,
    RemediationTicket,
    ScanResult,
    VulnEngine,
    VulnScan,
    VulnerabilityFinding,
)
from app.permissions import PERMISSIONS

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

TABLES = [
    VulnEngine,
    CveCatalog,
    VulnScan,
    ScanResult,
    VulnerabilityFinding,
    RemediationTicket,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

# (table, policy_name, command, using_expr, check_expr)
POLICIES = []
for _model in TABLES:
    _table = _model.__tablename__
    if _table == "cve_catalog":
        # Global catalog — no tenant data, no RLS.
        continue
    if _table == "scan_results":
        # Append-only raw evidence: SELECT + INSERT, no UPDATE/DELETE policy.
        POLICIES.append((_table, "scan_results_select", "SELECT", _ORG, None))
        POLICIES.append((_table, "scan_results_insert", "INSERT", None, _ORG))
    else:
        POLICIES.append((_table, f"{_table}_all", "ALL", _ORG, _ORG))

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

GRANT_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON '
            'vuln_engines, cve_catalog, vuln_scans, scan_results, vulnerability_findings, remediation_tickets TO null_app';
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

    # One open finding per (org, endpoint, CVE).
    op.create_index(
        "uq_vuln_finding_open",
        "vulnerability_findings",
        ["organization_id", "endpoint_id", "cve_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('open', 'in_progress')"),
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
    op.execute("DROP INDEX IF EXISTS uq_vuln_finding_open")
    # Drop in dependency order (children first).
    for table in (
        "remediation_tickets",
        "vulnerability_findings",
        "scan_results",
        "vuln_scans",
        "vuln_engines",
        "cve_catalog",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
