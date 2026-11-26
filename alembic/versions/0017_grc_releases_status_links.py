"""GRC, releases, feature flags, status page, cross-module links (migration 0017).

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-26

Creates the Phase 4 workstream D tables:

* GRC: grc_controls (+ grc_control_mappings SOC 2 / ISO 27001 / NIST CSF
  / CIS, grc_evidence, grc_assessments + grc_assessment_controls,
  grc_exceptions). Control status is DERIVED from assessments and
  exceptions (see app.services.grc_service) — never client-set, never a
  certification claim.
* Releases + feature flags: releases, feature_flags.
* Status page: status_page_incidents + status_page_incident_updates
  (the updates timeline).
* Cross-module linking: entity_links.

Follows the 0012/0013 pattern: tables via ``__table__.create(checkfirst=True)``,
standard org-scoped RLS ALL policies, the permission catalog re-seeded
idempotently, and grants via the 0001 ALTER DEFAULT PRIVILEGES pattern.
Adds the SECURITY DEFINER function ``status_page_org_id_by_slug`` for
the public status-page read: it resolves a public org slug to an org
id and reveals nothing else (mirrors ``org_slug_exists`` from 0013).

NOTE: this file's ``down_revision`` is "0016" per the Phase 4 plan
(migrations 0014–0016 belong to sibling workstreams A–C).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.models.grc import (
    GrcAssessment,
    GrcAssessmentControl,
    GrcControl,
    GrcControlMapping,
    GrcEvidence,
    GrcException,
)
from app.models.linking import (
    EntityLink,
    FeatureFlag,
    Release,
    StatusPageIncident,
    StatusPageIncidentUpdate,
)
from app.permissions import PERMISSIONS

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

TABLES = [
    GrcControl,
    GrcControlMapping,
    GrcEvidence,
    GrcAssessment,
    GrcAssessmentControl,
    GrcException,
    FeatureFlag,
    Release,
    StatusPageIncident,
    StatusPageIncidentUpdate,
    EntityLink,
]

# Standard org-scoped policy expression (0001 pattern).
_ORG = "organization_id::text = current_setting('app.current_org_id', true)"

POLICIES = [(_model.__tablename__, f"{_model.__tablename__}_all", "ALL", _ORG, _ORG) for _model in TABLES]

RLS_TABLES = sorted({table for table, _, _, _, _ in POLICIES})

_TABLE_LIST = ", ".join(_model.__tablename__ for _model in TABLES)

GRANT_SQL = f"""
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE_LIST} TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO null_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE null_owner IN SCHEMA public '
            'GRANT USAGE, SELECT ON SEQUENCES TO null_app';
  END IF;
END $$;
"""

STATUS_PAGE_ORG_FN_SQL = """
-- Resolve a public org slug to its org id for the public status page.
-- SECURITY DEFINER so the unauthenticated read can scope itself to the
-- org; it returns only the id (or NULL) and reveals nothing else.
-- The public endpoint then returns incident data only.
CREATE OR REPLACE FUNCTION status_page_org_id_by_slug(p_slug text)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT id FROM organizations WHERE slug = p_slug;
$$;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'null_app') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION status_page_org_id_by_slug(text) TO null_app';
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
    op.execute(STATUS_PAGE_ORG_FN_SQL)

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
    op.execute("DROP FUNCTION IF EXISTS status_page_org_id_by_slug(text)")
    for table in (
        "entity_links",
        "status_page_incident_updates",
        "status_page_incidents",
        "releases",
        "feature_flags",
        "grc_exceptions",
        "grc_assessment_controls",
        "grc_assessments",
        "grc_evidence",
        "grc_control_mappings",
        "grc_controls",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
