"""Vulnerability management models (Phase 3, migration 0011).

``cve_catalog`` is GLOBAL (public CVE / CISA KEV data — no tenant data),
so it carries no ``organization_id`` and no RLS policy. Every other table
here is tenant-owned: ``organization_id`` FK to organizations (CASCADE,
NOT NULL, indexed) plus ``created_at`` / ``updated_at``. Row-Level
Security policies live in migration 0011 (standard org-scoped ALL policy,
except ``scan_results`` which is append-only raw engine evidence:
SELECT + INSERT only).

Honesty rules (see docs/DECISIONS.md, "Real data only"): findings come
from real engine scans and real CVE/KEV data with stored evidence.
``scan_results`` are the raw engine output; ``vulnerability_findings``
are the deduplicated working set (one open row per endpoint+CVE).
Remediation is a ``remediation_tickets`` link row: finding → ticket →
patch → deployment → verification scan. A finding is ``verified`` only
when a verification scan says so — never on the basis of a ticket being
closed alone.

Engine credentials that must be reversible (Greenbone/GMP password) are
Fernet-encrypted through ``app.crypto`` (imported lazily in the services
that need it); storing one fails closed with an honest error when no
field-encryption key is configured.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable)


class VulnEngine(Base):
    """A configured vulnerability scan engine for one org.

    Multi-engine architecture: ``engine_type`` selects the driver
    (``greenbone`` / ``openvas`` / ``manual``). The Greenbone driver
    speaks GMP to a configured Greenbone host; when no engine is
    configured, scans fail honestly ("no engine configured") instead of
    inventing results. ``manual`` engines accept imported results only.
    """

    __tablename__ = "vuln_engines"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # greenbone | openvas | manual
    engine_type: Mapped[str] = mapped_column(String(20), nullable=False)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Fernet-encrypted (app.crypto, lazy import); never plaintext.
    password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # active | inactive | error
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    last_sync_at: Mapped[datetime | None] = tz_col()
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class CveCatalog(Base):
    """Global CVE + CISA KEV catalog (NOT tenant data).

    Synced from the real NVD API and the real CISA KEV feed by a Celery
    task; rows are never invented. ``kev`` flags KEV membership with the
    feed's own dates. No ``organization_id``, no RLS.
    """

    __tablename__ = "cve_catalog"

    id: Mapped[uuid.UUID] = uuid_pk()
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # critical | high | medium | low | none
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    published_date: Mapped[datetime | None] = tz_col()
    last_modified_date: Mapped[datetime | None] = tz_col()
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    kev_added_date: Mapped[datetime | None] = tz_col()
    kev_due_date: Mapped[datetime | None] = tz_col()
    kev_vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_ransomware_use: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    references: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class VulnScan(Base):
    """One vulnerability scan run (engine-driven or manual import)."""

    __tablename__ = "vuln_scans"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    engine_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vuln_engines.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # The engine's own scan/report id (e.g. Greenbone scan UUID).
    engine_scan_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str | None] = mapped_column(Text, nullable=True)
    # queued | running | completed | failed | cancelled
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="queued")
    started_at: Mapped[datetime | None] = tz_col()
    finished_at: Mapped[datetime | None] = tz_col()
    result_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ScanResult(Base):
    """One raw engine result. Append-only evidence (SELECT + INSERT only).

    A result names a host and a CVE; the host may or may not be an
    enrolled endpoint (``endpoint_id`` is NULL for unenrolled hosts).
    Workflow state lives on ``vulnerability_findings``, never here.
    """

    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vuln_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    plugin_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    plugin_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    # critical | high | medium | low | none
    severity: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    detected_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()


class VulnerabilityFinding(Base):
    """One deduplicated vulnerability finding (the working set).

    One open row per (endpoint, CVE): enforced by a partial unique index
    in migration 0011 (``status IN ('open', 'in_progress')``). A finding
    links to its remediation ticket, patch, and verification scan; it
    becomes ``verified`` only when a verification scan confirms the CVE
    is gone.
    """

    __tablename__ = "vulnerability_findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # critical | high | medium | low | none
    severity: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    # open | in_progress | remediated | verified | false_positive | accepted_risk
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="open")
    first_seen_at: Mapped[datetime | None] = tz_col()
    last_seen_at: Mapped[datetime | None] = tz_col()
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vuln_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    remediation_ticket_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    remediation_patch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patches.id", ondelete="SET NULL"), nullable=True, index=True
    )
    verified_at: Mapped[datetime | None] = tz_col()
    verification_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vuln_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class RemediationTicket(Base):
    """Cross-module remediation link: finding → ticket → patch →
    deployment → verification scan (the unified-model promise).

    One row per (finding, ticket). ``status`` tracks the remediation
    lifecycle independently of the ticket's own status: open |
    in_progress | remediated | verified | closed.
    """

    __tablename__ = "remediation_tickets"
    __table_args__ = (UniqueConstraint("finding_id", "ticket_id", name="uq_remediation_finding_ticket"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    patch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patches.id", ondelete="SET NULL"), nullable=True, index=True
    )
    deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patch_deployments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    verification_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vuln_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # open | in_progress | remediated | verified | closed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="open")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
