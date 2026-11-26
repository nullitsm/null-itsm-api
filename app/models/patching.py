"""Patching models (Phase 3, migration 0010).

Every table here is tenant-owned: ``organization_id`` FK to organizations
(CASCADE, NOT NULL, indexed) plus ``created_at`` / ``updated_at``.
Row-Level Security policies live in migration 0010 (standard org-scoped
ALL policy).

Flow: an agent patch scan (``AgentJob`` type ``patch_scan``) reports
missing patches → ``Patch`` catalog rows (created on first sight) +
``PatchFinding`` rows (missing, per endpoint). A ``PatchDeployment``
groups (endpoint, patch) items; each item is executed through an agent
job (type ``patch_deploy``). Verification is a post-deploy patch scan:
``verification_scan_id`` points at the ``PatchScan`` that proves the
patch is installed. Nothing here claims a patch was installed unless a
scan or a job result says so.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable)


class Patch(Base):
    """A known patch (vendor catalog entry). Created on first sight from a
    scan result; never invented — a patch exists here only because a scan
    or an admin reported it.
    """

    __tablename__ = "patches"
    __table_args__ = (UniqueConstraint("organization_id", "kb_id", name="uq_patch_org_kb"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    kb_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    # critical | high | medium | low
    severity: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    os_family: Mapped[str | None] = mapped_column(String(100), nullable=True)
    release_date: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PatchScan(Base):
    """One patch-scan run against one endpoint (usually driven by an
    agent job; a scan can also be recorded without a job id).
    """

    __tablename__ = "patch_scans"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # pending | running | completed | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    started_at: Mapped[datetime | None] = tz_col()
    finished_at: Mapped[datetime | None] = tz_col()
    missing_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PatchFinding(Base):
    """A patch missing (or installed) on one endpoint, from one scan.

    One open row per (endpoint, patch): enforced by a partial unique
    index in migration 0010 (``status = 'missing'``). Installing the
    patch flips the row to ``installed`` (with ``installed_at``); a later
    scan that still finds it missing re-opens it.
    """

    __tablename__ = "patch_findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    patch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patches.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patch_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # missing | installed | failed | superseded
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="missing")
    detected_at: Mapped[datetime | None] = tz_col()
    installed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PatchDeployment(Base):
    """A patch deployment: a set of (endpoint, patch) items deployed
    together, optionally on a schedule, with approval and verification.

    ``status``: draft | scheduled | approved | deploying | completed |
    failed | cancelled. Verification is a post-deploy ``PatchScan``
    (``verification_scan_id``); ``verification_status`` is pending |
    passed | failed. A deployment is never reported complete on the
    basis of job issue alone — items report their own job results.
    """

    __tablename__ = "patch_deployments"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    scheduled_at: Mapped[datetime | None] = tz_col()
    approved_by_id: Mapped[uuid.UUID | None] = _user_fk()
    approved_at: Mapped[datetime | None] = tz_col()
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    verification_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patch_scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    verification_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PatchDeploymentItem(Base):
    """One (endpoint, patch) inside a deployment, executed via one agent job."""

    __tablename__ = "patch_deployment_items"
    __table_args__ = (
        UniqueConstraint("deployment_id", "endpoint_id", "patch_id", name="uq_deploy_item_endpoint_patch"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patch_deployments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    patch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("patches.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # pending | queued | deploying | succeeded | failed | skipped
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
