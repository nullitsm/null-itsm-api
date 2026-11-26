"""Agent + endpoint models (Phase 3, migration 0009).

Every table here is tenant-owned: ``organization_id`` FK to organizations
(CASCADE, NOT NULL, indexed) plus ``created_at`` / ``updated_at`` — except
``agent_releases``, which is a global release catalog (no tenant data:
version + artifact metadata for every org's agents), so it carries no
``organization_id`` and no RLS policy. Row-Level Security policies live in
migration 0009 (standard org-scoped ALL policy, except
``endpoint_inventory`` which is append-only: SELECT + INSERT only, like
the audit log).

Secrets: enrollment tokens and device tokens are stored ONLY as SHA-256
hashes — the raw secret is shown once at creation and never persisted.
Device authentication resolves through the SECURITY DEFINER functions
``auth_get_enrollment_token_by_hash`` and
``auth_get_endpoint_by_device_token`` (migration 0009), the same pattern
as the SCIM token lookup in 0007: no JWT, no RLS context yet, exact
credential match only, never enumeration.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable)


def _endpoint_fk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)


class EnrollmentToken(Base):
    """One-time enrollment token, issued out-of-band by an org admin.

    Single-use and short-lived: ``used_at`` is set atomically on
    enrollment (the consume UPDATE must match ``used_at IS NULL`` and
    check the rowcount, or two agents could enroll on one token).
    """

    __tablename__ = "enrollment_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    # SHA-256 hex of the raw token. The raw token is shown once at creation.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    expires_at: Mapped[datetime | None] = tz_col()
    used_at: Mapped[datetime | None] = tz_col()
    used_endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    revoked_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class Endpoint(Base):
    """An agent-enrolled device. Identity is (device_id, device_token).

    ``status``: enrolled | online | offline | stale | unenrolled.
    ``last_seen_at`` is updated by every heartbeat; a device silent beyond
    the org's threshold is shown stale/offline by the console (derived,
    never stored as a separate flag). ``asset_id`` links the endpoint to
    its Phase 2 asset record when one exists.
    """

    __tablename__ = "endpoints"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(50), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="enrolled")
    agent_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # SHA-256 hex of the device token. Shown once at enrollment, never again.
    device_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)
    token_revoked_at: Mapped[datetime | None] = tz_col()
    token_last_used_at: Mapped[datetime | None] = tz_col()
    last_seen_at: Mapped[datetime | None] = tz_col()
    enrolled_at: Mapped[datetime | None] = tz_col()
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class EndpointInventory(Base):
    """One inventory submission from an agent. Append-only history.

    Each submission is a new row; the latest row per endpoint is the
    current inventory. Unknown top-level sections are rejected by the API
    (contract §9.4) rather than silently dropped, so the stored JSONB is
    always a validated shape.
    """

    __tablename__ = "endpoint_inventory"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    endpoint_id: Mapped[uuid.UUID] = _endpoint_fk()
    collected_at: Mapped[datetime | None] = tz_col()
    os: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    hardware: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    network: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    software: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    services: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    created_at: Mapped[datetime] = created_at_col()


class AgentJob(Base):
    """A remote job issued to one agent. The agent polls; the server never
    initiates a connection (contract §9.5).

    At-most-once delivery: a job is delivered once (``delivered_at`` set
    on the ``/jobs/next`` poll); a reported result closes it. An expired
    job is never re-delivered under the same id. The backend never sends
    arbitrary shell strings — ``type`` is from the allowlisted set and
    ``payload`` is a validated shape; the agent must reject anything else.
    """

    __tablename__ = "agent_jobs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    endpoint_id: Mapped[uuid.UUID] = _endpoint_fk()
    # patch_scan | inventory_refresh | config_apply | patch_deploy |
    # vuln_scan | restart | shutdown
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    # pending | delivered | succeeded | failed | rejected | expired
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    issued_by_id: Mapped[uuid.UUID | None] = _user_fk()
    expires_at: Mapped[datetime | None] = tz_col()
    delivered_at: Mapped[datetime | None] = tz_col()
    started_at: Mapped[datetime | None] = tz_col()
    finished_at: Mapped[datetime | None] = tz_col()
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class AgentRelease(Base):
    """Global agent release catalog (NOT tenant data).

    No ``organization_id`` and no RLS: release metadata (version,
    artifact hash, signature) is the same for every org. The agent
    installs an update only after verifying the detached signature
    against the pinned NULL public key AND the SHA-256 of the artifact
    (contract §9.6). ``download_url`` is per-device and short-lived and
    is generated at check time, never stored here.
    """

    __tablename__ = "agent_releases"
    __table_args__ = (UniqueConstraint("version", "os", "arch", name="uq_agent_release_version_os_arch"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    os: Mapped[str] = mapped_column(String(50), nullable=False)
    arch: Mapped[str] = mapped_column(String(50), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    release_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
