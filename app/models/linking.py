"""Cross-module linking, releases, feature flags, and status page
models (Phase 4 workstream D, migration 0017).

Every table here is tenant-owned: ``organization_id`` FK to organizations
(CASCADE, NOT NULL, indexed) plus ``created_at`` / ``updated_at``.
Row-Level Security policies live in migration 0017 (standard org-scoped
ALL policy).

``entity_links`` is the unified-model promise: a generic typed link
between two entities in the SAME org. ``source_id`` / ``target_id``
are plain UUIDs (no FK) because the target table depends on
``source_type`` / ``target_type``; existence in the same org is
validated in ``app.services.linking_service`` on write, never trusted
from the client.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable)


# --- Releases + feature flags ------------------------------------------------

# draft | scheduled | released
RELEASE_STATUSES = {"draft", "scheduled", "released"}


class Release(Base):
    """A product release for one org.

    ``released_at`` is set when the release transitions to ``released``
    (and never back-dated by a client). ``version`` is unique per org.
    """

    __tablename__ = "releases"
    __table_args__ = (UniqueConstraint("organization_id", "version", name="uq_release_org_version"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    version: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    scheduled_at: Mapped[datetime | None] = tz_col()
    released_at: Mapped[datetime | None] = tz_col()
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class FeatureFlag(Base):
    """A feature flag for one org.

    ``rollout_percentage`` (0–100) is evaluated deterministically per
    org (see ``linking_service.evaluate_flag``): the same org always
    gets the same answer for the same flag — never random, never
    hardcoded.
    """

    __tablename__ = "feature_flags"
    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_feature_flag_org_key"),
        CheckConstraint("rollout_percentage >= 0 AND rollout_percentage <= 100", name="ck_flag_rollout_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    rollout_percentage: Mapped[int] = mapped_column(Integer, nullable=False, server_default="100")
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Status page ---------------------------------------------------------------

# investigating | identified | monitoring | resolved
STATUS_PAGE_INCIDENT_STATUSES = {"investigating", "identified", "monitoring", "resolved"}


class StatusPageIncident(Base):
    """A status-page incident for one org.

    Incidents are the only thing the public status-page endpoint
    reveals: no org internals, no user data, no ticket data.
    ``resolved_at`` is set when the incident transitions to ``resolved``.
    """

    __tablename__ = "status_page_incidents"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="investigating")
    started_at: Mapped[datetime | None] = tz_col()
    resolved_at: Mapped[datetime | None] = tz_col()
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class StatusPageIncidentUpdate(Base):
    """One timeline update on a status-page incident.

    Posting an update moves the incident to the update's status (see
    the router): the timeline is the incident's status history.
    """

    __tablename__ = "status_page_incident_updates"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("status_page_incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Cross-module linking ------------------------------------------------------

class EntityLink(Base):
    """A typed link between two entities in the same org.

    ``source_type`` / ``target_type`` must be in the allow-list in
    ``linking_service``; both ends must exist in the same org at
    creation time (validated in the service — never linked across orgs,
    never linked to a nonexistent record). Links are immutable facts:
    there is no update path, only create + delete.
    """

    __tablename__ = "entity_links"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "source_type",
            "source_id",
            "target_type",
            "target_id",
            "link_type",
            name="uq_entity_link",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    link_type: Mapped[str] = mapped_column(String(50), nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
