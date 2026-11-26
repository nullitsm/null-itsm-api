"""Access governance models (Phase 1, Users & Roles screen).

- ``AccessApproval``: elevated-access approval requests. When an
  organization's least-privilege policy requires approval for elevated
  access, assigning a Privileged/Full Access role creates a pending
  approval instead of granting immediately.
- ``AccessReview``: periodic access-review records. "Review Now" creates a
  review holding a snapshot of current memberships and role assignments.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, uuid_pk


class AccessApproval(Base):
    __tablename__ = "access_approvals"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    target_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    # pending | approved | denied
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()


class AccessReview(Base):
    __tablename__ = "access_reviews"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    initiated_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # open | completed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="open")
    # Snapshot of memberships + role assignments at review time.
    snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    completed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
