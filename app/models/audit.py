"""Audit log model — append-only by design.

There is NO update or delete API for audit records, and the database
enforces it: the RLS policy set (see the initial migration) contains no
UPDATE or DELETE policy for ``audit_logs``, so those statements are denied
even for the application role. Every event records organization, actor,
action, resource, timestamp, outcome, and metadata.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, uuid_pk


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Actor may be NULL for system-initiated events (e.g. token expiry).
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(100), nullable=False)
    # success | failure | denied
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, server_default="success")
    # Attribute is `meta` because `metadata` is reserved by SQLAlchemy's
    # declarative API; the column name stays "metadata".
    meta: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
