"""SQLAlchemy declarative base and shared columns."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def created_at_col() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def updated_at_col() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


def tz_col(nullable: bool = True) -> Mapped[datetime | None]:
    """A timezone-aware timestamp column (TIMESTAMPTZ).

    Every application datetime is timezone-aware (``_now()`` returns UTC);
    a naive TIMESTAMP column breaks every comparison against one, so all
    non-audit timestamp columns use this helper.
    """
    return mapped_column(DateTime(timezone=True), nullable=nullable)
