"""Tickets — the Phase 1 tenant-isolation proof domain.

Phase 1's platform tables do not yet include the full ITSM domain (that is
Phase 2). This minimal ``tickets`` table exists so tenant isolation can be
proven end-to-end in Phase 1: two organizations, two sets of tickets, and
RLS + API checks that make cross-organization access impossible.

Phase 2 extends this table (SLA, comments, attachments, workflow state)
without rework — see docs/DATA_MODEL.md.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, updated_at_col, uuid_pk


class Ticket(Base):
    __tablename__ = "tickets"
    __table_args__ = (UniqueConstraint("organization_id", "number", name="uq_ticket_org_number"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Per-organization human number, e.g. INC-000123.
    number: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # open | in_progress | pending | resolved | closed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="open")
    # low | medium | high | critical
    priority: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    category: Mapped[str] = mapped_column(String(50), nullable=False, server_default="General")
    requester_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class TicketCounter(Base):
    """Per-organization ticket number counter (row-locked on increment)."""

    __tablename__ = "ticket_counters"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    last_number: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    updated_at: Mapped[datetime] = updated_at_col()
