"""SLA engine models — Phase 2 (migration 0005).

Business hours, SLA policies, breach records, and escalation rules/events.
Every table is tenant-owned (``organization_id``) and RLS-scoped by the
migration's standard org-scoped ALL policy. The SLA columns on ``tickets``
(first_response_due_at, resolution_due_at, first_response_at, resolved_at,
sla_policy_id, sla_breached) are added by the same migration; their ORM
mapping lives on ``app.models.ticket.Ticket``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


class BusinessHours(Base):
    """Weekly working-hours schedule + holidays, in a named timezone.

    ``schedule`` maps ``mon``..``sun`` to a list of ``[start, end]``
    ``"HH:MM"`` pairs; an empty list means closed that day.
    ``holidays`` is a list of ``"YYYY-MM-DD"`` strings (closed all day).
    """

    __tablename__ = "business_hours"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, server_default="UTC")
    schedule: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    holidays: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class SlaPolicy(Base):
    """Response/resolution targets (minutes per priority), optionally
    measured in business hours instead of calendar time.

    ``applies_to`` is e.g. ``{"categories": [...], "priorities": [...]}``;
    an empty/absent list means "all". ``business_hours_id`` NULL means
    calendar minutes.
    """

    __tablename__ = "sla_policies"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    applies_to: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    response_minutes: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    resolution_minutes: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    business_hours_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("business_hours.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class SlaBreach(Base):
    """One breach record per (organization, ticket, breach_type).

    ``breach_type`` is ``first_response`` or ``resolution``. The unique
    constraint plus a check-first in the service make breach detection
    idempotent.
    """

    __tablename__ = "sla_breaches"
    __table_args__ = (
        UniqueConstraint("organization_id", "ticket_id", "breach_type", name="uq_sla_breach_org_ticket_type"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sla_policies.id", ondelete="SET NULL"), nullable=True, index=True
    )
    breach_type: Mapped[str] = mapped_column(String(20), nullable=False)
    breached_at: Mapped[datetime] = tz_col(nullable=False)
    notified_at: Mapped[datetime | None] = tz_col()
    acknowledged_at: Mapped[datetime | None] = tz_col()
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # open | acknowledged | resolved
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="open")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class EscalationRule(Base):
    """A rule evaluated by the breach sweep: when a ticket matches the
    trigger + conditions, its actions run in ``sort_order``.

    ``trigger``: ``{"event": "sla_breach"|"no_response"|"no_update",
    "after_minutes": int}``. ``conditions``: e.g.
    ``{"priority": ["high", "critical"], "category": [...]}``.
    ``actions``: a list of ``{"type": "priority_bump"|"reassign"|"notify",
    "to_role"|"to_user_id"|"message"}``.
    """

    __tablename__ = "escalation_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    trigger: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    conditions: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    actions: Mapped[dict | list] = mapped_column(JSONB, nullable=False, server_default="[]")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class EscalationEvent(Base):
    """Record of one rule firing on one ticket. ``executed_at`` is
    ``created_at`` (per the Phase 2 spec)."""

    __tablename__ = "escalation_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("escalation_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_taken: Mapped[dict | list] = mapped_column(JSONB, nullable=False, server_default="{}")
    # executed | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="executed")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
