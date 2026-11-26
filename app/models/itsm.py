"""Phase 2 ITSM engine models (migration 0004).

Service requests + catalog, knowledge base, changes, problems /
known errors, notifications, ticket comments / attachments / links,
ticket templates + recurring tickets, major incidents, surveys.

Every tenant-owned table carries ``organization_id`` (FK organizations,
CASCADE, NOT NULL, indexed) and is RLS-scoped by the standard
org-scoped ALL policy (see migration 0004). Audit-style tables
(knowledge_feedback, survey_responses) are SELECT + INSERT only at
the policy level — same rule as the audit log.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_col() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_col(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable, index=True)


class _OrgCounter:
    """Shared shape for per-org human-number counters (row-locked)."""

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    last_number: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    updated_at: Mapped[datetime] = updated_at_col()


# --- Service requests ------------------------------------------------------


class ServiceRequest(Base):
    __tablename__ = "requests"
    __table_args__ = (UniqueConstraint("organization_id", "number", name="uq_request_org_number"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    # Per-organization human number, e.g. REQ-000001.
    number: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # submitted | in_progress | pending_approval | approved | fulfilled | rejected | cancelled
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="submitted")
    # low | medium | high | critical
    priority: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    catalog_item_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalog_items.id", ondelete="SET NULL"), nullable=True, index=True
    )
    requester_id: Mapped[uuid.UUID | None] = _user_col()
    assignee_id: Mapped[uuid.UUID | None] = _user_col()
    approved_by_id: Mapped[uuid.UUID | None] = _user_col()
    approved_at: Mapped[datetime | None] = tz_col()
    fulfilled_at: Mapped[datetime | None] = tz_col()
    form_data: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class RequestCounter(Base, _OrgCounter):
    __tablename__ = "request_counters"


# --- Service catalog -------------------------------------------------------


class CatalogCategory(Base):
    __tablename__ = "catalog_categories"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalog_categories.id", ondelete="SET NULL"), nullable=True, index=True
    )
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class CatalogItem(Base):
    __tablename__ = "catalog_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    category_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalog_categories.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # draft | published | retired
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    fulfillment_instructions: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    form_schema: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Knowledge base --------------------------------------------------------


class KnowledgeArticle(Base):
    __tablename__ = "knowledge_articles"
    __table_args__ = (UniqueConstraint("organization_id", "slug", name="uq_kb_article_org_slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # draft | published | archived
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    author_id: Mapped[uuid.UUID | None] = _user_col()
    category: Mapped[str] = mapped_column(String(100), nullable=False, server_default="General")
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    view_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    published_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class KnowledgeFeedback(Base):
    __tablename__ = "knowledge_feedback"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    article_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("knowledge_articles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID | None] = _user_col()
    helpful: Mapped[bool] = mapped_column(Boolean, nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Changes ---------------------------------------------------------------


class Change(Base):
    __tablename__ = "changes"
    __table_args__ = (UniqueConstraint("organization_id", "number", name="uq_change_org_number"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    # Per-organization human number, e.g. CHG-000001.
    number: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # draft | pending_approval | approved | scheduled | implementing |
    # implemented | failed | rolled_back | closed | cancelled
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    # low | medium | high
    risk: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    # low | medium | high | critical
    priority: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    # standard | normal | emergency
    type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="normal")
    requester_id: Mapped[uuid.UUID | None] = _user_col()
    assignee_id: Mapped[uuid.UUID | None] = _user_col()
    implementation_window_start: Mapped[datetime | None] = tz_col()
    implementation_window_end: Mapped[datetime | None] = tz_col()
    rollback_plan: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    scheduled_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ChangeCounter(Base, _OrgCounter):
    __tablename__ = "change_counters"


class ChangeApproval(Base):
    __tablename__ = "change_approvals"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("changes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approver_id: Mapped[uuid.UUID | None] = _user_col()
    # pending | approved | rejected
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    decision_at: Mapped[datetime | None] = tz_col()
    comment: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ChangeTask(Base):
    __tablename__ = "change_tasks"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("changes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # pending | in_progress | done | skipped
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    assignee_id: Mapped[uuid.UUID | None] = _user_col()
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    due_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Problems / known errors -----------------------------------------------


class Problem(Base):
    __tablename__ = "problems"
    __table_args__ = (UniqueConstraint("organization_id", "number", name="uq_problem_org_number"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    # Per-organization human number, e.g. PRB-000001.
    number: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # open | investigating | root_cause_identified | resolved | closed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="open")
    # low | medium | high | critical
    priority: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    workaround: Mapped[str | None] = mapped_column(Text, nullable=True)
    known_error_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("known_errors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    assignee_id: Mapped[uuid.UUID | None] = _user_col()
    requester_id: Mapped[uuid.UUID | None] = _user_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ProblemCounter(Base, _OrgCounter):
    __tablename__ = "problem_counters"


class KnownError(Base):
    __tablename__ = "known_errors"
    __table_args__ = (UniqueConstraint("organization_id", "code", name="uq_known_error_org_code"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    code: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    workaround: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # active | resolved
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    problem_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("problems.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Notifications -----------------------------------------------------------


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    channel: Mapped[str] = mapped_column(String(20), nullable=False, server_default="in_app")
    email_status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="n/a")
    read_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Ticket extensions: comments / attachments / links ---------------------


class TicketComment(Base):
    __tablename__ = "ticket_comments"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = _user_col()
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_internal: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class TicketAttachment(Base):
    __tablename__ = "ticket_attachments"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    uploaded_by_id: Mapped[uuid.UUID | None] = _user_col()
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False, server_default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    storage_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class TicketLink(Base):
    __tablename__ = "ticket_links"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    source_ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # ticket | request | change | problem
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    # parent | child | related | caused_by | blocks
    link_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="related")
    created_by_id: Mapped[uuid.UUID | None] = _user_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Templates / recurring tickets ------------------------------------------


class TicketTemplate(Base):
    __tablename__ = "ticket_templates"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    category: Mapped[str] = mapped_column(String(50), nullable=False, server_default="General")
    priority: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    default_assignee_id: Mapped[uuid.UUID | None] = _user_col()
    form_schema: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class RecurringTicket(Base):
    __tablename__ = "recurring_tickets"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ticket_templates.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # {"frequency": "daily"|"weekly"|"monthly", "time": "HH:MM", "weekday": 0-6}
    schedule: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    next_run_at: Mapped[datetime | None] = tz_col()
    last_run_at: Mapped[datetime | None] = tz_col()
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_by_id: Mapped[uuid.UUID | None] = _user_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Major incidents ---------------------------------------------------------


class MajorIncident(Base):
    __tablename__ = "major_incidents"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    # low | medium | high | critical
    severity: Mapped[str] = mapped_column(String(20), nullable=False, server_default="high")
    # declared | investigating | mitigating | resolved | closed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="declared")
    commander_id: Mapped[uuid.UUID | None] = _user_col()
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    resolved_at: Mapped[datetime | None] = tz_col()
    summary: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Surveys -----------------------------------------------------------------


class Survey(Base):
    __tablename__ = "surveys"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # ticket | request
    target_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ticket")
    questions: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class SurveyResponse(Base):
    __tablename__ = "survey_responses"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_col()
    survey_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("surveys.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    respondent_id: Mapped[uuid.UUID | None] = _user_col()
    answers: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # submitted_at carries the submission time; it is set to created_at
    # (server now) on insert.
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


ITSM_TABLES = [
    ServiceRequest,
    RequestCounter,
    CatalogCategory,
    CatalogItem,
    KnowledgeArticle,
    KnowledgeFeedback,
    Change,
    ChangeCounter,
    ChangeApproval,
    ChangeTask,
    Problem,
    ProblemCounter,
    KnownError,
    Notification,
    TicketComment,
    TicketAttachment,
    TicketLink,
    TicketTemplate,
    RecurringTicket,
    MajorIncident,
    Survey,
    SurveyResponse,
]
