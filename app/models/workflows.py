"""Workflow designer + automation rules models (migration 0014, Phase 4).

- ``workflows`` / ``workflow_versions``: a workflow is a named,
  org-scoped, trigger-based definition whose steps operate on real ITSM
  entities (tickets, requests, changes). Every create and every edit of
  the step list snapshots an immutable ``workflow_versions`` row; a run
  pins the version it executed, so later edits never rewrite history.
- ``workflow_runs`` / ``workflow_run_steps``: execution history. A run
  records status, start/finish, and error; each step records its own
  name, status, start/finish, output, and error. Failed runs can be
  retried: succeeded steps are skipped, failed steps re-execute.
- ``automation_rules`` / ``automation_runs``: trigger -> conditions ->
  actions. A rule fires only when a real event is evaluated against it
  and every condition matches the real entity; each firing writes an
  ``automation_runs`` row recording exactly which actions ran and their
  outcome. A rule that matches nothing runs nothing and records nothing
  as done.

Step/action payloads are JSONB dicts, validated in the service layer:

- step ``{"type": "assign", "assignee_id": "<uuid>"}``
- step ``{"type": "set_priority", "priority": "high"}``
- step ``{"type": "set_status", "status": "in_progress"}``
- step ``{"type": "add_comment", "body": "...", "is_internal": true}``
- step ``{"type": "notify", "user_id": "<uuid>", "title": "...",
  "body": "..."}``

Rule conditions are a list of ``{"field": ..., "operator": ...,
"value": ...}`` where operator is one of ``eq`` / ``ne`` / ``in`` /
``not_in`` / ``is_null`` / ``is_not_null`` and field is a real column
of the target entity (``status``, ``priority``, ``category``,
``assignee_id``, ``sla_breached`` for tickets).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk(nullable: bool = False) -> Mapped[uuid.UUID | None]:
    return mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=nullable,
        index=True,
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=nullable,
        index=True,
    )


# --- Workflows ----------------------------------------------------------------

WORKFLOW_STATUSES = {"draft", "published", "archived"}
WORKFLOW_ENTITY_TYPES = {"ticket", "request", "change"}
WORKFLOW_TRIGGERS = {
    "ticket.created",
    "ticket.updated",
    "ticket.priority_changed",
    "sla_breach",
    "request.created",
    "request.updated",
    "change.created",
    "change.updated",
    "manual",
}
RUN_STATUSES = {"running", "succeeded", "failed", "cancelled"}
STEP_STATUSES = {"pending", "running", "succeeded", "failed", "skipped"}


class Workflow(Base):
    __tablename__ = "workflows"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # Entity the workflow acts on: ticket | request | change.
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ticket")
    # Event that starts a run: ticket.created | ticket.updated |
    # ticket.priority_changed | sla_breach | request.created |
    # request.updated | change.created | change.updated | manual.
    trigger: Mapped[str] = mapped_column(String(40), nullable=False, server_default="manual")
    # draft | published | archived. Only published workflows run.
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    # Current step definition (the editable draft). Immutable snapshots
    # live in workflow_versions; runs pin a version id.
    steps: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workflow_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class WorkflowVersion(Base):
    __tablename__ = "workflow_versions"
    __table_args__ = (UniqueConstraint("workflow_id", "version_number", name="uq_workflow_version_number"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    # Immutable snapshot of the step list at publish/edit time.
    steps: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()


class WorkflowRun(Base):
    __tablename__ = "workflow_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workflow_versions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    triggered_by_id: Mapped[uuid.UUID | None] = _user_fk()
    # running | succeeded | failed | cancelled
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="running")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = tz_col(nullable=False)
    finished_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class WorkflowRunStep(Base):
    __tablename__ = "workflow_run_steps"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workflow_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    # pending | running | succeeded | failed | skipped
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    # What the step actually did (e.g. {"field": "priority", "value": "high"}).
    output: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = tz_col()
    finished_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Automation rules ---------------------------------------------------------

AUTOMATION_TRIGGERS = {
    "ticket.created",
    "ticket.updated",
    "ticket.priority_changed",
    "sla_breach",
}
AUTOMATION_ENTITY_TYPES = {"ticket"}
CONDITION_OPERATORS = {"eq", "ne", "in", "not_in", "is_null", "is_not_null"}
# Fields a rule condition may compare, per entity type.
CONDITION_FIELDS = {
    "ticket": {"status", "priority", "category", "assignee_id", "sla_breached"},
}
ACTION_TYPES = {"assign", "set_priority", "set_status", "add_comment", "notify"}


class AutomationRule(Base):
    __tablename__ = "automation_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # ticket.created | ticket.updated | ticket.priority_changed | sla_breach
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ticket")
    # [{"field": "priority", "operator": "eq", "value": "critical"}]
    conditions: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    # [{"type": "assign", "assignee_id": "<uuid>"}, ...]
    actions: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class AutomationRun(Base):
    __tablename__ = "automation_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("automation_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    # succeeded | failed | partial (some actions applied, some failed)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="succeeded")
    # [{"type": "assign", "status": "succeeded", "detail": {...}}, ...]
    # Only actions that actually ran appear here.
    actions_applied: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
