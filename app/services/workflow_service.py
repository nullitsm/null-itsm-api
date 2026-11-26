"""Workflow designer service (migration 0014, Phase 4).

Workflows operate on REAL entities — tickets, service requests, and
changes — through the existing models and services. A step never
records an effect it did not perform: each step's outcome (or error)
is written to ``workflow_run_steps`` as it happens, and the run only
reports ``succeeded`` when every step succeeded.

Step types (validated by :func:`validate_steps`):

- ``{"type": "assign", "assignee_id": "<uuid>"}`` — set the assignee
  on a ticket / request / change (target must be a member of the org).
- ``{"type": "set_priority", "priority": "high"}`` — ticket/request/
  change priority (low | medium | high | critical).
- ``{"type": "set_status", "status": "in_progress"}`` — validated
  against the entity's real status set.
- ``{"type": "add_comment", "body": "...", "is_internal": true}`` —
  tickets only; creates a real ``ticket_comments`` row.
- ``{"type": "notify", "user_id": "<uuid>", "title": "...",
  "body": "..."}`` — creates a real in-app notification row.

``apply_action`` is the shared executor: the automation service calls
the same function, so a rule action and a workflow step do exactly
the same real thing.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.itsm import Change, ServiceRequest, TicketComment
from app.models.platform import Membership
from app.models.ticket import Ticket
from app.models.workflows import (
    ACTION_TYPES,
    WORKFLOW_ENTITY_TYPES,
    WORKFLOW_TRIGGERS,
    Workflow,
    WorkflowRun,
    WorkflowRunStep,
    WorkflowVersion,
)
from app.services.notification_service import create_notification

PRIORITIES = {"low", "medium", "high", "critical"}
TICKET_STATUSES = {"open", "in_progress", "pending", "resolved", "closed"}
REQUEST_STATUSES = {"submitted", "in_progress", "pending_approval", "approved", "fulfilled", "rejected", "cancelled"}
CHANGE_STATUSES = {
    "draft",
    "pending_approval",
    "approved",
    "scheduled",
    "implementing",
    "implemented",
    "failed",
    "rolled_back",
    "closed",
    "cancelled",
}
ENTITY_STATUSES = {
    "ticket": TICKET_STATUSES,
    "request": REQUEST_STATUSES,
    "change": CHANGE_STATUSES,
}
ENTITY_MODELS = {"ticket": Ticket, "request": ServiceRequest, "change": Change}
STEP_TYPES = ACTION_TYPES


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _not_found(detail: str = "Not found") -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def validate_steps(steps: object, entity_type: str) -> list[dict]:
    """Validate a step list for ``entity_type``; returns the normalized list.

    Raises 400 on any malformed step. ``add_comment`` is ticket-only —
    requests and changes have no comment table, so the step is rejected
    at design time rather than failing at run time.
    """
    if not isinstance(steps, list):
        raise _bad("steps must be a list")
    normalized: list[dict] = []
    for i, raw in enumerate(steps):
        if not isinstance(raw, dict):
            raise _bad(f"steps[{i}] must be an object")
        step_type = raw.get("type")
        if step_type not in STEP_TYPES:
            raise _bad(f"steps[{i}].type must be one of {sorted(STEP_TYPES)}")
        step = dict(raw)
        if step_type == "assign":
            if not raw.get("assignee_id"):
                raise _bad(f"steps[{i}].assignee_id is required")
            try:
                uuid.UUID(str(raw["assignee_id"]))
            except ValueError:
                raise _bad(f"steps[{i}].assignee_id must be a UUID")
        elif step_type == "set_priority":
            if raw.get("priority") not in PRIORITIES:
                raise _bad(f"steps[{i}].priority must be one of {sorted(PRIORITIES)}")
        elif step_type == "set_status":
            if raw.get("status") not in ENTITY_STATUSES[entity_type]:
                raise _bad(f"steps[{i}].status is not valid for {entity_type}")
        elif step_type == "add_comment":
            if entity_type != "ticket":
                raise _bad(f"steps[{i}]: add_comment is only supported for tickets")
            if not raw.get("body"):
                raise _bad(f"steps[{i}].body is required")
            step.setdefault("is_internal", True)
        elif step_type == "notify":
            if not raw.get("user_id") or not raw.get("title"):
                raise _bad(f"steps[{i}].user_id and steps[{i}].title are required")
            try:
                uuid.UUID(str(raw["user_id"]))
            except ValueError:
                raise _bad(f"steps[{i}].user_id must be a UUID")
        step.setdefault("name", step_type)
        normalized.append(step)
    return normalized


def load_entity(session: Session, org_id: uuid.UUID, entity_type: str, entity_id: uuid.UUID):
    """Load an org-scoped entity, or 404 (cross-org ids are 404, never 403)."""
    model = ENTITY_MODELS.get(entity_type)
    if model is None:
        raise _bad(f"Unknown entity_type: {entity_type}")
    row = session.get(model, entity_id)
    if row is None or row.organization_id != org_id:
        raise _not_found(f"{entity_type} not found")
    return row


def _require_member(session: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> None:
    member = session.execute(
        select(Membership).where(
            Membership.organization_id == org_id,
            Membership.user_id == user_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if member is None:
        raise _bad("Target user is not an active member of this organization")


def apply_action(
    session: Session,
    *,
    org_id: uuid.UUID,
    entity_type: str,
    entity_id: uuid.UUID,
    action: dict,
    actor_id: uuid.UUID | None,
) -> dict:
    """Apply ONE action to a real entity. Returns a detail dict of what ran.

    Raises HTTPException (400/404) when the action cannot be performed —
    nothing is recorded as done in that case. The caller commits.
    """
    action_type = action.get("type")
    if action_type not in ACTION_TYPES:
        raise _bad(f"Unknown action type: {action_type}")
    entity = load_entity(session, org_id, entity_type, entity_id)

    if action_type == "assign":
        assignee_id = uuid.UUID(str(action["assignee_id"]))
        _require_member(session, org_id, assignee_id)
        entity.assignee_id = assignee_id
        session.flush()
        return {"type": "assign", "field": "assignee_id", "value": str(assignee_id)}

    if action_type == "set_priority":
        priority = action["priority"]
        if priority not in PRIORITIES:
            raise _bad(f"Invalid priority: {priority}")
        entity.priority = priority
        session.flush()
        return {"type": "set_priority", "field": "priority", "value": priority}

    if action_type == "set_status":
        new_status = action["status"]
        if new_status not in ENTITY_STATUSES[entity_type]:
            raise _bad(f"Invalid status {new_status} for {entity_type}")
        entity.status = new_status
        session.flush()
        return {"type": "set_status", "field": "status", "value": new_status}

    if action_type == "add_comment":
        if entity_type != "ticket":
            raise _bad("add_comment is only supported for tickets")
        body = action.get("body") or ""
        if not body:
            raise _bad("add_comment body is required")
        comment = TicketComment(
            organization_id=org_id,
            ticket_id=entity.id,
            author_id=actor_id,
            body=body,
            is_internal=bool(action.get("is_internal", True)),
        )
        session.add(comment)
        session.flush()
        return {"type": "add_comment", "comment_id": str(comment.id)}

    if action_type == "notify":
        user_id = uuid.UUID(str(action["user_id"]))
        _require_member(session, org_id, user_id)
        title = action.get("title") or ""
        if not title:
            raise _bad("notify title is required")
        row = create_notification(
            session,
            organization_id=org_id,
            user_id=user_id,
            type="workflow",
            title=title,
            body=action.get("body") or "",
            resource_type=entity_type,
            resource_id=entity.id,
        )
        return {"type": "notify", "notification_id": str(row.id), "user_id": str(user_id)}

    raise _bad(f"Unknown action type: {action_type}")


# --- Workflow CRUD ------------------------------------------------------------


def create_workflow(
    session: Session,
    *,
    org_id: uuid.UUID,
    name: str,
    description: str,
    entity_type: str,
    trigger: str,
    steps: list[dict],
    created_by_id: uuid.UUID,
) -> Workflow:
    if entity_type not in WORKFLOW_ENTITY_TYPES:
        raise _bad(f"entity_type must be one of {sorted(WORKFLOW_ENTITY_TYPES)}")
    if trigger not in WORKFLOW_TRIGGERS:
        raise _bad(f"trigger must be one of {sorted(WORKFLOW_TRIGGERS)}")
    steps = validate_steps(steps, entity_type)
    workflow = Workflow(
        organization_id=org_id,
        name=name,
        description=description,
        entity_type=entity_type,
        trigger=trigger,
        status="draft",
        steps=steps,
        created_by_id=created_by_id,
    )
    session.add(workflow)
    session.flush()
    version = WorkflowVersion(
        organization_id=org_id,
        workflow_id=workflow.id,
        version_number=1,
        steps=steps,
        created_by_id=created_by_id,
    )
    session.add(version)
    session.flush()
    workflow.current_version_id = version.id
    session.flush()
    return workflow


def snapshot_version(
    session: Session, *, org_id: uuid.UUID, workflow: Workflow, actor_id: uuid.UUID
) -> WorkflowVersion:
    """Create the next immutable version snapshot for ``workflow``."""
    last = session.execute(
        select(WorkflowVersion.version_number)
        .where(WorkflowVersion.workflow_id == workflow.id)
        .order_by(WorkflowVersion.version_number.desc())
        .limit(1)
    ).scalar_one_or_none()
    version = WorkflowVersion(
        organization_id=org_id,
        workflow_id=workflow.id,
        version_number=(last or 0) + 1,
        steps=list(workflow.steps),
        created_by_id=actor_id,
    )
    session.add(version)
    session.flush()
    workflow.current_version_id = version.id
    session.flush()
    return version


def update_workflow(
    session: Session,
    *,
    workflow: Workflow,
    actor_id: uuid.UUID,
    name: str | None = None,
    description: str | None = None,
    steps: list[dict] | None = None,
) -> Workflow:
    """Edit a workflow. Any step change snapshots a new version row."""
    if name is not None:
        workflow.name = name
    if description is not None:
        workflow.description = description
    if steps is not None:
        workflow.steps = validate_steps(steps, workflow.entity_type)
        snapshot_version(session, org_id=workflow.organization_id, workflow=workflow, actor_id=actor_id)
    session.flush()
    return workflow


def publish_workflow(session: Session, *, workflow: Workflow) -> Workflow:
    """Draft -> published. Runs pin the current version; a workflow with
    no steps cannot be published (it would run nothing)."""
    if workflow.status == "archived":
        raise _bad("An archived workflow cannot be published")
    if not workflow.steps:
        raise _bad("A workflow with no steps cannot be published")
    workflow.status = "published"
    session.flush()
    return workflow


def archive_workflow(session: Session, *, workflow: Workflow) -> Workflow:
    workflow.status = "archived"
    session.flush()
    return workflow


# --- Execution ----------------------------------------------------------------


def _step_display(step: dict) -> str:
    name = step.get("name") or step.get("type") or "step"
    return str(name)


def execute_workflow(
    session: Session,
    *,
    org_id: uuid.UUID,
    workflow: Workflow,
    entity_type: str,
    entity_id: uuid.UUID,
    triggered_by_id: uuid.UUID | None,
) -> WorkflowRun:
    """Run a published workflow against a real entity.

    The run pins the workflow's current version. Steps execute in order
    against the real entity; the first failure stops the run (later
    steps stay ``pending``) so a partial run never claims more than it
    did. The caller commits.
    """
    if workflow.status != "published":
        raise _bad("Only a published workflow can run")
    if entity_type != workflow.entity_type:
        raise _bad(f"This workflow acts on {workflow.entity_type}, not {entity_type}")
    # The entity must exist in this org before any step is recorded.
    load_entity(session, org_id, entity_type, entity_id)
    version = session.get(WorkflowVersion, workflow.current_version_id) if workflow.current_version_id else None
    if version is None:
        raise _bad("Workflow has no version to run")

    run = WorkflowRun(
        organization_id=org_id,
        workflow_id=workflow.id,
        version_id=version.id,
        version_number=version.version_number,
        entity_type=entity_type,
        entity_id=entity_id,
        triggered_by_id=triggered_by_id,
        status="running",
        started_at=_now(),
    )
    session.add(run)
    session.flush()

    step_rows: list[WorkflowRunStep] = []
    for index, step in enumerate(version.steps):
        row = WorkflowRunStep(
            organization_id=org_id,
            run_id=run.id,
            step_index=index,
            name=_step_display(step),
            status="pending",
        )
        session.add(row)
        step_rows.append(row)
    session.flush()

    failure: str | None = None
    for index, step in enumerate(version.steps):
        row = step_rows[index]
        row.status = "running"
        row.started_at = _now()
        session.flush()
        try:
            detail = apply_action(
                session,
                org_id=org_id,
                entity_type=entity_type,
                entity_id=entity_id,
                action=step,
                actor_id=triggered_by_id,
            )
        except HTTPException as exc:
            row.status = "failed"
            row.error = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            row.finished_at = _now()
            failure = row.error
            session.flush()
            break
        row.status = "succeeded"
        row.output = detail
        row.finished_at = _now()
        session.flush()

    run.status = "failed" if failure else "succeeded"
    run.error = failure
    run.finished_at = _now()
    session.flush()
    return run


def retry_run(session: Session, *, run: WorkflowRun, actor_id: uuid.UUID | None) -> WorkflowRun:
    """Retry a failed run: succeeded steps are skipped, failed and
    pending steps re-execute in order against the real entity. A run
    that is not failed cannot be retried."""
    if run.status != "failed":
        raise _bad(f"Only a failed run can be retried (run status is {run.status})")
    workflow = session.get(Workflow, run.workflow_id)
    if workflow is None:
        raise _not_found("Workflow not found")
    version = session.get(WorkflowVersion, run.version_id) if run.version_id else None
    if version is None:
        raise _bad("Run has no pinned version to retry")
    # The entity must still exist in this org.
    load_entity(session, run.organization_id, run.entity_type, run.entity_id)

    run.status = "running"
    run.error = None
    run.finished_at = None
    session.flush()

    step_rows = (
        session.execute(
            select(WorkflowRunStep).where(WorkflowRunStep.run_id == run.id).order_by(WorkflowRunStep.step_index)
        )
        .scalars()
        .all()
    )
    steps = list(version.steps)

    failure: str | None = None
    for index, step in enumerate(steps):
        if index >= len(step_rows):
            break
        row = step_rows[index]
        if row.status == "succeeded":
            continue
        row.status = "running"
        row.started_at = _now()
        row.error = None
        session.flush()
        try:
            detail = apply_action(
                session,
                org_id=run.organization_id,
                entity_type=run.entity_type,
                entity_id=run.entity_id,
                action=step,
                actor_id=actor_id,
            )
        except HTTPException as exc:
            row.status = "failed"
            row.error = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            row.finished_at = _now()
            failure = row.error
            session.flush()
            break
        row.status = "succeeded"
        row.output = detail
        row.finished_at = _now()
        session.flush()

    run.status = "failed" if failure else "succeeded"
    run.error = failure
    run.finished_at = _now()
    session.flush()
    return run
