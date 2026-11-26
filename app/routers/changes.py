"""Changes — Phase 2 ITSM engine.

Lifecycle: draft -> pending_approval -> approved -> scheduled ->
implementing -> implemented / failed -> rolled_back -> closed
(cancelled from any non-terminal state). Approval is one decision
per approver; a rejection sends the change back to draft for rework.
Tasks are the implementation checklist under a change.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.itsm import Change, ChangeApproval, ChangeTask
from app.services.itsm_service import get_org_row, next_change_number

router = APIRouter(prefix="/api/v1/changes", tags=["changes"])

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
RISKS = {"low", "medium", "high"}
PRIORITIES = {"low", "medium", "high", "critical"}
CHANGE_TYPES = {"standard", "normal", "emergency"}
# Allowed PATCH status moves (submit / approve / reject / execute /
# rollback have their own endpoints).
TRANSITIONS: dict[str, set[str]] = {
    "draft": {"cancelled"},
    "pending_approval": {"cancelled"},
    "approved": {"scheduled", "cancelled"},
    "scheduled": {"implementing", "cancelled"},
    "implementing": {"implemented", "failed", "rolled_back"},
    "implemented": {"closed", "rolled_back"},
    "failed": {"rolled_back", "closed"},
    "rolled_back": {"closed"},
    "closed": set(),
    "cancelled": set(),
}
TASK_STATUSES = {"pending", "in_progress", "done", "skipped"}


class ChangeCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    risk: str = "medium"
    priority: str = "medium"
    type: str = "normal"
    assignee_id: uuid.UUID | None = None
    implementation_window_start: datetime | None = None
    implementation_window_end: datetime | None = None
    rollback_plan: str = ""
    scheduled_at: datetime | None = None


class ChangeUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    description: str | None = None
    status: str | None = None
    risk: str | None = None
    priority: str | None = None
    type: str | None = None
    assignee_id: uuid.UUID | None = None
    implementation_window_start: datetime | None = None
    implementation_window_end: datetime | None = None
    rollback_plan: str | None = None
    scheduled_at: datetime | None = None


class DecisionBody(BaseModel):
    comment: str = ""


class ChangeOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    number: str
    title: str
    description: str
    status: str
    risk: str
    priority: str
    type: str
    requester_id: uuid.UUID | None
    assignee_id: uuid.UUID | None
    implementation_window_start: datetime | None
    implementation_window_end: datetime | None
    rollback_plan: str
    scheduled_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ApprovalOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    change_id: uuid.UUID
    approver_id: uuid.UUID | None
    status: str
    decision_at: datetime | None
    comment: str
    created_at: datetime
    updated_at: datetime


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    assignee_id: uuid.UUID | None = None
    sort_order: int = 0
    due_at: datetime | None = None


class TaskUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    description: str | None = None
    status: str | None = None
    assignee_id: uuid.UUID | None = None
    sort_order: int | None = None
    due_at: datetime | None = None


class TaskOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    change_id: uuid.UUID
    title: str
    description: str
    status: str
    assignee_id: uuid.UUID | None
    sort_order: int
    due_at: datetime | None
    created_at: datetime
    updated_at: datetime


def _out(c: Change) -> ChangeOut:
    return ChangeOut(
        id=c.id,
        organization_id=c.organization_id,
        number=c.number,
        title=c.title,
        description=c.description,
        status=c.status,
        risk=c.risk,
        priority=c.priority,
        type=c.type,
        requester_id=c.requester_id,
        assignee_id=c.assignee_id,
        implementation_window_start=c.implementation_window_start,
        implementation_window_end=c.implementation_window_end,
        rollback_plan=c.rollback_plan,
        scheduled_at=c.scheduled_at,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _approval_out(a: ChangeApproval) -> ApprovalOut:
    return ApprovalOut(
        id=a.id,
        organization_id=a.organization_id,
        change_id=a.change_id,
        approver_id=a.approver_id,
        status=a.status,
        decision_at=a.decision_at,
        comment=a.comment,
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


def _task_out(t: ChangeTask) -> TaskOut:
    return TaskOut(
        id=t.id,
        organization_id=t.organization_id,
        change_id=t.change_id,
        title=t.title,
        description=t.description,
        status=t.status,
        assignee_id=t.assignee_id,
        sort_order=t.sort_order,
        due_at=t.due_at,
        created_at=t.created_at,
        updated_at=t.updated_at,
    )


def _audit(session: Session, principal: Principal, action: str, change: Change, **meta) -> None:
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type="change",
        resource_id=str(change.id),
        outcome="success",
        metadata={"number": change.number, **meta},
    )


@router.get("", response_model=list[ChangeOut])
def list_changes(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("changes:read"))
):
    rows = session.execute(
        select(Change).where(Change.organization_id == principal.organization_id).order_by(Change.created_at.desc())
    ).scalars()
    return [_out(c) for c in rows]


@router.post("", response_model=ChangeOut, status_code=status.HTTP_201_CREATED)
def create_change(
    body: ChangeCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:create")),
):
    if body.risk not in RISKS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid risk")
    if body.priority not in PRIORITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
    if body.type not in CHANGE_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type")
    change = Change(
        organization_id=principal.organization_id,
        number=next_change_number(session, principal.organization_id),
        title=body.title,
        description=body.description,
        risk=body.risk,
        priority=body.priority,
        type=body.type,
        requester_id=principal.user_id,
        assignee_id=body.assignee_id,
        implementation_window_start=body.implementation_window_start,
        implementation_window_end=body.implementation_window_end,
        rollback_plan=body.rollback_plan,
        scheduled_at=body.scheduled_at,
        status="draft",
    )
    session.add(change)
    session.flush()
    _audit(session, principal, audit_mod.CHANGE_CREATED, change)
    out = _out(change)
    session.commit()
    return out


@router.get("/{change_id}", response_model=ChangeOut)
def get_change(
    change_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:read")),
):
    return _out(get_org_row(session, Change, change_id, principal.organization_id))


@router.patch("/{change_id}", response_model=ChangeOut)
def update_change(
    change_id: uuid.UUID,
    body: ChangeUpdate,
    session: Session = Depends(get_db),
    # No changes:update code exists; edits are gated on changes:create.
    principal: Principal = Depends(require_permission("changes:create")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    if body.status is not None:
        if body.status not in CHANGE_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        if body.status != change.status and body.status not in TRANSITIONS.get(change.status, set()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot move change from {change.status} to {body.status}",
            )
        change.status = body.status
    if body.risk is not None:
        if body.risk not in RISKS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid risk")
        change.risk = body.risk
    if body.priority is not None:
        if body.priority not in PRIORITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid priority")
        change.priority = body.priority
    if body.type is not None:
        if body.type not in CHANGE_TYPES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type")
        change.type = body.type
    if body.title is not None:
        change.title = body.title
    if body.description is not None:
        change.description = body.description
    if body.assignee_id is not None:
        change.assignee_id = body.assignee_id
    if body.implementation_window_start is not None:
        change.implementation_window_start = body.implementation_window_start
    if body.implementation_window_end is not None:
        change.implementation_window_end = body.implementation_window_end
    if body.rollback_plan is not None:
        change.rollback_plan = body.rollback_plan
    if body.scheduled_at is not None:
        change.scheduled_at = body.scheduled_at
    _audit(session, principal, audit_mod.CHANGE_UPDATED, change, status=change.status)
    session.flush()
    out = _out(change)
    session.commit()
    return out


@router.delete("/{change_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_change(
    change_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:create")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    session.delete(change)
    _audit(session, principal, audit_mod.CHANGE_UPDATED, change, deleted=True)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{change_id}/submit", response_model=ChangeOut)
def submit_change(
    change_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:create")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    if change.status != "draft":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot submit a change in status {change.status}"
        )
    change.status = "pending_approval"
    _audit(session, principal, audit_mod.CHANGE_UPDATED, change, status="pending_approval")
    session.flush()
    out = _out(change)
    session.commit()
    return out


def _decide(session: Session, principal: Principal, change: Change, decision: str, comment: str) -> ChangeApproval:
    if change.status != "pending_approval":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Change is not pending approval (status {change.status})"
        )
    existing = session.execute(
        select(ChangeApproval).where(
            ChangeApproval.change_id == change.id,
            ChangeApproval.approver_id == principal.user_id,
            ChangeApproval.status != "pending",
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This approver has already decided")
    approval = ChangeApproval(
        organization_id=principal.organization_id,
        change_id=change.id,
        approver_id=principal.user_id,
        status=decision,
        decision_at=datetime.now(timezone.utc),
        comment=comment,
    )
    session.add(approval)
    session.flush()
    return approval


@router.post("/{change_id}/approve", response_model=ChangeOut)
def approve_change(
    change_id: uuid.UUID,
    body: DecisionBody,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:approve")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    _decide(session, principal, change, "approved", body.comment)
    change.status = "approved"
    _audit(session, principal, audit_mod.CHANGE_APPROVED, change)
    session.flush()
    out = _out(change)
    session.commit()
    return out


@router.post("/{change_id}/reject", response_model=ChangeOut)
def reject_change(
    change_id: uuid.UUID,
    body: DecisionBody,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:approve")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    _decide(session, principal, change, "rejected", body.comment)
    # A rejected change goes back to draft for rework (there is no
    # "rejected" change status in the model).
    change.status = "draft"
    _audit(session, principal, audit_mod.CHANGE_REJECTED, change)
    session.flush()
    out = _out(change)
    session.commit()
    return out


@router.get("/{change_id}/approvals", response_model=list[ApprovalOut])
def list_approvals(
    change_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:read")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    rows = session.execute(
        select(ChangeApproval).where(ChangeApproval.change_id == change.id).order_by(ChangeApproval.created_at)
    ).scalars()
    return [_approval_out(a) for a in rows]


@router.post("/{change_id}/execute", response_model=ChangeOut)
def execute_change(
    change_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:execute")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    if change.status not in {"approved", "scheduled"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot execute a change in status {change.status}"
        )
    change.status = "implementing"
    _audit(session, principal, audit_mod.CHANGE_EXECUTED, change)
    session.flush()
    out = _out(change)
    session.commit()
    return out


@router.post("/{change_id}/rollback", response_model=ChangeOut)
def rollback_change(
    change_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:execute")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    if change.status not in {"implementing", "implemented", "failed"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot roll back a change in status {change.status}"
        )
    change.status = "rolled_back"
    _audit(session, principal, audit_mod.CHANGE_UPDATED, change, status="rolled_back")
    session.flush()
    out = _out(change)
    session.commit()
    return out


# --- Change tasks --------------------------------------------------------------


def _get_task(session: Session, principal: Principal, change_id: uuid.UUID, task_id: uuid.UUID) -> ChangeTask:
    change = get_org_row(session, Change, change_id, principal.organization_id)
    task = session.get(ChangeTask, task_id)
    if task is None or task.change_id != change.id or task.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return task


@router.get("/{change_id}/tasks", response_model=list[TaskOut])
def list_tasks(
    change_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:read")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    rows = session.execute(
        select(ChangeTask)
        .where(ChangeTask.change_id == change.id)
        .order_by(ChangeTask.sort_order, ChangeTask.created_at)
    ).scalars()
    return [_task_out(t) for t in rows]


@router.post("/{change_id}/tasks", response_model=TaskOut, status_code=status.HTTP_201_CREATED)
def create_task(
    change_id: uuid.UUID,
    body: TaskCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:create")),
):
    change = get_org_row(session, Change, change_id, principal.organization_id)
    task = ChangeTask(
        organization_id=principal.organization_id,
        change_id=change.id,
        title=body.title,
        description=body.description,
        assignee_id=body.assignee_id,
        sort_order=body.sort_order,
        due_at=body.due_at,
        status="pending",
    )
    session.add(task)
    session.flush()
    _audit(session, principal, audit_mod.CHANGE_UPDATED, change, task_created=str(task.id))
    out = _task_out(task)
    session.commit()
    return out


@router.get("/{change_id}/tasks/{task_id}", response_model=TaskOut)
def get_task(
    change_id: uuid.UUID,
    task_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:read")),
):
    return _task_out(_get_task(session, principal, change_id, task_id))


@router.patch("/{change_id}/tasks/{task_id}", response_model=TaskOut)
def update_task(
    change_id: uuid.UUID,
    task_id: uuid.UUID,
    body: TaskUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:create")),
):
    task = _get_task(session, principal, change_id, task_id)
    if body.status is not None:
        if body.status not in TASK_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        task.status = body.status
    if body.title is not None:
        task.title = body.title
    if body.description is not None:
        task.description = body.description
    if body.assignee_id is not None:
        task.assignee_id = body.assignee_id
    if body.sort_order is not None:
        task.sort_order = body.sort_order
    if body.due_at is not None:
        task.due_at = body.due_at
    session.flush()
    out = _task_out(task)
    session.commit()
    return out


@router.delete("/{change_id}/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(
    change_id: uuid.UUID,
    task_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("changes:create")),
):
    task = _get_task(session, principal, change_id, task_id)
    session.delete(task)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
