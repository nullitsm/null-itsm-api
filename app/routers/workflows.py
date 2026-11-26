"""Workflows + automation rules — Phase 4 workstream A.

Prefix ``/api/v1/workflows``. All endpoints are org-scoped and gated
by ``automation:read`` / ``automation:manage`` (the Organization
Administrator role holds both via ``*``).

Workflows: a designer CRUDs a workflow (name, entity type, trigger,
steps); every create and every step edit snapshots an immutable
version; publishing flips draft -> published; a run executes the
pinned version against a real ticket/request/change and records
per-step history; a failed run can be retried.

Automation rules: trigger -> conditions -> actions, evaluated against
a real event through ``POST /automation-rules/evaluate`` (the ticket
and SLA routers will call the same evaluation at integration). Only
rules whose conditions match the real entity fire, and each firing
writes an ``automation_runs`` row recording exactly what ran.

Audit actions use the centralized constants in ``app/audit.py``
(e.g. ``audit_mod.WORKFLOW_CREATED``).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.workflows import (
    AutomationRule,
    AutomationRun,
    Workflow,
    WorkflowRun,
    WorkflowRunStep,
    WorkflowVersion,
)
from app.services import automation_service, workflow_service
from app.services.itsm_service import get_org_row

router = APIRouter(prefix="/api/v1/workflows", tags=["workflows"])

READ = "automation:read"
MANAGE = "automation:manage"


# --- Pydantic models (local to this router; schemas.py is coordinator-owned) ---


class WorkflowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    entity_type: str = "ticket"
    trigger: str = "manual"
    steps: list[dict] = Field(default_factory=list)


class WorkflowUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    steps: list[dict] | None = None


class WorkflowOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    entity_type: str
    trigger: str
    status: str
    steps: list[dict]
    current_version_id: uuid.UUID | None
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class WorkflowVersionOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    workflow_id: uuid.UUID
    version_number: int
    steps: list[dict]
    created_by_id: uuid.UUID | None
    created_at: datetime


class WorkflowRunStepOut(BaseModel):
    id: uuid.UUID
    step_index: int
    name: str
    status: str
    output: dict
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class WorkflowRunOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    workflow_id: uuid.UUID
    version_id: uuid.UUID | None
    version_number: int
    entity_type: str
    entity_id: uuid.UUID
    triggered_by_id: uuid.UUID | None
    status: str
    error: str | None
    started_at: datetime
    finished_at: datetime | None
    steps: list[WorkflowRunStepOut] = Field(default_factory=list)


class WorkflowRunCreate(BaseModel):
    entity_type: str
    entity_id: uuid.UUID


class AutomationRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    trigger: str
    entity_type: str = "ticket"
    conditions: list[dict] = Field(default_factory=list)
    actions: list[dict] = Field(default_factory=list)
    is_enabled: bool = True


class AutomationRuleUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    trigger: str | None = None
    conditions: list[dict] | None = None
    actions: list[dict] | None = None
    is_enabled: bool | None = None


class AutomationRuleOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    trigger: str
    entity_type: str
    conditions: list[dict]
    actions: list[dict]
    is_enabled: bool
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class AutomationRunOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    rule_id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    trigger: str
    status: str
    actions_applied: list[dict]
    error: str | None
    created_at: datetime


class EvaluateBody(BaseModel):
    trigger: str
    entity_type: str
    entity_id: uuid.UUID


class EvaluateOut(BaseModel):
    evaluated_rules: int
    fired: int
    runs: list[AutomationRunOut]


# --- Serializers ----------------------------------------------------------------


def _workflow_out(w: Workflow) -> WorkflowOut:
    return WorkflowOut(
        id=w.id,
        organization_id=w.organization_id,
        name=w.name,
        description=w.description,
        entity_type=w.entity_type,
        trigger=w.trigger,
        status=w.status,
        steps=list(w.steps or []),
        current_version_id=w.current_version_id,
        created_by_id=w.created_by_id,
        created_at=w.created_at,
        updated_at=w.updated_at,
    )


def _version_out(v: WorkflowVersion) -> WorkflowVersionOut:
    return WorkflowVersionOut(
        id=v.id,
        organization_id=v.organization_id,
        workflow_id=v.workflow_id,
        version_number=v.version_number,
        steps=list(v.steps or []),
        created_by_id=v.created_by_id,
        created_at=v.created_at,
    )


def _run_steps(session: Session, run_id: uuid.UUID) -> list[WorkflowRunStepOut]:
    rows = (
        session.execute(
            select(WorkflowRunStep).where(WorkflowRunStep.run_id == run_id).order_by(WorkflowRunStep.step_index)
        )
        .scalars()
        .all()
    )
    return [
        WorkflowRunStepOut(
            id=r.id,
            step_index=r.step_index,
            name=r.name,
            status=r.status,
            output=dict(r.output or {}),
            error=r.error,
            started_at=r.started_at,
            finished_at=r.finished_at,
        )
        for r in rows
    ]


def _run_out(session: Session, run: WorkflowRun) -> WorkflowRunOut:
    return WorkflowRunOut(
        id=run.id,
        organization_id=run.organization_id,
        workflow_id=run.workflow_id,
        version_id=run.version_id,
        version_number=run.version_number,
        entity_type=run.entity_type,
        entity_id=run.entity_id,
        triggered_by_id=run.triggered_by_id,
        status=run.status,
        error=run.error,
        started_at=run.started_at,
        finished_at=run.finished_at,
        steps=_run_steps(session, run.id),
    )


def _rule_out(r: AutomationRule) -> AutomationRuleOut:
    return AutomationRuleOut(
        id=r.id,
        organization_id=r.organization_id,
        name=r.name,
        description=r.description,
        trigger=r.trigger,
        entity_type=r.entity_type,
        conditions=list(r.conditions or []),
        actions=list(r.actions or []),
        is_enabled=r.is_enabled,
        created_by_id=r.created_by_id,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _automation_run_out(r: AutomationRun) -> AutomationRunOut:
    return AutomationRunOut(
        id=r.id,
        organization_id=r.organization_id,
        rule_id=r.rule_id,
        entity_type=r.entity_type,
        entity_id=r.entity_id,
        trigger=r.trigger,
        status=r.status,
        actions_applied=list(r.actions_applied or []),
        error=r.error,
        created_at=r.created_at,
    )


def _audit(session: Session, principal: Principal, action: str, resource_type: str, resource_id: str, **meta) -> None:
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="success",
        metadata=meta,
    )


# --- Workflows ------------------------------------------------------------------


@router.get("", response_model=list[WorkflowOut])
def list_workflows(session: Session = Depends(get_db), principal: Principal = Depends(require_permission(READ))):
    rows = session.execute(
        select(Workflow)
        .where(Workflow.organization_id == principal.organization_id)
        .order_by(Workflow.created_at.desc())
    ).scalars()
    return [_workflow_out(w) for w in rows]


@router.post("", response_model=WorkflowOut, status_code=status.HTTP_201_CREATED)
def create_workflow(
    body: WorkflowCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    workflow = workflow_service.create_workflow(
        session,
        org_id=principal.organization_id,
        name=body.name,
        description=body.description,
        entity_type=body.entity_type,
        trigger=body.trigger,
        steps=body.steps,
        created_by_id=principal.user_id,
    )
    _audit(session, principal, audit_mod.WORKFLOW_CREATED, "workflow", str(workflow.id), name=workflow.name)
    out = _workflow_out(workflow)
    session.commit()
    return out


@router.get("/{workflow_id}", response_model=WorkflowOut)
def get_workflow(
    workflow_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(READ)),
):
    return _workflow_out(get_org_row(session, Workflow, workflow_id, principal.organization_id))


@router.patch("/{workflow_id}", response_model=WorkflowOut)
def update_workflow(
    workflow_id: uuid.UUID,
    body: WorkflowUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    if workflow.status == "archived":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="An archived workflow cannot be edited")
    workflow_service.update_workflow(
        session,
        workflow=workflow,
        actor_id=principal.user_id,
        name=body.name,
        description=body.description,
        steps=body.steps,
    )
    _audit(session, principal, audit_mod.WORKFLOW_UPDATED, "workflow", str(workflow.id), name=workflow.name)
    out = _workflow_out(workflow)
    session.commit()
    return out


@router.delete("/{workflow_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_workflow(
    workflow_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    session.delete(workflow)
    _audit(session, principal, audit_mod.WORKFLOW_DELETED, "workflow", str(workflow.id), name=workflow.name)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{workflow_id}/publish", response_model=WorkflowOut)
def publish_workflow(
    workflow_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    workflow_service.publish_workflow(session, workflow=workflow)
    _audit(session, principal, audit_mod.WORKFLOW_PUBLISHED, "workflow", str(workflow.id), name=workflow.name)
    out = _workflow_out(workflow)
    session.commit()
    return out


@router.post("/{workflow_id}/archive", response_model=WorkflowOut)
def archive_workflow(
    workflow_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    workflow_service.archive_workflow(session, workflow=workflow)
    _audit(session, principal, audit_mod.WORKFLOW_ARCHIVED, "workflow", str(workflow.id), name=workflow.name)
    out = _workflow_out(workflow)
    session.commit()
    return out


@router.get("/{workflow_id}/versions", response_model=list[WorkflowVersionOut])
def list_versions(
    workflow_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(READ)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    rows = session.execute(
        select(WorkflowVersion)
        .where(WorkflowVersion.workflow_id == workflow.id)
        .order_by(WorkflowVersion.version_number)
    ).scalars()
    return [_version_out(v) for v in rows]


@router.get("/{workflow_id}/versions/{version_id}", response_model=WorkflowVersionOut)
def get_version(
    workflow_id: uuid.UUID,
    version_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(READ)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    version = session.get(WorkflowVersion, version_id)
    if version is None or version.workflow_id != workflow.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return _version_out(version)


@router.post("/{workflow_id}/run", response_model=WorkflowRunOut, status_code=status.HTTP_201_CREATED)
def run_workflow(
    workflow_id: uuid.UUID,
    body: WorkflowRunCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    run = workflow_service.execute_workflow(
        session,
        org_id=principal.organization_id,
        workflow=workflow,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        triggered_by_id=principal.user_id,
    )
    _audit(
        session,
        principal,
        audit_mod.WORKFLOW_RUN_STARTED,
        "workflow_run",
        str(run.id),
        workflow_id=str(workflow.id),
        status=run.status,
    )
    out = _run_out(session, run)
    session.commit()
    return out


@router.get("/{workflow_id}/runs", response_model=list[WorkflowRunOut])
def list_workflow_runs(
    workflow_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(READ)),
):
    workflow = get_org_row(session, Workflow, workflow_id, principal.organization_id)
    rows = (
        session.execute(
            select(WorkflowRun).where(WorkflowRun.workflow_id == workflow.id).order_by(WorkflowRun.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_run_out(session, r) for r in rows]


# --- Workflow runs (run-scoped) -------------------------------------------------


@router.get("/runs/{run_id}", response_model=WorkflowRunOut)
def get_run(
    run_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(READ)),
):
    return _run_out(session, get_org_row(session, WorkflowRun, run_id, principal.organization_id))


@router.post("/runs/{run_id}/retry", response_model=WorkflowRunOut)
def retry_run(
    run_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    run = get_org_row(session, WorkflowRun, run_id, principal.organization_id)
    workflow_service.retry_run(session, run=run, actor_id=principal.user_id)
    _audit(
        session,
        principal,
        audit_mod.WORKFLOW_RUN_RETRIED,
        "workflow_run",
        str(run.id),
        workflow_id=str(run.workflow_id),
        status=run.status,
    )
    out = _run_out(session, run)
    session.commit()
    return out


# --- Automation rules ------------------------------------------------------------

# Static sub-routes first: POST /automation-rules/evaluate must not be
# captured by /automation-rules/{rule_id}.


@router.post("/automation-rules/evaluate", response_model=EvaluateOut)
def evaluate_automation(
    body: EvaluateBody,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    runs = automation_service.evaluate_rules(
        session,
        org_id=principal.organization_id,
        trigger=body.trigger,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        actor_id=principal.user_id,
    )
    total = (
        session.execute(
            select(AutomationRule).where(
                AutomationRule.organization_id == principal.organization_id,
                AutomationRule.trigger == body.trigger,
                AutomationRule.entity_type == body.entity_type,
                AutomationRule.is_enabled.is_(True),
            )
        )
        .scalars()
        .all()
    )
    _audit(
        session,
        principal,
        audit_mod.AUTOMATION_RULE_EVALUATED,
        "automation_rule",
        str(body.entity_id),
        trigger=body.trigger,
        evaluated=len(total),
        fired=len(runs),
    )
    out = EvaluateOut(evaluated_rules=len(total), fired=len(runs), runs=[_automation_run_out(r) for r in runs])
    session.commit()
    return out


@router.get("/automation-rules", response_model=list[AutomationRuleOut])
def list_rules(session: Session = Depends(get_db), principal: Principal = Depends(require_permission(READ))):
    rows = session.execute(
        select(AutomationRule)
        .where(AutomationRule.organization_id == principal.organization_id)
        .order_by(AutomationRule.created_at.desc())
    ).scalars()
    return [_rule_out(r) for r in rows]


@router.post("/automation-rules", response_model=AutomationRuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(
    body: AutomationRuleCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    rule = automation_service.create_rule(
        session,
        org_id=principal.organization_id,
        name=body.name,
        description=body.description,
        trigger=body.trigger,
        entity_type=body.entity_type,
        conditions=body.conditions,
        actions=body.actions,
        is_enabled=body.is_enabled,
        created_by_id=principal.user_id,
    )
    _audit(session, principal, audit_mod.AUTOMATION_RULE_CREATED, "automation_rule", str(rule.id), name=rule.name)
    out = _rule_out(rule)
    session.commit()
    return out


@router.get("/automation-rules/{rule_id}", response_model=AutomationRuleOut)
def get_rule(
    rule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(READ)),
):
    return _rule_out(get_org_row(session, AutomationRule, rule_id, principal.organization_id))


@router.patch("/automation-rules/{rule_id}", response_model=AutomationRuleOut)
def update_rule(
    rule_id: uuid.UUID,
    body: AutomationRuleUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    rule = get_org_row(session, AutomationRule, rule_id, principal.organization_id)
    automation_service.update_rule(
        session,
        rule=rule,
        name=body.name,
        description=body.description,
        trigger=body.trigger,
        conditions=body.conditions,
        actions=body.actions,
        is_enabled=body.is_enabled,
    )
    _audit(session, principal, audit_mod.AUTOMATION_RULE_UPDATED, "automation_rule", str(rule.id), name=rule.name)
    out = _rule_out(rule)
    session.commit()
    return out


@router.delete("/automation-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(MANAGE)),
):
    rule = get_org_row(session, AutomationRule, rule_id, principal.organization_id)
    session.delete(rule)
    _audit(session, principal, audit_mod.AUTOMATION_RULE_DELETED, "automation_rule", str(rule.id), name=rule.name)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/automation-rules/{rule_id}/runs", response_model=list[AutomationRunOut])
def list_rule_runs(
    rule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(READ)),
):
    rule = get_org_row(session, AutomationRule, rule_id, principal.organization_id)
    rows = session.execute(
        select(AutomationRun).where(AutomationRun.rule_id == rule.id).order_by(AutomationRun.created_at.desc())
    ).scalars()
    return [_automation_run_out(r) for r in rows]


@router.get("/automation-runs", response_model=list[AutomationRunOut])
def list_automation_runs(session: Session = Depends(get_db), principal: Principal = Depends(require_permission(READ))):
    rows = session.execute(
        select(AutomationRun)
        .where(AutomationRun.organization_id == principal.organization_id)
        .order_by(AutomationRun.created_at.desc())
    ).scalars()
    return [_automation_run_out(r) for r in rows]
