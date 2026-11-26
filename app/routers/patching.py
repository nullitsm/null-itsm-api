"""Patching routes: scan results, missing patches, deployments, verification.

Permissions: ``patching:read`` / ``patching:deploy`` / ``patching:approve``,
plus ``endpoints:scan`` to trigger a patch scan. Cross-org access returns
404 (never reveals another org's rows). Every mutating endpoint writes an
audit row.

Scan results themselves arrive through workstream A's agent job-result
endpoint, which lazily calls
``app.services.patching_service.apply_patch_scan_result`` /
``apply_patch_deploy_result``. This router only issues the jobs and reads
the resulting state — it never claims a patch was installed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.audit import (
    PATCHING_DEPLOYMENT_APPROVED,
    PATCHING_DEPLOYMENT_CANCELLED,
    PATCHING_DEPLOYMENT_CREATED,
    PATCHING_DEPLOYMENT_EXECUTED,
    PATCHING_DEPLOYMENT_VERIFIED,
    PATCHING_SCAN_CREATED,
)
from app.deps import Principal, get_db, require_permission
from app.models.endpoints import AgentJob, Endpoint
from app.models.patching import (
    Patch,
    PatchDeployment,
    PatchDeploymentItem,
    PatchFinding,
    PatchScan,
)

UTC = timezone.utc
JOB_TTL = timedelta(minutes=60)

router = APIRouter(prefix="/api/v1/patching", tags=["patching"])


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class PatchOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    vendor: str | None
    kb_id: str | None
    severity: str
    category: str | None
    description: str | None
    cve_ids: list
    os_family: str | None
    release_date: datetime | None
    created_at: datetime
    updated_at: datetime


class PatchFindingOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    endpoint_id: uuid.UUID
    patch_id: uuid.UUID
    patch_title: str | None = None
    patch_kb_id: str | None = None
    patch_severity: str | None = None
    scan_id: uuid.UUID | None
    status: str
    detected_at: datetime | None
    installed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class PatchScanOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    endpoint_id: uuid.UUID
    job_id: uuid.UUID | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    missing_count: int
    created_at: datetime
    updated_at: datetime


class PatchScanDetailOut(PatchScanOut):
    findings: list[PatchFindingOut] = []


class ScanCreate(BaseModel):
    endpoint_id: uuid.UUID


class DeploymentItemCreate(BaseModel):
    endpoint_id: uuid.UUID
    patch_id: uuid.UUID


class DeploymentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    items: list[DeploymentItemCreate] = Field(min_length=1)
    scheduled_at: datetime | None = None


class DeploymentItemOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    deployment_id: uuid.UUID
    endpoint_id: uuid.UUID
    patch_id: uuid.UUID
    job_id: uuid.UUID | None
    status: str
    result: str | None
    created_at: datetime
    updated_at: datetime


class DeploymentOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    status: str
    scheduled_at: datetime | None
    approved_by_id: uuid.UUID | None
    approved_at: datetime | None
    created_by_id: uuid.UUID | None
    verification_scan_id: uuid.UUID | None
    verification_status: str | None
    created_at: datetime
    updated_at: datetime


class DeploymentDetailOut(DeploymentOut):
    items: list[DeploymentItemOut] = []


# --- Helpers ----------------------------------------------------------------


def _patch_out(p: Patch) -> PatchOut:
    return PatchOut(
        id=p.id,
        organization_id=p.organization_id,
        title=p.title,
        vendor=p.vendor,
        kb_id=p.kb_id,
        severity=p.severity,
        category=p.category,
        description=p.description,
        cve_ids=p.cve_ids or [],
        os_family=p.os_family,
        release_date=p.release_date,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


def _finding_out(f: PatchFinding, patch: Patch | None = None) -> PatchFindingOut:
    return PatchFindingOut(
        id=f.id,
        organization_id=f.organization_id,
        endpoint_id=f.endpoint_id,
        patch_id=f.patch_id,
        patch_title=patch.title if patch else None,
        patch_kb_id=patch.kb_id if patch else None,
        patch_severity=patch.severity if patch else None,
        scan_id=f.scan_id,
        status=f.status,
        detected_at=f.detected_at,
        installed_at=f.installed_at,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


def _finding_outs(session: Session, findings: list[PatchFinding]) -> list[PatchFindingOut]:
    patch_ids = {f.patch_id for f in findings}
    patches = {}
    if patch_ids:
        patches = {p.id: p for p in session.execute(select(Patch).where(Patch.id.in_(patch_ids))).scalars().all()}
    return [_finding_out(f, patches.get(f.patch_id)) for f in findings]


def _scan_out(s: PatchScan) -> PatchScanOut:
    return PatchScanOut(
        id=s.id,
        organization_id=s.organization_id,
        endpoint_id=s.endpoint_id,
        job_id=s.job_id,
        status=s.status,
        started_at=s.started_at,
        finished_at=s.finished_at,
        missing_count=s.missing_count,
        created_at=s.created_at,
        updated_at=s.updated_at,
    )


def _scan_detail_out(session: Session, s: PatchScan) -> PatchScanDetailOut:
    findings = (
        session.execute(
            select(PatchFinding).where(PatchFinding.scan_id == s.id).order_by(PatchFinding.created_at.desc())
        )
        .scalars()
        .all()
    )
    out = _scan_out(s)
    return PatchScanDetailOut(**out.model_dump(), findings=_finding_outs(session, findings))


def _item_out(item: PatchDeploymentItem) -> DeploymentItemOut:
    return DeploymentItemOut(
        id=item.id,
        organization_id=item.organization_id,
        deployment_id=item.deployment_id,
        endpoint_id=item.endpoint_id,
        patch_id=item.patch_id,
        job_id=item.job_id,
        status=item.status,
        result=item.result,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def _deployment_out(d: PatchDeployment) -> DeploymentOut:
    return DeploymentOut(
        id=d.id,
        organization_id=d.organization_id,
        name=d.name,
        status=d.status,
        scheduled_at=d.scheduled_at,
        approved_by_id=d.approved_by_id,
        approved_at=d.approved_at,
        created_by_id=d.created_by_id,
        verification_scan_id=d.verification_scan_id,
        verification_status=d.verification_status,
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


def _deployment_detail_out(session: Session, d: PatchDeployment) -> DeploymentDetailOut:
    items = (
        session.execute(
            select(PatchDeploymentItem)
            .where(PatchDeploymentItem.deployment_id == d.id)
            .order_by(PatchDeploymentItem.created_at)
        )
        .scalars()
        .all()
    )
    out = _deployment_out(d)
    return DeploymentDetailOut(**out.model_dump(), items=[_item_out(i) for i in items])


def _get_endpoint(session: Session, org_id: uuid.UUID, endpoint_id: uuid.UUID) -> Endpoint:
    endpoint = session.get(Endpoint, endpoint_id)
    if endpoint is None or endpoint.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    return endpoint


def _get_patch(session: Session, org_id: uuid.UUID, patch_id: uuid.UUID) -> Patch:
    patch = session.get(Patch, patch_id)
    if patch is None or patch.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patch not found")
    return patch


def _get_deployment(session: Session, org_id: uuid.UUID, deployment_id: uuid.UUID) -> PatchDeployment:
    deployment = session.get(PatchDeployment, deployment_id)
    if deployment is None or deployment.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    return deployment


def _create_job(
    session: Session,
    org_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    job_type: str,
    payload: dict,
    issued_by_id: uuid.UUID,
) -> AgentJob:
    job = AgentJob(
        id=uuid.uuid4(),
        organization_id=org_id,
        endpoint_id=endpoint_id,
        type=job_type,
        payload=payload,
        status="pending",
        issued_by_id=issued_by_id,
        expires_at=datetime.now(UTC) + JOB_TTL,
    )
    session.add(job)
    session.flush()
    return job


def _audit(
    session: Session,
    principal: Principal,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID,
    metadata: dict | None = None,
) -> None:
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        outcome="success",
        metadata=metadata or {},
    )


# --- Patches ----------------------------------------------------------------


@router.get("/patches", response_model=list[PatchOut])
def list_patches(
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:read")),
):
    stmt = select(Patch).where(Patch.organization_id == principal.organization_id)
    if severity is not None:
        stmt = stmt.where(Patch.severity == severity)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(or_(Patch.title.ilike(like), Patch.kb_id.ilike(like)))
    rows = session.execute(stmt.order_by(Patch.created_at.desc())).scalars().all()
    return [_patch_out(p) for p in rows]


@router.get("/patches/{patch_id}", response_model=PatchOut)
def get_patch(
    patch_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:read")),
):
    return _patch_out(_get_patch(session, principal.organization_id, patch_id))


# --- Findings ---------------------------------------------------------------


@router.get("/findings", response_model=list[PatchFindingOut])
def list_findings(
    endpoint_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:read")),
):
    stmt = (
        select(PatchFinding, Patch)
        .join(Patch, Patch.id == PatchFinding.patch_id)
        .where(PatchFinding.organization_id == principal.organization_id)
    )
    if endpoint_id is not None:
        stmt = stmt.where(PatchFinding.endpoint_id == endpoint_id)
    if status is not None:
        stmt = stmt.where(PatchFinding.status == status)
    if severity is not None:
        stmt = stmt.where(Patch.severity == severity)
    rows = session.execute(stmt.order_by(PatchFinding.created_at.desc())).all()
    return [_finding_out(f, p) for f, p in rows]


# --- Scans ------------------------------------------------------------------


@router.get("/scans", response_model=list[PatchScanOut])
def list_scans(
    endpoint_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:read")),
):
    stmt = select(PatchScan).where(PatchScan.organization_id == principal.organization_id)
    if endpoint_id is not None:
        stmt = stmt.where(PatchScan.endpoint_id == endpoint_id)
    if status is not None:
        stmt = stmt.where(PatchScan.status == status)
    rows = session.execute(stmt.order_by(PatchScan.created_at.desc())).scalars().all()
    return [_scan_out(s) for s in rows]


@router.get("/scans/{scan_id}", response_model=PatchScanDetailOut)
def get_scan(
    scan_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:read")),
):
    scan = session.get(PatchScan, scan_id)
    if scan is None or scan.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_detail_out(session, scan)


@router.post("/scans", response_model=PatchScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    body: ScanCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:scan")),
):
    _get_endpoint(session, principal.organization_id, body.endpoint_id)
    job = _create_job(
        session,
        principal.organization_id,
        body.endpoint_id,
        "patch_scan",
        {},
        principal.user_id,
    )
    scan = PatchScan(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        endpoint_id=body.endpoint_id,
        job_id=job.id,
        status="pending",
    )
    session.add(scan)
    session.flush()
    _audit(
        session,
        principal,
        PATCHING_SCAN_CREATED,
        "patch_scan",
        scan.id,
        {"endpoint_id": str(body.endpoint_id), "job_id": str(job.id)},
    )
    out = _scan_out(scan)
    session.commit()
    return out


# --- Deployments ------------------------------------------------------------


@router.get("/deployments", response_model=list[DeploymentOut])
def list_deployments(
    status: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:read")),
):
    stmt = select(PatchDeployment).where(PatchDeployment.organization_id == principal.organization_id)
    if status is not None:
        stmt = stmt.where(PatchDeployment.status == status)
    rows = session.execute(stmt.order_by(PatchDeployment.created_at.desc())).scalars().all()
    return [_deployment_out(d) for d in rows]


@router.post("/deployments", response_model=DeploymentDetailOut, status_code=status.HTTP_201_CREATED)
def create_deployment(
    body: DeploymentCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:deploy")),
):
    for item in body.items:
        _get_endpoint(session, principal.organization_id, item.endpoint_id)
        _get_patch(session, principal.organization_id, item.patch_id)
    now = datetime.now(UTC)
    dep_status = "scheduled" if body.scheduled_at is not None and body.scheduled_at > now else "draft"
    deployment = PatchDeployment(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        name=body.name,
        status=dep_status,
        scheduled_at=body.scheduled_at,
        created_by_id=principal.user_id,
    )
    session.add(deployment)
    session.flush()
    items: list[PatchDeploymentItem] = []
    for item in body.items:
        row = PatchDeploymentItem(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            deployment_id=deployment.id,
            endpoint_id=item.endpoint_id,
            patch_id=item.patch_id,
            status="pending",
        )
        session.add(row)
        items.append(row)
    session.flush()
    _audit(
        session,
        principal,
        PATCHING_DEPLOYMENT_CREATED,
        "patch_deployment",
        deployment.id,
        {"name": body.name, "status": dep_status, "item_count": len(items)},
    )
    out = _deployment_detail_out(session, deployment)
    session.commit()
    return out


@router.get("/deployments/{deployment_id}", response_model=DeploymentDetailOut)
def get_deployment(
    deployment_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:read")),
):
    return _deployment_detail_out(session, _get_deployment(session, principal.organization_id, deployment_id))


@router.post("/deployments/{deployment_id}/approve", response_model=DeploymentDetailOut)
def approve_deployment(
    deployment_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:approve")),
):
    deployment = _get_deployment(session, principal.organization_id, deployment_id)
    if deployment.status not in ("draft", "scheduled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve a deployment in status '{deployment.status}'",
        )
    deployment.status = "approved"
    deployment.approved_by_id = principal.user_id
    deployment.approved_at = datetime.now(UTC)
    session.flush()
    _audit(session, principal, PATCHING_DEPLOYMENT_APPROVED, "patch_deployment", deployment.id)
    out = _deployment_detail_out(session, deployment)
    session.commit()
    return out


@router.post("/deployments/{deployment_id}/execute", response_model=DeploymentDetailOut)
def execute_deployment(
    deployment_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:deploy")),
):
    deployment = _get_deployment(session, principal.organization_id, deployment_id)
    if deployment.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot execute a deployment in status '{deployment.status}'",
        )
    items = (
        session.execute(
            select(PatchDeploymentItem)
            .where(PatchDeploymentItem.deployment_id == deployment.id)
            .order_by(PatchDeploymentItem.created_at)
        )
        .scalars()
        .all()
    )
    for item in items:
        job = _create_job(
            session,
            principal.organization_id,
            item.endpoint_id,
            "patch_deploy",
            {"patch_id": str(item.patch_id)},
            principal.user_id,
        )
        item.job_id = job.id
        item.status = "queued"
    deployment.status = "deploying"
    session.flush()
    _audit(
        session,
        principal,
        PATCHING_DEPLOYMENT_EXECUTED,
        "patch_deployment",
        deployment.id,
        {"item_count": len(items)},
    )
    out = _deployment_detail_out(session, deployment)
    session.commit()
    return out


@router.post("/deployments/{deployment_id}/cancel", response_model=DeploymentDetailOut)
def cancel_deployment(
    deployment_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:deploy")),
):
    deployment = _get_deployment(session, principal.organization_id, deployment_id)
    if deployment.status not in ("draft", "scheduled", "approved"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel a deployment in status '{deployment.status}'",
        )
    deployment.status = "cancelled"
    session.flush()
    _audit(session, principal, PATCHING_DEPLOYMENT_CANCELLED, "patch_deployment", deployment.id)
    out = _deployment_detail_out(session, deployment)
    session.commit()
    return out


@router.post("/deployments/{deployment_id}/verify", response_model=DeploymentDetailOut)
def verify_deployment(
    deployment_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("patching:deploy")),
):
    deployment = _get_deployment(session, principal.organization_id, deployment_id)
    if deployment.status not in ("deploying", "completed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot verify a deployment in status '{deployment.status}'",
        )
    items = (
        session.execute(
            select(PatchDeploymentItem)
            .where(PatchDeploymentItem.deployment_id == deployment.id)
            .order_by(PatchDeploymentItem.created_at)
        )
        .scalars()
        .all()
    )
    endpoint_ids: list[uuid.UUID] = []
    for item in items:
        if item.endpoint_id not in endpoint_ids:
            endpoint_ids.append(item.endpoint_id)
    first_scan_id: uuid.UUID | None = None
    for endpoint_id in endpoint_ids:
        job = _create_job(
            session,
            principal.organization_id,
            endpoint_id,
            "patch_scan",
            {},
            principal.user_id,
        )
        scan = PatchScan(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            endpoint_id=endpoint_id,
            job_id=job.id,
            status="pending",
        )
        session.add(scan)
        session.flush()
        if first_scan_id is None:
            first_scan_id = scan.id
    deployment.verification_scan_id = first_scan_id
    deployment.verification_status = "pending"
    session.flush()
    _audit(
        session,
        principal,
        PATCHING_DEPLOYMENT_VERIFIED,
        "patch_deployment",
        deployment.id,
        {"verification_scan_id": str(first_scan_id) if first_scan_id else None},
    )
    out = _deployment_detail_out(session, deployment)
    session.commit()
    return out
