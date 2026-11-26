"""User-facing endpoint management (Phase 3, contract §9): enrollment
tokens, endpoint list/detail/inventory/jobs, rename, revocation, job
issuance, and the global agent-release catalog.

All routes require a user Bearer token + the named permission.
Cross-org access → 404 (never reveal another org's endpoints).
Every mutating route writes an audit row.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.audit import (
    AGENT_JOB_ISSUED,
    AGENT_RELEASE_CREATED,
    AGENT_RELEASE_DELETED,
    AGENT_RELEASE_UPDATED,
    ENDPOINT_ENROLLMENT_TOKEN_CREATED,
    ENDPOINT_ENROLLMENT_TOKEN_REVOKED,
    ENDPOINT_REVOKED,
    ENDPOINT_UPDATED,
)
from app.deps import Principal, get_db, get_principal, require_permission
from app.models.endpoints import AgentJob, AgentRelease, Endpoint, EndpointInventory, EnrollmentToken
from app.services import agent_service, endpoint_service

UTC = timezone.utc

router = APIRouter(prefix="/api/v1/endpoints", tags=["endpoints"])


ENDPOINT_STATUSES = {"enrolled", "online", "offline", "stale", "unenrolled"}


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class EnrollmentTokenCreate(BaseModel):
    expires_in_hours: int = 24


class EnrollmentTokenOut(BaseModel):
    id: uuid.UUID
    expires_at: datetime | None
    used_at: datetime | None
    used_endpoint_id: uuid.UUID | None
    revoked_at: datetime | None
    created_at: datetime


class EnrollmentTokenCreateOut(EnrollmentTokenOut):
    token: str


class EndpointOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    hostname: str
    display_name: str | None
    os_name: str | None
    os_version: str | None
    arch: str | None
    serial_number: str | None
    status: str
    agent_version: str | None
    ip_address: str | None
    last_seen_at: datetime | None
    enrolled_at: datetime | None
    created_at: datetime
    updated_at: datetime


class InventoryOut(BaseModel):
    id: uuid.UUID
    endpoint_id: uuid.UUID
    collected_at: datetime | None
    os: dict
    hardware: dict
    network: dict
    software: list
    services: list
    created_at: datetime


class EndpointDetailOut(EndpointOut):
    latest_inventory: InventoryOut | None = None


class JobOut(BaseModel):
    id: uuid.UUID
    endpoint_id: uuid.UUID
    organization_id: uuid.UUID
    type: str
    payload: dict
    status: str
    issued_by_id: uuid.UUID | None
    expires_at: datetime | None
    delivered_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    output: str | None
    error: str | None
    created_at: datetime
    updated_at: datetime


class EndpointUpdate(BaseModel):
    display_name: str | None = None
    hostname: str | None = None


class JobIssueRequest(BaseModel):
    type: str
    payload: dict = Field(default_factory=dict)
    expires_in_minutes: int = 60


class ReleaseCreate(BaseModel):
    version: str = Field(min_length=1, max_length=50)
    os: str = Field(min_length=1, max_length=50)
    arch: str = Field(min_length=1, max_length=50)
    sha256: str = Field(min_length=64, max_length=64)
    signature: str | None = None
    release_notes: str | None = None


class ReleaseUpdate(BaseModel):
    is_active: bool | None = None


class ReleaseOut(BaseModel):
    id: uuid.UUID
    version: str
    os: str
    arch: str
    sha256: str
    signature: str | None
    release_notes: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


# --- Helpers ----------------------------------------------------------------


def _token_out(row: EnrollmentToken) -> EnrollmentTokenOut:
    return EnrollmentTokenOut(
        id=row.id,
        expires_at=row.expires_at,
        used_at=row.used_at,
        used_endpoint_id=row.used_endpoint_id,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
    )


def _endpoint_out(e: Endpoint) -> EndpointOut:
    return EndpointOut(
        id=e.id,
        organization_id=e.organization_id,
        hostname=e.hostname,
        display_name=e.display_name,
        os_name=e.os_name,
        os_version=e.os_version,
        arch=e.arch,
        serial_number=e.serial_number,
        status=e.status,
        agent_version=e.agent_version,
        ip_address=e.ip_address,
        last_seen_at=e.last_seen_at,
        enrolled_at=e.enrolled_at,
        created_at=e.created_at,
        updated_at=e.updated_at,
    )


def _inventory_out(row: EndpointInventory) -> InventoryOut:
    return InventoryOut(
        id=row.id,
        endpoint_id=row.endpoint_id,
        collected_at=row.collected_at,
        os=row.os or {},
        hardware=row.hardware or {},
        network=row.network or {},
        software=row.software or [],
        services=row.services or [],
        created_at=row.created_at,
    )


def _job_out(job: AgentJob) -> JobOut:
    return JobOut(
        id=job.id,
        endpoint_id=job.endpoint_id,
        organization_id=job.organization_id,
        type=job.type,
        payload=job.payload or {},
        status=job.status,
        issued_by_id=job.issued_by_id,
        expires_at=job.expires_at,
        delivered_at=job.delivered_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        output=job.output,
        error=job.error,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


def _release_out(r: AgentRelease) -> ReleaseOut:
    return ReleaseOut(
        id=r.id,
        version=r.version,
        os=r.os,
        arch=r.arch,
        sha256=r.sha256,
        signature=r.signature,
        release_notes=r.release_notes,
        is_active=r.is_active,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _get_endpoint(session: Session, org_id: uuid.UUID, endpoint_id: uuid.UUID) -> Endpoint:
    endpoint = session.get(Endpoint, endpoint_id)
    if endpoint is None or endpoint.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    return endpoint


def _latest_inventory(session: Session, endpoint_id: uuid.UUID) -> EndpointInventory | None:
    return (
        session.execute(
            select(EndpointInventory)
            .where(EndpointInventory.endpoint_id == endpoint_id)
            .order_by(EndpointInventory.created_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


# --- Enrollment tokens (static routes first: before /{endpoint_id}) --------


@router.post("/enrollment-tokens", response_model=EnrollmentTokenCreateOut, status_code=status.HTTP_201_CREATED)
def create_enrollment_token(
    body: EnrollmentTokenCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:manage")),
):
    """Mint a one-time enrollment token. The raw token is returned ONCE;
    only its SHA-256 hash is stored."""
    try:
        row, raw = endpoint_service.create_enrollment_token(
            session, principal.organization_id, principal.user_id, body.expires_in_hours
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=ENDPOINT_ENROLLMENT_TOKEN_CREATED,
        resource_type="enrollment_token",
        resource_id=str(row.id),
        outcome="success",
        metadata={"expires_at": row.expires_at.isoformat() if row.expires_at else None},
    )
    out = EnrollmentTokenCreateOut(**_token_out(row).model_dump(), token=raw)
    session.commit()
    return out


@router.get("/enrollment-tokens", response_model=list[EnrollmentTokenOut])
def list_enrollment_tokens(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("endpoints:manage"))
):
    """List enrollment tokens. Hashes and raw tokens are never returned."""
    rows = (
        session.execute(
            select(EnrollmentToken)
            .where(EnrollmentToken.organization_id == principal.organization_id)
            .order_by(EnrollmentToken.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_token_out(r) for r in rows]


@router.post("/enrollment-tokens/{token_id}/revoke", response_model=EnrollmentTokenOut)
def revoke_enrollment_token(
    token_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:manage")),
):
    row = session.get(EnrollmentToken, token_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enrollment token not found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        session.flush()
        audit_mod.write_audit(
            session,
            organization_id=principal.organization_id,
            actor_id=principal.user_id,
            action=ENDPOINT_ENROLLMENT_TOKEN_REVOKED,
            resource_type="enrollment_token",
            resource_id=str(row.id),
            outcome="success",
            metadata={},
        )
    out = _token_out(row)
    session.commit()
    return out


# --- Agent releases (global catalog — no tenant data; static routes first) -


@router.get("/releases", response_model=list[ReleaseOut])
def list_releases(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("endpoints:read"))
):
    rows = session.execute(select(AgentRelease).order_by(AgentRelease.created_at.desc())).scalars().all()
    return [_release_out(r) for r in rows]


@router.post("/releases", response_model=ReleaseOut, status_code=status.HTTP_201_CREATED)
def create_release(
    body: ReleaseCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:manage")),
):
    release = AgentRelease(
        version=body.version,
        os=body.os,
        arch=body.arch,
        sha256=body.sha256,
        signature=body.signature,
        release_notes=body.release_notes,
        is_active=True,
    )
    session.add(release)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Release {body.version} for {body.os}/{body.arch} already exists",
        )
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=AGENT_RELEASE_CREATED,
        resource_type="agent_release",
        resource_id=str(release.id),
        outcome="success",
        metadata={"version": body.version, "os": body.os, "arch": body.arch},
    )
    out = _release_out(release)
    session.commit()
    return out


@router.patch("/releases/{release_id}", response_model=ReleaseOut)
def update_release(
    release_id: uuid.UUID,
    body: ReleaseUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:manage")),
):
    release = session.get(AgentRelease, release_id)
    if release is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Release not found")
    if body.is_active is not None:
        release.is_active = body.is_active
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=AGENT_RELEASE_UPDATED,
        resource_type="agent_release",
        resource_id=str(release.id),
        outcome="success",
        metadata={"is_active": release.is_active},
    )
    out = _release_out(release)
    session.commit()
    return out


@router.delete("/releases/{release_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_release(
    release_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:manage")),
):
    release = session.get(AgentRelease, release_id)
    if release is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Release not found")
    session.delete(release)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=AGENT_RELEASE_DELETED,
        resource_type="agent_release",
        resource_id=str(release.id),
        outcome="success",
        metadata={"version": release.version, "os": release.os, "arch": release.arch},
    )
    session.commit()
    return None


# --- Endpoints ---------------------------------------------------------------


@router.get("", response_model=list[EndpointOut])
def list_endpoints(
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:read")),
):
    if status_filter is not None and status_filter not in ENDPOINT_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid endpoint status")
    query = select(Endpoint).where(Endpoint.organization_id == principal.organization_id)
    if status_filter is not None:
        query = query.where(Endpoint.status == status_filter)
    if search:
        query = query.where(Endpoint.hostname.ilike(f"%{search}%"))
    rows = session.execute(query.order_by(Endpoint.created_at.desc())).scalars().all()
    return [_endpoint_out(e) for e in rows]


@router.get("/{endpoint_id}", response_model=EndpointDetailOut)
def get_endpoint(
    endpoint_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:read")),
):
    endpoint = _get_endpoint(session, principal.organization_id, endpoint_id)
    latest = _latest_inventory(session, endpoint_id)
    out = EndpointDetailOut(
        **_endpoint_out(endpoint).model_dump(),
        latest_inventory=_inventory_out(latest) if latest else None,
    )
    return out


@router.get("/{endpoint_id}/inventory", response_model=list[InventoryOut])
def list_endpoint_inventory(
    endpoint_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:read")),
):
    endpoint = _get_endpoint(session, principal.organization_id, endpoint_id)
    rows = (
        session.execute(
            select(EndpointInventory)
            .where(EndpointInventory.endpoint_id == endpoint.id)
            .order_by(EndpointInventory.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_inventory_out(r) for r in rows]


@router.get("/{endpoint_id}/jobs", response_model=list[JobOut])
def list_endpoint_jobs(
    endpoint_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:read")),
):
    endpoint = _get_endpoint(session, principal.organization_id, endpoint_id)
    rows = (
        session.execute(
            select(AgentJob).where(AgentJob.endpoint_id == endpoint.id).order_by(AgentJob.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_job_out(j) for j in rows]


@router.patch("/{endpoint_id}", response_model=EndpointOut)
def update_endpoint(
    endpoint_id: uuid.UUID,
    body: EndpointUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:modify")),
):
    endpoint = _get_endpoint(session, principal.organization_id, endpoint_id)
    if body.display_name is not None:
        endpoint.display_name = body.display_name
    if body.hostname is not None:
        endpoint.hostname = body.hostname
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=ENDPOINT_UPDATED,
        resource_type="endpoint",
        resource_id=str(endpoint.id),
        outcome="success",
        metadata={"hostname": endpoint.hostname},
    )
    out = _endpoint_out(endpoint)
    session.commit()
    return out


@router.post("/{endpoint_id}/revoke", response_model=EndpointOut)
def revoke_endpoint(
    endpoint_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("endpoints:manage")),
):
    endpoint = _get_endpoint(session, principal.organization_id, endpoint_id)
    try:
        endpoint_service.revoke_endpoint(session, endpoint)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=ENDPOINT_REVOKED,
        resource_type="endpoint",
        resource_id=str(endpoint.id),
        outcome="success",
        metadata={"hostname": endpoint.hostname},
    )
    out = _endpoint_out(endpoint)
    session.commit()
    return out


@router.post("/{endpoint_id}/jobs", response_model=JobOut, status_code=status.HTTP_201_CREATED)
def issue_job(
    endpoint_id: uuid.UUID,
    body: JobIssueRequest,
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    """Issue a job to one endpoint. Permission depends on the job type:
    scan types need ``endpoints:scan``, deploy types need
    ``endpoints:deploy``. The job is pending until the agent polls."""
    endpoint = _get_endpoint(session, principal.organization_id, endpoint_id)
    if body.type not in agent_service.JOB_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown job type: {body.type}")
    required = agent_service.JOB_TYPE_PERMISSIONS[body.type]
    if not principal.has(required):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {required}")
    try:
        job = endpoint_service.issue_job(
            session,
            org_id=principal.organization_id,
            endpoint=endpoint,
            job_type=body.type,
            payload=body.payload,
            expires_in_minutes=body.expires_in_minutes,
            issued_by_id=principal.user_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=AGENT_JOB_ISSUED,
        resource_type="agent_job",
        resource_id=str(job.id),
        outcome="success",
        metadata={"endpoint_id": str(endpoint.id), "type": body.type},
    )
    out = _job_out(job)
    session.commit()
    return out
