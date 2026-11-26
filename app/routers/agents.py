"""Agent API routes (Phase 3, contract §9): enrollment, heartbeats,
inventory, job polling/results, and update checks.

Authentication is device auth (``app.device_auth``): ``X-Device-Id`` +
``X-Device-Token``. No user Bearer token is consulted here, so a user
token 401s on every route in this router. Device tokens are scoped to
one device; the path device id must match the authenticated device.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.audit import AGENT_ENROLLED, AGENT_JOB_DELIVERED, AGENT_JOB_RESULT
from app.database import set_rls_context
from app.deps import get_db
from app.device_auth import DevicePrincipal, ensure_device_matches_path, get_device_principal
from app.models.endpoints import AgentJob, Endpoint, EndpointInventory
from app.services import agent_service

UTC = timezone.utc

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


# Inventory top-level sections (contract §9.4). Anything else → 422.
INVENTORY_SECTIONS = {"collected_at", "os", "hardware", "network", "software", "services"}

RESULT_STATUSES = {"succeeded", "failed", "rejected"}
CLOSED_JOB_STATUSES = {"succeeded", "failed", "rejected", "expired"}


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class DeviceInfo(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os: str = Field(min_length=1, max_length=100)
    os_version: str = Field(min_length=1, max_length=100)
    arch: str = Field(min_length=1, max_length=50)
    serial: str | None = Field(default=None, max_length=255)


class EnrollRequest(BaseModel):
    enrollment_token: str = Field(min_length=1)
    device: DeviceInfo


class HeartbeatRequest(BaseModel):
    status: str = "online"
    agent_version: str | None = Field(default=None, max_length=50)
    last_seen_at: datetime | None = None
    ip_address: str | None = Field(default=None, max_length=45)


class InventoryRequest(BaseModel):
    model_config = {"extra": "forbid"}

    collected_at: datetime | None = None
    os: dict = Field(default_factory=dict)
    hardware: dict = Field(default_factory=dict)
    network: dict = Field(default_factory=dict)
    software: list = Field(default_factory=list)
    services: list = Field(default_factory=list)


class JobResultRequest(BaseModel):
    status: str
    output: dict | list | str | None = None
    error: str | None = None
    started_at: datetime
    finished_at: datetime


# --- Helpers ----------------------------------------------------------------


def _get_endpoint(session: Session, device_id: uuid.UUID) -> Endpoint:
    endpoint = session.get(Endpoint, device_id)
    if endpoint is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")
    return endpoint


# --- Update check (defined before /{device_id} routes) ----------------------


@router.get("/updates/check")
def check_update(
    current_version: str = Query(min_length=1),
    os: str = Query(min_length=1),
    arch: str = Query(min_length=1),
    session: Session = Depends(get_db),
    device: DevicePrincipal = Depends(get_device_principal),
):
    """Newest ACTIVE release for (os, arch) newer than current_version.

    ``download_url`` is null: no artifact storage is configured, so no
    URL is invented. Per-device short-lived download URLs need the
    storage backend (Phase 5); an update offered here is therefore NOT
    installable yet — the agent must not claim otherwise.
    """
    release = agent_service.find_newer_release(session, current_version, os, arch)
    if release is None:
        return {"update_available": False}
    return {
        "update_available": True,
        "version": release["version"],
        "download_url": None,
        "sha256": release["sha256"],
        "signature": release.get("signature"),
        "release_notes": release.get("release_notes"),
    }


# --- Enrollment (no auth header: the enrollment token IS the credential) ---


@router.post("/enroll", status_code=status.HTTP_201_CREATED)
def enroll(body: EnrollRequest, session: Session = Depends(get_db)):
    """Exchange a one-time enrollment token for a device credential.

    The raw device token is returned ONCE and never again. The
    enrollment token is consumed atomically (UPDATE ... WHERE
    used_at IS NULL, rowcount checked) so two agents cannot enroll
    on one token.
    """
    token_hash = hashlib.sha256(body.enrollment_token.encode("utf-8")).hexdigest()
    row = (
        session.execute(text("SELECT * FROM auth_get_enrollment_token_by_hash(:h)"), {"h": token_hash})
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    now = datetime.now(UTC)
    if row.get("used_at") is not None or row.get("revoked_at") is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    if row.get("expires_at") is not None and row["expires_at"] <= now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    org_id = uuid.UUID(str(row["organization_id"]))
    token_id = uuid.UUID(str(row["id"]))

    # Client-generate the endpoint UUID BEFORE setting RLS context
    # (DECISIONS.md: SQLAlchemy applies the uuid default only at flush,
    # and INSERT ... RETURNING is checked against the SELECT policy).
    device_id = uuid.uuid4()
    set_rls_context(session, org_id, None)
    raw_device_token = secrets.token_urlsafe(32)
    endpoint = Endpoint(
        id=device_id,
        organization_id=org_id,
        hostname=body.device.hostname,
        os_name=body.device.os,
        os_version=body.device.os_version,
        arch=body.device.arch,
        serial_number=body.device.serial,
        status="enrolled",
        device_token_hash=hashlib.sha256(raw_device_token.encode("utf-8")).hexdigest(),
        enrolled_at=now,
    )
    session.add(endpoint)
    session.flush()
    # Atomic consume: only the first enrollment on this token wins.
    # (The endpoint row must exist first: used_endpoint_id is an FK.)
    consumed = session.execute(
        text(
            "UPDATE enrollment_tokens SET used_at = now(), used_endpoint_id = :eid WHERE id = :tid AND used_at IS NULL"
        ),
        {"eid": str(device_id), "tid": str(token_id)},
    )
    if (consumed.rowcount or 0) == 0:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=None,
        action=AGENT_ENROLLED,
        resource_type="endpoint",
        resource_id=str(device_id),
        outcome="success",
        metadata={"hostname": body.device.hostname},
    )
    out = {
        "device_id": str(device_id),
        "device_token": raw_device_token,
        "enrolled_organization_id": str(org_id),
    }
    session.commit()
    return out


# --- Heartbeat ---------------------------------------------------------------


@router.post("/{device_id}/heartbeat")
def heartbeat(
    device_id: uuid.UUID,
    body: HeartbeatRequest,
    session: Session = Depends(get_db),
    device: DevicePrincipal = Depends(get_device_principal),
):
    """Record a heartbeat. Carries NO inventory payload (§9.3)."""
    ensure_device_matches_path(device, device_id)
    if body.status != "online":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Heartbeat status must be 'online'")
    endpoint = _get_endpoint(session, device_id)
    now = datetime.now(UTC)
    agent_service.expire_pending_jobs(session, device_id, now)
    endpoint.last_seen_at = body.last_seen_at or now
    endpoint.agent_version = body.agent_version
    endpoint.ip_address = body.ip_address
    endpoint.status = "online"
    session.flush()
    pending = agent_service.pending_jobs_count(session, device_id)
    out = {"status": "ok", "server_time": now.isoformat(), "pending_jobs": pending}
    session.commit()
    return out


# --- Inventory ---------------------------------------------------------------


@router.post("/{device_id}/inventory", status_code=status.HTTP_201_CREATED)
def submit_inventory(
    device_id: uuid.UUID,
    body: InventoryRequest,
    session: Session = Depends(get_db),
    device: DevicePrincipal = Depends(get_device_principal),
):
    """Append one inventory submission (append-only history, §9.4).

    Unknown top-level sections are rejected with 422 by the schema
    (``extra="forbid"``), never silently dropped.
    """
    ensure_device_matches_path(device, device_id)
    _get_endpoint(session, device_id)
    now = datetime.now(UTC)
    row = EndpointInventory(
        organization_id=device.organization_id,
        endpoint_id=device_id,
        collected_at=body.collected_at,
        os=body.os,
        hardware=body.hardware,
        network=body.network,
        software=body.software,
        services=body.services,
    )
    session.add(row)
    session.flush()
    out = {
        "status": "ok",
        "inventory_id": str(row.id),
        "received_at": (row.created_at or now).isoformat(),
    }
    session.commit()
    return out


# --- Jobs --------------------------------------------------------------------


@router.get("/{device_id}/jobs/next")
def next_job(
    device_id: uuid.UUID,
    session: Session = Depends(get_db),
    device: DevicePrincipal = Depends(get_device_principal),
):
    """At-most-once delivery: the oldest pending, unexpired job is marked
    delivered and returned; a second poll returns ``{job: null}``. Jobs
    past ``expires_at`` are marked expired and never delivered."""
    ensure_device_matches_path(device, device_id)
    now = datetime.now(UTC)
    agent_service.expire_pending_jobs(session, device_id, now)
    job = (
        session.execute(
            select(AgentJob)
            .where(AgentJob.endpoint_id == device_id, AgentJob.status == "pending")
            .order_by(AgentJob.created_at.asc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if job is None:
        session.commit()
        return {"job": None}
    job.status = "delivered"
    job.delivered_at = now
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=device.organization_id,
        actor_id=None,
        action=AGENT_JOB_DELIVERED,
        resource_type="agent_job",
        resource_id=str(job.id),
        outcome="success",
        metadata={"endpoint_id": str(device_id), "type": job.type},
    )
    out = {
        "job": {
            "job_id": str(job.id),
            "type": job.type,
            "payload": job.payload or {},
            "issued_at": job.created_at.isoformat() if job.created_at else None,
            "expires_at": job.expires_at.isoformat() if job.expires_at else None,
        }
    }
    session.commit()
    return out


@router.post("/{device_id}/jobs/{job_id}/result")
def job_result(
    device_id: uuid.UUID,
    job_id: uuid.UUID,
    body: JobResultRequest,
    session: Session = Depends(get_db),
    device: DevicePrincipal = Depends(get_device_principal),
):
    """Close a job with the agent's result, then dispatch to the
    registered result handler (patching / vulnerability workstreams)."""
    ensure_device_matches_path(device, device_id)
    if body.status not in RESULT_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid job result status")
    job = session.get(AgentJob, job_id)
    if job is None or job.endpoint_id != device_id or job.organization_id != device.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    if job.status in CLOSED_JOB_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Job is already closed")
    job.status = body.status
    job.output = agent_service.serialize_job_output(body.output)
    job.error = body.error
    job.started_at = body.started_at
    job.finished_at = body.finished_at
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=device.organization_id,
        actor_id=None,
        action=AGENT_JOB_RESULT,
        resource_type="agent_job",
        resource_id=str(job.id),
        outcome="success",
        metadata={"endpoint_id": str(device_id), "type": job.type, "result": body.status},
    )
    # The result is recorded even when no handler is registered yet.
    agent_service.dispatch_job_result(session, device.organization_id, job)
    session.commit()
    return {"status": "ok"}
