"""User-facing endpoint service logic (Phase 3).

Owns the pieces the ``/api/v1/endpoints`` router needs that are not
HTTP concerns: enrollment-token minting (raw token shown once, only
its SHA-256 hash stored), job issuance against the §9.5 allowlist, and
endpoint revocation.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.endpoints import AgentJob, Endpoint, EnrollmentToken
from app.services.agent_service import JOB_TYPES

UTC = timezone.utc

MAX_ENROLLMENT_TOKEN_HOURS = 168


def hash_token(raw: str) -> str:
    """SHA-256 hex of a raw token (only the hash is ever stored)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_raw_token() -> str:
    """A fresh opaque token, shown once at creation and never again."""
    return secrets.token_urlsafe(32)


def create_enrollment_token(
    session: Session, org_id: uuid.UUID, created_by_id: uuid.UUID, expires_in_hours: int
) -> tuple[EnrollmentToken, str]:
    """Mint a one-time enrollment token. Returns (row, raw token)."""
    if expires_in_hours < 1 or expires_in_hours > MAX_ENROLLMENT_TOKEN_HOURS:
        raise ValueError(f"expires_in_hours must be between 1 and {MAX_ENROLLMENT_TOKEN_HOURS}")
    raw = new_raw_token()
    row = EnrollmentToken(
        organization_id=org_id,
        token_hash=hash_token(raw),
        created_by_id=created_by_id,
        expires_at=datetime.now(UTC) + timedelta(hours=expires_in_hours),
    )
    session.add(row)
    session.flush()
    return row, raw


def issue_job(
    session: Session,
    *,
    org_id: uuid.UUID,
    endpoint: Endpoint,
    job_type: str,
    payload: dict | None,
    expires_in_minutes: int,
    issued_by_id: uuid.UUID,
) -> AgentJob:
    """Issue a job to one endpoint. Unknown types are rejected (400).

    The job is pending until the agent polls ``/jobs/next``; the server
    never initiates a connection to a device.
    """
    if job_type not in JOB_TYPES:
        raise ValueError(f"Unknown job type: {job_type}")
    if expires_in_minutes < 1:
        raise ValueError("expires_in_minutes must be at least 1")
    job = AgentJob(
        organization_id=org_id,
        endpoint_id=endpoint.id,
        type=job_type,
        payload=payload or {},
        status="pending",
        issued_by_id=issued_by_id,
        expires_at=datetime.now(UTC) + timedelta(minutes=expires_in_minutes),
    )
    session.add(job)
    session.flush()
    return job


def revoke_endpoint(session: Session, endpoint: Endpoint) -> Endpoint:
    """Revoke a device credential: token revoked, status → unenrolled.

    Raises ValueError when the endpoint is already unenrolled.
    """
    if endpoint.status == "unenrolled":
        raise ValueError("Endpoint is already unenrolled")
    endpoint.token_revoked_at = datetime.now(UTC)
    endpoint.status = "unenrolled"
    session.flush()
    return endpoint
