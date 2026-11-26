"""Device authentication for the agent API (Phase 3, contract §9.2).

Agent requests authenticate with ``X-Device-Id`` + ``X-Device-Token`` —
no user Bearer token. The credential row is resolved through the
SECURITY DEFINER function ``auth_get_endpoint_by_device_token``
(migration 0009), the same pattern as the SCIM token lookup: the
function runs before any RLS context exists, matches the SHA-256 hash
exactly, and never enumerates. The session is then RLS-scoped to the
org returned by the function — never to a client-supplied org id.

A device token confers NO user permissions: user endpoints require a
Bearer JWT (``get_principal``), so a device token alone 401s there.
Conversely a user Bearer token 401s on every agent endpoint because
these routes never consult it — they require the device headers.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import set_rls_context
from app.deps import get_db
from app.models.endpoints import Endpoint

UTC = timezone.utc


def hash_device_token(raw: str) -> str:
    """SHA-256 hex of a raw device token (only the hash is ever stored)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class DevicePrincipal:
    """The authenticated device, with its enrolled organization."""

    device_id: uuid.UUID
    organization_id: uuid.UUID
    hostname: str
    status: str


def resolve_device_by_token(session: Session, device_id: uuid.UUID, raw_token: str) -> dict | None:
    """Resolve (device_id, token) via the SECURITY DEFINER function.

    Returns the function row as a dict, or None when the id/token pair
    does not match exactly. Works before any RLS context exists.
    """
    row = (
        session.execute(
            text("SELECT * FROM auth_get_endpoint_by_device_token(:id, :h)"),
            {"id": str(device_id), "h": hash_device_token(raw_token)},
        )
        .mappings()
        .first()
    )
    return dict(row) if row is not None else None


def get_device_principal(request: Request, session: Session = Depends(get_db)) -> DevicePrincipal:
    """Authenticate an agent request from X-Device-Id / X-Device-Token.

    Wrong, unknown, or revoked token → 401, with no enumeration detail.
    On success the session is RLS-scoped to the device's org.
    """
    device_id_raw = request.headers.get("X-Device-Id", "").strip()
    raw_token = request.headers.get("X-Device-Token", "").strip()
    if not device_id_raw or not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")
    try:
        device_id = uuid.UUID(device_id_raw)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")
    row = resolve_device_by_token(session, device_id, raw_token)
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")
    if row.get("token_revoked_at") is not None or row.get("status") == "unenrolled":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")
    org_id = uuid.UUID(str(row["organization_id"]))
    # Org comes from the function result, never from the client.
    set_rls_context(session, org_id, None)
    endpoint = session.get(Endpoint, device_id)
    if endpoint is not None:
        endpoint.token_last_used_at = datetime.now(UTC)
        session.flush()
    return DevicePrincipal(
        device_id=device_id,
        organization_id=org_id,
        hostname=row.get("hostname") or "",
        status=row.get("status") or "",
    )


def ensure_device_matches_path(principal: DevicePrincipal, path_device_id: uuid.UUID) -> None:
    """Device tokens are scoped to one device: a token for device A used
    with device B's id in the path → 401."""
    if principal.device_id != path_device_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")
