"""Data exports: tickets / requests / users / audit / full (exports:manage).

Exports generate from the live database at request time. When S3 is
configured the file is also stored; when it is not, ``download``
regenerates and streams the content on demand — always real data.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.email_portal import DataExport
from app.services.export_service import generate_export, store_export

router = APIRouter(prefix="/api/v1/exports", tags=["exports"])

logger = logging.getLogger("null.exports")


class ExportCreate(BaseModel):
    export_type: str
    format: str = "csv"


class ExportOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    export_type: str
    format: str
    status: str
    storage_key: str | None
    row_count: int
    requested_by_id: uuid.UUID
    completed_at: datetime | None
    created_at: datetime


def _export_out(row: DataExport) -> ExportOut:
    return ExportOut(
        id=row.id,
        organization_id=row.organization_id,
        export_type=row.export_type,
        format=row.format,
        status=row.status,
        storage_key=row.storage_key,
        row_count=row.row_count,
        requested_by_id=row.requested_by_id,
        completed_at=row.completed_at,
        created_at=row.created_at,
    )


def _get_export(session: Session, org_id: uuid.UUID, export_id: uuid.UUID) -> DataExport:
    row = session.get(DataExport, export_id)
    if row is None or row.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export not found")
    return row


@router.post("", response_model=ExportOut, status_code=status.HTTP_201_CREATED)
def create_export(
    body: ExportCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("exports:manage")),
):
    export_row = DataExport(
        organization_id=principal.organization_id,
        export_type=body.export_type,
        format=body.format,
        status="running",
        requested_by_id=principal.user_id,
    )
    session.add(export_row)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.EXPORT_CREATED,
        resource_type="export",
        resource_id=str(export_row.id),
        outcome="success",
        metadata={"export_type": body.export_type, "format": body.format},
    )
    try:
        content, row_count = generate_export(session, principal.organization_id, body.export_type, body.format)
    except ValueError as exc:
        export_row.status = "failed"
        session.flush()
        out = _export_out(export_row)
        session.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    try:
        export_row.storage_key = store_export(principal.organization_id, export_row.id, content, body.format)
    except Exception as exc:  # storage failure must not lose the export: download regenerates
        logger.warning("Export %s: S3 store failed (%s); download will regenerate", export_row.id, exc)
        export_row.storage_key = None
    export_row.status = "completed"
    export_row.row_count = row_count
    export_row.completed_at = datetime.now(timezone.utc)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.EXPORT_COMPLETED,
        resource_type="export",
        resource_id=str(export_row.id),
        outcome="success",
        metadata={"export_type": body.export_type, "format": body.format, "row_count": row_count},
    )
    out = _export_out(export_row)
    session.commit()
    return out


@router.get("", response_model=list[ExportOut])
def list_exports(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("exports:read"))
):
    rows = session.execute(
        select(DataExport)
        .where(DataExport.organization_id == principal.organization_id)
        .order_by(DataExport.created_at.desc())
    ).scalars()
    return [_export_out(r) for r in rows]


@router.get("/{export_id}", response_model=ExportOut)
def get_export(
    export_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("exports:read")),
):
    return _export_out(_get_export(session, principal.organization_id, export_id))


@router.get("/{export_id}/download")
def download_export(
    export_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("exports:read")),
):
    """Regenerate the export from the live database and stream it.

    Always real data: a ticket created after the export was requested
    appears in the download.
    """
    export_row = _get_export(session, principal.organization_id, export_id)
    try:
        content, _ = generate_export(session, principal.organization_id, export_row.export_type, export_row.format)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    media_type = "text/csv" if export_row.format == "csv" else "application/json"
    filename = f"{export_row.export_type}-{export_row.id}.{export_row.format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
