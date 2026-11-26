"""Data imports: ServiceNow / Jira / generic CSV (imports:manage).

Imports run synchronously in-request and return the final summary.
Re-running an import (``POST /imports/{id}/reprocess``) skips records
already marked ``imported`` — see app/services/import_service.py.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import Principal, get_db, require_permission
from app.models.email_portal import DataImport, ImportRecord
from app.services.import_service import create_import, process_import

router = APIRouter(prefix="/api/v1/imports", tags=["imports"])


class ImportCreate(BaseModel):
    source_system: str
    rows: list[dict] = Field(default_factory=list)


class ImportRecordOut(BaseModel):
    id: uuid.UUID
    source_id: str
    target_type: str
    target_id: uuid.UUID | None
    status: str
    error: str | None


class ImportOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    source_system: str
    status: str
    total_rows: int
    processed_rows: int
    error_rows: int
    summary: dict
    requested_by_id: uuid.UUID
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    records: list[ImportRecordOut] | None = None


def _import_out(row: DataImport, records: list[ImportRecord] | None = None) -> ImportOut:
    return ImportOut(
        id=row.id,
        organization_id=row.organization_id,
        source_system=row.source_system,
        status=row.status,
        total_rows=row.total_rows,
        processed_rows=row.processed_rows,
        error_rows=row.error_rows,
        summary=row.summary or {},
        requested_by_id=row.requested_by_id,
        started_at=row.started_at,
        completed_at=row.completed_at,
        created_at=row.created_at,
        records=(
            [
                ImportRecordOut(
                    id=r.id,
                    source_id=r.source_id,
                    target_type=r.target_type,
                    target_id=r.target_id,
                    status=r.status,
                    error=r.error,
                )
                for r in records
            ]
            if records is not None
            else None
        ),
    )


def _get_import(session: Session, org_id: uuid.UUID, import_id: uuid.UUID) -> DataImport:
    row = session.get(DataImport, import_id)
    if row is None or row.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Import not found")
    return row


def _records(session: Session, import_id: uuid.UUID) -> list[ImportRecord]:
    return list(
        session.execute(
            select(ImportRecord).where(ImportRecord.import_id == import_id).order_by(ImportRecord.created_at)
        ).scalars()
    )


@router.post("", response_model=ImportOut, status_code=status.HTTP_201_CREATED)
def run_import(
    body: ImportCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("imports:manage")),
):
    try:
        import_row = create_import(session, principal.organization_id, principal.user_id, body.source_system, body.rows)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    records = _records(session, import_row.id)
    out = _import_out(import_row, records)
    session.commit()
    return out


@router.get("", response_model=list[ImportOut])
def list_imports(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("imports:read"))
):
    rows = session.execute(
        select(DataImport)
        .where(DataImport.organization_id == principal.organization_id)
        .order_by(DataImport.created_at.desc())
    ).scalars()
    return [_import_out(r) for r in rows]


@router.get("/{import_id}", response_model=ImportOut)
def get_import(
    import_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("imports:read")),
):
    row = _get_import(session, principal.organization_id, import_id)
    return _import_out(row, _records(session, row.id))


@router.post("/{import_id}/reprocess", response_model=ImportOut)
def reprocess_import(
    import_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("imports:manage")),
):
    """Re-run an import: already-imported records are skipped."""
    row = _get_import(session, principal.organization_id, import_id)
    process_import(session, row, principal.user_id)
    out = _import_out(row, _records(session, row.id))
    session.commit()
    return out
