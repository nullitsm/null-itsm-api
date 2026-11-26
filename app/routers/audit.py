"""Audit log routes — READ-ONLY. There is deliberately no update or
delete endpoint for audit records, anywhere in the API.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import Principal, get_db, require_permission
from app.models.audit import AuditLog
from app.schemas import AuditLogOut

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    action: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("audit:read")),
):
    stmt = (
        select(AuditLog)
        .where(AuditLog.organization_id == principal.organization_id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    rows = session.execute(stmt).scalars()
    return [
        AuditLogOut(
            id=r.id,
            organization_id=r.organization_id,
            actor_id=r.actor_id,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            outcome=r.outcome,
            metadata=r.meta,
            created_at=r.created_at,
        )
        for r in rows
    ]
