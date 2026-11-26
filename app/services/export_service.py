"""Data export generation: RLS-scoped queries rendered as CSV or JSON.

Exports are generated from the live database at request time. When S3
is configured the file is also stored (see :func:`store_export`);
when it is not, nothing is stored — ``GET /exports/{id}/download``
regenerates and streams the content on demand, so the download is
always real data from the database, never a stale stub.
"""

from __future__ import annotations

import csv
import io
import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.itsm import ServiceRequest
from app.models.platform import Membership, User
from app.models.ticket import Ticket
from app.services.storage import get_storage

EXPORT_TYPES = {"tickets", "requests", "users", "audit", "full"}
EXPORT_FORMATS = {"csv", "json"}

_COLUMNS = {
    "tickets": [
        "number",
        "title",
        "description",
        "status",
        "priority",
        "category",
        "requester_id",
        "assignee_id",
        "created_at",
    ],
    "requests": [
        "number",
        "title",
        "description",
        "status",
        "priority",
        "catalog_item_id",
        "requester_id",
        "assignee_id",
        "created_at",
    ],
    "users": ["email", "full_name", "status", "is_owner", "joined_at"],
    "audit": ["action", "actor_id", "resource_type", "resource_id", "outcome", "created_at"],
}


def _rows_for(session: Session, org_id: uuid.UUID, export_type: str) -> list[dict]:
    if export_type == "tickets":
        rows = session.execute(
            select(Ticket).where(Ticket.organization_id == org_id).order_by(Ticket.created_at)
        ).scalars()
        return [
            {
                "number": t.number,
                "title": t.title,
                "description": t.description,
                "status": t.status,
                "priority": t.priority,
                "category": t.category,
                "requester_id": str(t.requester_id) if t.requester_id else "",
                "assignee_id": str(t.assignee_id) if t.assignee_id else "",
                "created_at": t.created_at.isoformat() if t.created_at else "",
            }
            for t in rows
        ]
    if export_type == "requests":
        rows = session.execute(
            select(ServiceRequest).where(ServiceRequest.organization_id == org_id).order_by(ServiceRequest.created_at)
        ).scalars()
        return [
            {
                "number": r.number,
                "title": r.title,
                "description": r.description,
                "status": r.status,
                "priority": r.priority,
                "catalog_item_id": str(r.catalog_item_id) if r.catalog_item_id else "",
                "requester_id": str(r.requester_id) if r.requester_id else "",
                "assignee_id": str(r.assignee_id) if r.assignee_id else "",
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in rows
        ]
    if export_type == "users":
        rows = session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == org_id)
            .order_by(User.email)
        ).all()
        return [
            {
                "email": u.email,
                "full_name": u.full_name,
                "status": m.status,
                "is_owner": str(m.is_owner),
                "joined_at": m.created_at.isoformat() if m.created_at else "",
            }
            for m, u in rows
        ]
    if export_type == "audit":
        rows = session.execute(
            select(AuditLog).where(AuditLog.organization_id == org_id).order_by(AuditLog.created_at)
        ).scalars()
        return [
            {
                "action": a.action,
                "actor_id": str(a.actor_id) if a.actor_id else "",
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "outcome": a.outcome,
                "created_at": a.created_at.isoformat() if a.created_at else "",
            }
            for a in rows
        ]
    raise ValueError(f"unknown export_type: {export_type}")


def _to_csv(rows: list[dict], columns: list[str]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({c: row.get(c, "") for c in columns})
    return buf.getvalue()


def generate_export(session: Session, org_id: uuid.UUID, export_type: str, fmt: str) -> tuple[str, int]:
    """Render an export. Returns (content, row_count).

    ``full`` is JSON-only (it bundles four sections); ``full`` + CSV is
    rejected with ValueError rather than silently dropping sections.
    """
    if export_type not in EXPORT_TYPES:
        raise ValueError(f"unknown export_type: {export_type}")
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"unknown format: {fmt}")
    if export_type == "full":
        if fmt != "json":
            raise ValueError("full export requires JSON format")
        bundle = {section: _rows_for(session, org_id, section) for section in ("tickets", "requests", "users", "audit")}
        total = sum(len(v) for v in bundle.values())
        return json.dumps(bundle, indent=2, default=str), total
    rows = _rows_for(session, org_id, export_type)
    if fmt == "json":
        return json.dumps(rows, indent=2, default=str), len(rows)
    return _to_csv(rows, _COLUMNS[export_type]), len(rows)


def store_export(org_id: uuid.UUID, export_id: uuid.UUID, content: str, fmt: str) -> str | None:
    """Store export content in S3 when configured. Returns the key or None."""
    storage = get_storage()
    if not storage.configured:
        return None
    key = f"exports/{org_id}/{export_id}.{fmt}"
    storage._client.put_object(Bucket=storage.bucket, Key=key, Body=content.encode("utf-8"))
    return key
