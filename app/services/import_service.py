"""Data import engine: ServiceNow / Jira / generic CSV mapping profiles.

Imports run synchronously in-request (small payloads) and are idempotent:
re-running the same import (same import_id) skips ``import_records``
already marked ``imported``. Imported users are created with an
``invited`` membership plus an ``invitations`` row — the existing
invitation flow, not a second invite path. The raw token is never
stored (only its hash); the invitation email is sent via the email
service (dev: logged).
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.config import get_settings
from app.database import as_uuid, set_rls_context
from app.models.auth import Invitation, InvitationRole
from app.models.email_portal import DataImport, ImportRecord
from app.models.itsm import ServiceRequest
from app.models.platform import Membership, User
from app.models.rbac import Role
from app.models.ticket import Ticket
from app.security import hash_password, hash_token, new_opaque_token
from app.services import email as email_service
from app.services.portal_service import next_request_number, next_ticket_number

UTC = timezone.utc

SOURCE_SYSTEMS = {"servicenow", "jira", "csv"}
TARGET_TYPES = {"ticket", "request", "user"}

_TICKET_STATUSES = {"open", "in_progress", "pending", "resolved", "closed"}
_REQUEST_STATUSES = {
    "submitted",
    "in_progress",
    "pending_approval",
    "approved",
    "fulfilled",
    "rejected",
    "cancelled",
}
_PRIORITIES = {"low", "medium", "high", "critical"}

_SERVICENOW_STATE = {
    "1": "open",
    "2": "in_progress",
    "3": "pending",
    "6": "resolved",
    "7": "closed",
    "new": "open",
    "in progress": "in_progress",
    "on hold": "pending",
    "resolved": "resolved",
    "closed": "closed",
    "cancelled": "closed",
}
_SERVICENOW_PRIORITY = {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "low"}
_JIRA_STATUS = {
    "to do": "open",
    "open": "open",
    "in progress": "in_progress",
    "in review": "pending",
    "done": "closed",
    "closed": "closed",
    "resolved": "resolved",
}
_REQUEST_STATUS_FROM_TICKET = {
    "open": "submitted",
    "in_progress": "in_progress",
    "pending": "pending_approval",
    "resolved": "fulfilled",
    "closed": "fulfilled",
}


def _map_value(value, mapping: dict, valid: set[str], default: str) -> str:
    if value is None:
        return default
    text_value = str(value).strip()
    if text_value in mapping:
        return mapping[text_value]
    lowered = text_value.lower()
    if lowered in mapping:
        return mapping[lowered]
    if lowered in valid:
        return lowered
    return default


def _email_or_none(value) -> str | None:
    if value and isinstance(value, str) and "@" in value:
        return value.strip()
    return None


def normalize_row(source_system: str, row: dict) -> dict:
    """Map one source row to the canonical import shape.

    Returns {source_id, target_type, title, description, status,
    priority, requester_email, full_name}. Raises ValueError on a
    row that cannot be mapped (missing source id / title).
    """
    if not isinstance(row, dict):
        raise ValueError("row must be an object")
    target_type = str(row.get("target_type") or "ticket").lower()
    if target_type not in TARGET_TYPES:
        raise ValueError(f"unknown target_type: {target_type}")

    if source_system == "servicenow":
        source_id = row.get("number") or row.get("sys_id")
        if not source_id:
            raise ValueError("missing source id (number)")
        return {
            "source_id": str(source_id),
            "target_type": target_type,
            "title": (row.get("short_description") or row.get("number") or "")[:255],
            "description": str(row.get("description") or ""),
            "status": _map_value(row.get("state"), _SERVICENOW_STATE, _TICKET_STATUSES, "open"),
            "priority": _map_value(row.get("priority"), _SERVICENOW_PRIORITY, _PRIORITIES, "medium"),
            "requester_email": _email_or_none(row.get("caller_id")),
            "full_name": str(row.get("caller_name") or "")[:255],
        }
    if source_system == "jira":
        source_id = row.get("key")
        if not source_id:
            raise ValueError("missing source id (key)")
        reporter = row.get("reporter") or {}
        reporter_email = reporter.get("emailAddress") if isinstance(reporter, dict) else None
        return {
            "source_id": str(source_id),
            "target_type": target_type,
            "title": (row.get("summary") or "")[:255],
            "description": str(row.get("description") or ""),
            "status": _map_value(row.get("status"), _JIRA_STATUS, _TICKET_STATUSES, "open"),
            "priority": _map_value(row.get("priority"), {}, _PRIORITIES, "medium"),
            "requester_email": _email_or_none(reporter_email or row.get("reporter_email")),
            "full_name": str((reporter.get("displayName") if isinstance(reporter, dict) else "") or "")[:255],
        }
    # csv-generic
    source_id = row.get("source_id") or row.get("id") or row.get("title")
    if not source_id:
        raise ValueError("missing source id (source_id/id/title)")
    return {
        "source_id": str(source_id),
        "target_type": target_type,
        "title": (row.get("title") or "")[:255],
        "description": str(row.get("description") or ""),
        "status": _map_value(row.get("status"), {}, _TICKET_STATUSES, "open"),
        "priority": _map_value(row.get("priority"), {}, _PRIORITIES, "medium"),
        "requester_email": _email_or_none(row.get("requester_email")),
        "full_name": str(row.get("full_name") or row.get("name") or "")[:255],
    }


def _find_user_by_email(session: Session, email: str) -> dict | None:
    """Look a user up by email via the SECURITY DEFINER function."""
    row = session.execute(text("SELECT * FROM auth_get_user_by_email(:email)"), {"email": email}).mappings().first()
    return dict(row) if row else None


def _find_member_id_by_email(session: Session, org_id: uuid.UUID, email: str | None) -> uuid.UUID | None:
    """Active member id for an email, if any.

    Same lookup discipline as email_ingest: SECURITY DEFINER user
    lookup (works without a user RLS context) + membership check.
    """
    if not email:
        return None
    row = session.execute(text("SELECT * FROM auth_get_user_by_email(:email)"), {"email": email}).mappings().first()
    if row is None:
        return None
    user_id = as_uuid(row["id"])
    membership = session.execute(
        select(Membership).where(
            Membership.organization_id == org_id,
            Membership.user_id == user_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if membership is None:
        return None
    return user_id


def _import_user(
    session: Session, org_id: uuid.UUID, actor_id: uuid.UUID, normalized: dict, raw: dict
) -> tuple[uuid.UUID, str]:
    """Create an invited user. Returns (user_id, outcome).

    Outcome is "imported" for a new user, "skipped" when the email
    already exists in the org (the existing user id is returned).
    """
    email = normalized["requester_email"]
    if not email:
        raise ValueError("user import requires requester_email")
    settings = get_settings()
    existing = _find_user_by_email(session, email)
    if existing is not None:
        existing_id = as_uuid(existing["id"])
        membership = session.execute(
            select(Membership).where(Membership.organization_id == org_id, Membership.user_id == existing_id)
        ).scalar_one_or_none()
        if membership is not None:
            return existing_id, "skipped"
        membership = Membership(organization_id=org_id, user_id=existing_id, status="invited")
        session.add(membership)
        session.flush()
        return existing_id, "skipped"

    full_name = normalized["full_name"] or email.split("@")[0]
    user = User(
        id=uuid.uuid4(),
        email=email,
        # Random, unusable password: the invitee sets their own via the
        # invitation accept flow. The plaintext is never stored.
        password_hash=hash_password(secrets.token_urlsafe(32)),
        full_name=full_name,
        email_verified=False,
    )
    # INSERT ... RETURNING is checked against the users SELECT policy:
    # the new user has no membership yet, so run the insert with the RLS
    # user context set to the new user (own-row clause), then restore
    # the caller's context. The org context stays set throughout.
    set_rls_context(session, org_id, user.id)
    session.add(user)
    session.flush()
    set_rls_context(session, org_id, actor_id)

    session.add(Membership(organization_id=org_id, user_id=user.id, status="invited"))
    token = new_opaque_token()
    invitation = Invitation(
        organization_id=org_id,
        email=email,
        token_hash=hash_token(token),
        invited_by_id=actor_id,
        expires_at=datetime.now(UTC) + timedelta(days=settings.invitation_days),
    )
    session.add(invitation)
    session.flush()
    role = session.execute(
        select(Role).where(Role.organization_id == org_id, Role.name == "Employee / Requester")
    ).scalar_one_or_none()
    if role is not None:
        session.add(InvitationRole(invitation_id=invitation.id, role_id=role.id, organization_id=org_id))
    org_name = "NULL ITSM"
    email_service.send_invitation_email(email, org_name, "https://app.nullitsm.example/invite/accept")
    return user.id, "imported"


def _import_ticket(session: Session, org_id: uuid.UUID, normalized: dict) -> uuid.UUID:
    if not normalized["title"]:
        raise ValueError("missing title")
    requester_id = _find_member_id_by_email(session, org_id, normalized["requester_email"])
    ticket = Ticket(
        organization_id=org_id,
        number=next_ticket_number(session, org_id),
        title=normalized["title"],
        description=normalized["description"],
        status=normalized["status"],
        priority=normalized["priority"],
        category="General",
        requester_id=requester_id,
    )
    session.add(ticket)
    session.flush()
    return ticket.id


def _import_request(session: Session, org_id: uuid.UUID, normalized: dict) -> uuid.UUID:
    if not normalized["title"]:
        raise ValueError("missing title")
    requester_id = _find_member_id_by_email(session, org_id, normalized["requester_email"])
    request = ServiceRequest(
        organization_id=org_id,
        number=next_request_number(session, org_id),
        title=normalized["title"],
        description=normalized["description"],
        status=_REQUEST_STATUS_FROM_TICKET.get(normalized["status"], "submitted"),
        priority=normalized["priority"],
        requester_id=requester_id,
    )
    session.add(request)
    session.flush()
    return request.id


def process_import(session: Session, import_row: DataImport, actor_id: uuid.UUID) -> DataImport:
    """Process the pending records of one import (idempotent).

    Records already marked ``imported`` are skipped; ``failed`` records
    are retried. Updates counts, summary, and status on the import row.
    """
    org_id = import_row.organization_id
    import_row.status = "running"
    import_row.started_at = datetime.now(UTC)
    session.flush()

    imported = failed = skipped = 0
    records = list(
        session.execute(
            select(ImportRecord).where(ImportRecord.import_id == import_row.id).order_by(ImportRecord.created_at)
        ).scalars()
    )
    for record in records:
        if record.status == "imported":
            skipped += 1
            continue
        try:
            normalized = normalize_row(import_row.source_system, record.raw_data or {})
            if normalized["target_type"] == "user":
                target_id, outcome = _import_user(session, org_id, actor_id, normalized, record.raw_data or {})
                if outcome == "skipped":
                    record.status = "skipped"
                    record.error = "user already exists"
                    record.target_id = target_id
                    skipped += 1
                else:
                    record.status = "imported"
                    record.target_id = target_id
                    imported += 1
            elif normalized["target_type"] == "request":
                record.target_id = _import_request(session, org_id, normalized)
                record.status = "imported"
                record.error = None
                imported += 1
            else:
                record.target_id = _import_ticket(session, org_id, normalized)
                record.status = "imported"
                record.error = None
                imported += 1
        except Exception as exc:  # per-row failure: recorded, import continues
            record.status = "failed"
            record.error = str(exc)[:500]
            failed += 1
        session.flush()

    import_row.processed_rows = imported + failed + skipped
    import_row.error_rows = failed
    import_row.completed_at = datetime.now(UTC)
    import_row.summary = {
        "imported": imported,
        "failed": failed,
        "skipped": skipped,
        "total": import_row.total_rows,
    }
    if failed and imported == 0 and skipped == 0:
        import_row.status = "failed"
    elif failed:
        import_row.status = "partial"
    else:
        import_row.status = "completed"
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.IMPORT_COMPLETED if import_row.status in ("completed", "partial") else audit_mod.IMPORT_FAILED,
        resource_type="import",
        resource_id=str(import_row.id),
        outcome="success" if import_row.status != "failed" else "failure",
        metadata={"source_system": import_row.source_system, **import_row.summary},
    )
    session.flush()
    return import_row


def create_import(
    session: Session, org_id: uuid.UUID, actor_id: uuid.UUID, source_system: str, rows: list[dict]
) -> DataImport:
    """Create an import + its records, then process it synchronously."""
    if source_system not in SOURCE_SYSTEMS:
        raise ValueError(f"unknown source_system: {source_system}")
    import_row = DataImport(
        organization_id=org_id,
        source_system=source_system,
        status="pending",
        total_rows=len(rows),
        requested_by_id=actor_id,
    )
    session.add(import_row)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.IMPORT_STARTED,
        resource_type="import",
        resource_id=str(import_row.id),
        outcome="success",
        metadata={"source_system": source_system, "total_rows": len(rows)},
    )
    for row in rows:
        raw = row if isinstance(row, dict) else {"_raw": str(row)}
        source_id = None
        if isinstance(row, dict):
            source_id = row.get("number") or row.get("key") or row.get("source_id") or row.get("id")
        record = ImportRecord(
            organization_id=org_id,
            import_id=import_row.id,
            source_id=str(source_id) if source_id is not None else f"row-{uuid.uuid4()}",
            target_type=str(row.get("target_type") or "ticket").lower() if isinstance(row, dict) else "ticket",
            status="pending",
            raw_data=raw,
        )
        session.add(record)
    session.flush()
    return process_import(session, import_row, actor_id)
