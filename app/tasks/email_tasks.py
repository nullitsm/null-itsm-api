"""Mailbox polling (Celery): IMAP fetch -> email ingest.

Beat entry (coordinator wires it in app/tasks/celery_app.py):
``poll-mailboxes`` — task ``null.tasks.poll_mailboxes``, every 5 minutes.

The task discovers organizations with active mailboxes through the
SECURITY DEFINER function ``email_list_active_mailbox_orgs()`` (it runs
before any RLS context exists), then polls each organization in its
own tenant session. Mailbox passwords are decrypted with app.crypto —
if field encryption is not configured the mailbox is skipped with
``last_error`` set, never with a plaintext fallback. Passwords and
message bodies are never logged.
"""

from __future__ import annotations

import imaplib
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.crypto import decrypt
from app.database import SessionLocal, as_uuid, tenant_session
from app.models.email_portal import EmailMailbox
from app.services.email_ingest import ingest_message
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks.email")

UTC = timezone.utc


def poll_mailbox(session: Session, mailbox: EmailMailbox) -> dict:
    """Poll one mailbox: fetch UNSEEN, ingest each message, mark seen.

    Returns {"ingested": n, "errors": [...]}. Connection/auth failures
    set ``mailbox.last_error`` and return without raising, so one bad
    mailbox never blocks the rest of the sweep.
    """
    ingested = 0
    errors: list[str] = []
    try:
        password = decrypt(mailbox.password_encrypted)
    except RuntimeError as exc:
        mailbox.last_error = str(exc)
        session.flush()
        return {"ingested": 0, "errors": [str(exc)]}

    mail = None
    try:
        if mailbox.use_tls:
            mail = imaplib.IMAP4_SSL(mailbox.host, mailbox.port)
        else:
            mail = imaplib.IMAP4(mailbox.host, mailbox.port)
        mail.login(mailbox.username, password)
        mail.select(mailbox.folder)
        _typ, data = mail.search(None, "UNSEEN")
        ids = data[0].split() if data and data[0] else []
        for num in ids:
            try:
                _typ, fetched = mail.fetch(num, "(RFC822)")
                raw = fetched[0][1] if fetched and fetched[0] else None
                if raw is None:
                    continue
                if isinstance(raw, str):
                    raw = raw.encode("utf-8")
                ingest_message(session, mailbox.organization_id, mailbox.id, raw)
                mail.store(num, "+FLAGS", "\\Seen")
                ingested += 1
            except Exception as exc:  # one bad message must not stop the batch
                errors.append(f"message {num!r}: {exc}")
                logger.warning("Mailbox %s: failed to ingest message %r: %s", mailbox.id, num, exc)
        session.flush()
        mailbox.last_poll_at = datetime.now(UTC)
        mailbox.last_error = None
    except Exception as exc:
        mailbox.last_error = str(exc)[:500]
        errors.append(str(exc)[:500])
        logger.warning("Mailbox %s poll failed: %s", mailbox.id, exc)
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass
    session.flush()
    return {"ingested": ingested, "errors": errors}


def poll_org_mailboxes(org_id: uuid.UUID) -> dict:
    """Poll every active mailbox of one organization."""
    polled = ingested = 0
    errors: list[str] = []
    with tenant_session(org_id) as session:
        mailboxes = list(
            session.execute(
                select(EmailMailbox).where(EmailMailbox.organization_id == org_id, EmailMailbox.is_active.is_(True))
            ).scalars()
        )
        for mailbox in mailboxes:
            polled += 1
            result = poll_mailbox(session, mailbox)
            ingested += result["ingested"]
            errors.extend(result["errors"])
    return {"polled": polled, "ingested": ingested, "errors": errors}


@celery_app.task(name="null.tasks.poll_mailboxes")
def poll_mailboxes(org_id: str | None = None) -> dict:
    """Poll mailboxes for one org, or for every org with an active mailbox.

    With no mailbox configured anywhere returns
    ``{"polled": 0, "ingested": 0, "errors": []}``.
    """
    if org_id is not None:
        return poll_org_mailboxes(as_uuid(org_id))
    with SessionLocal() as session:
        org_ids = [r[0] for r in session.execute(text("SELECT * FROM email_list_active_mailbox_orgs()")).all()]
    polled = ingested = 0
    errors: list[str] = []
    for oid in org_ids:
        result = poll_org_mailboxes(as_uuid(oid))
        polled += result["polled"]
        ingested += result["ingested"]
        errors.extend(result["errors"])
    return {"polled": polled, "ingested": ingested, "errors": errors}


# --- Delivery retries ---------------------------------------------------------
# A failed provider send is recorded on the EmailDelivery row and a retry
# is enqueued (backoff 60s, 120s, ...). The retry re-sends the STORED
# rendered bodies, so the identical email goes out without ever needing
# the raw invitation token again. Tenant scope travels in the task args.


def _audit_retry_event(session: Session, row, scope: str, action: str, outcome: str, error: str | None) -> None:
    """One audit event for a retry attempt, in the right audit log."""
    metadata = {
        "to": row.to_email,
        "subject": row.subject,
        "template": row.template,
        "provider": row.provider,
        "provider_message_id": row.provider_message_id,
        "attempts": row.attempts,
        "error": error,
    }
    if scope == "platform":
        from app.services.platform_service import write_platform_audit

        write_platform_audit(
            session,
            actor_id=row.created_by_id,
            action=action,
            resource_type="email_delivery",
            resource_id=str(row.id),
            organization_id=None,
            outcome=outcome,
            metadata=metadata,
        )
    else:
        from app.audit import write_audit

        write_audit(
            session,
            organization_id=row.organization_id,
            actor_id=row.created_by_id,
            action=action,
            resource_type="email_delivery",
            resource_id=str(row.id),
            outcome=outcome,
            metadata=metadata,
        )


@celery_app.task(name="null.tasks.retry_email_delivery")
def retry_email_delivery(
    delivery_id: str,
    organization_id: str | None = None,
    scope: str = "org",
    created_by_id: str | None = None,
) -> dict:
    """Re-send one failed delivery from its stored rendered bodies.

    Only rows with status ``failed`` and attempts remaining are retried.
    A row already ``sent`` (or recorded in dev) is left alone, so a
    duplicated task can never double-send. Returns the outcome; never
    raises for a provider failure.
    """
    from app import audit as audit_mod
    from app.config import get_settings
    from app.database import platform_session
    from app.models.email import STATUS_FAILED, STATUS_SENT, EmailDelivery
    from app.services import email as email_service

    max_attempts = get_settings().email_retry_max_attempts
    did = as_uuid(delivery_id)
    org_id = as_uuid(organization_id) if organization_id else None
    actor_id = as_uuid(created_by_id) if created_by_id else None

    if scope == "platform":
        if actor_id is None:
            return {"retried": False, "error": "platform retry requires created_by_id"}
        session_ctx = platform_session(actor_id)
    else:
        if org_id is None:
            return {"retried": False, "error": "org retry requires organization_id"}
        session_ctx = tenant_session(org_id)

    with session_ctx as session:
        row = session.get(EmailDelivery, did)
        if row is None:
            return {"retried": False, "error": "delivery not found"}
        if row.status != STATUS_FAILED:
            return {"retried": False, "status": row.status, "reason": "not failed"}
        if row.attempts >= max_attempts:
            return {"retried": False, "status": row.status, "reason": "attempts exhausted"}
        try:
            provider = email_service.resolve_provider()
        except email_service.EmailConfigurationError as exc:
            # Config went away between enqueue and execution: do not burn
            # an attempt on a message that was never attempted.
            return {"retried": False, "status": row.status, "reason": str(exc)[:500]}
        if provider.name == "dev":
            # No real provider configured (or dev mode): do not re-record
            # a failure, do not loop. The row stays failed for an admin to
            # retry once delivery is configured again.
            return {"retried": False, "status": row.status, "reason": "no email provider configured"}

        try:
            message_id = provider.send(
                to=row.to_email, subject=row.subject, html_body=row.html_body, text_body=row.text_body
            )
        except email_service.EmailConfigurationError as exc:
            return {"retried": False, "status": row.status, "reason": str(exc)[:500]}
        except email_service.EmailDeliveryError as exc:
            row.attempts += 1
            row.last_error = str(exc)[:500]
            row.status = STATUS_FAILED
            _audit_retry_event(session, row, row.scope, audit_mod.EMAIL_DELIVERY_FAILED, "failure", row.last_error)
            if row.attempts < max_attempts:
                email_service._enqueue_retry(
                    row.id,
                    countdown_seconds=60 * (2 ** (row.attempts - 1)),
                    organization_id=row.organization_id,
                    scope=row.scope,
                    created_by_id=row.created_by_id,
                )
            return {"retried": True, "delivered": False, "attempts": row.attempts, "error": row.last_error}

        row.attempts += 1
        row.status = STATUS_SENT
        row.provider_message_id = message_id
        row.last_error = None
        _audit_retry_event(session, row, row.scope, audit_mod.EMAIL_DELIVERY_SENT, "success", None)
        return {
            "retried": True,
            "delivered": True,
            "provider_message_id": message_id,
            "attempts": row.attempts,
        }
