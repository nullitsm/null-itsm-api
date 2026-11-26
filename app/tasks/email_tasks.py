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
