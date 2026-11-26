"""Email: mailboxes, inbox, replies, triage (email-to-ticket).

Permissions: ``email:read`` for reads, ``email:manage`` for mailbox
configuration, replies, triage, and manual polls. Mailbox passwords
are Fernet-encrypted on write and never returned by the API.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.config import get_settings
from app.crypto import encrypt
from app.deps import Principal, get_db, require_permission
from app.models.email_portal import EmailMailbox, EmailMessage
from app.services import email as email_service
from app.services.email_ingest import append_public_comment, convert_message_to_ticket
from app.tasks.email_tasks import poll_mailbox

router = APIRouter(prefix="/api/v1/email", tags=["email"])


# --- Schemas (local: app/schemas.py is owned by another workstream) ------


class MailboxCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    protocol: str = "imap"
    host: str = Field(min_length=1, max_length=255)
    port: int = 993
    use_tls: bool = True
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)
    folder: str = "INBOX"
    is_active: bool = True


class MailboxUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    host: str | None = Field(default=None, max_length=255)
    port: int | None = None
    use_tls: bool | None = None
    username: str | None = Field(default=None, max_length=255)
    password: str | None = None
    folder: str | None = Field(default=None, max_length=100)
    is_active: bool | None = None


class MailboxOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    protocol: str
    host: str
    port: int
    use_tls: bool
    username: str
    folder: str
    is_active: bool
    last_poll_at: datetime | None
    last_error: str | None
    has_password: bool
    created_at: datetime
    updated_at: datetime


class MessageOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    mailbox_id: uuid.UUID | None
    message_id: str
    from_address: str
    to_addresses: list
    subject: str
    body_text: str
    body_html: str | None
    direction: str
    status: str
    ticket_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class ReplyRequest(BaseModel):
    body: str = Field(min_length=1)


def _mailbox_out(m: EmailMailbox) -> MailboxOut:
    return MailboxOut(
        id=m.id,
        organization_id=m.organization_id,
        name=m.name,
        protocol=m.protocol,
        host=m.host,
        port=m.port,
        use_tls=m.use_tls,
        username=m.username,
        folder=m.folder,
        is_active=m.is_active,
        last_poll_at=m.last_poll_at,
        last_error=m.last_error,
        has_password=bool(m.password_encrypted),
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


def _message_out(m: EmailMessage) -> MessageOut:
    return MessageOut(
        id=m.id,
        organization_id=m.organization_id,
        mailbox_id=m.mailbox_id,
        message_id=m.message_id,
        from_address=m.from_address,
        to_addresses=m.to_addresses or [],
        subject=m.subject,
        body_text=m.body_text,
        body_html=m.body_html,
        direction=m.direction,
        status=m.status,
        ticket_id=m.ticket_id,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


def _get_mailbox(session: Session, org_id: uuid.UUID, mailbox_id: uuid.UUID) -> EmailMailbox:
    mailbox = session.get(EmailMailbox, mailbox_id)
    if mailbox is None or mailbox.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mailbox not found")
    return mailbox


def _get_message(session: Session, org_id: uuid.UUID, message_id: uuid.UUID) -> EmailMessage:
    message = session.get(EmailMessage, message_id)
    if message is None or message.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    return message


# --- Mailboxes -------------------------------------------------------------


@router.get("/mailboxes", response_model=list[MailboxOut])
def list_mailboxes(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("email:read"))
):
    rows = session.execute(
        select(EmailMailbox)
        .where(EmailMailbox.organization_id == principal.organization_id)
        .order_by(EmailMailbox.created_at)
    ).scalars()
    return [_mailbox_out(m) for m in rows]


@router.post("/mailboxes", response_model=MailboxOut, status_code=status.HTTP_201_CREATED)
def create_mailbox(
    body: MailboxCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:manage")),
):
    if body.protocol not in ("imap",):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported protocol")
    try:
        encrypted = encrypt(body.password)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    mailbox = EmailMailbox(
        organization_id=principal.organization_id,
        name=body.name,
        protocol=body.protocol,
        host=body.host,
        port=body.port,
        use_tls=body.use_tls,
        username=body.username,
        password_encrypted=encrypted,
        folder=body.folder,
        is_active=body.is_active,
    )
    session.add(mailbox)
    session.flush()
    out = _mailbox_out(mailbox)
    session.commit()
    return out


@router.get("/mailboxes/{mailbox_id}", response_model=MailboxOut)
def get_mailbox(
    mailbox_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:read")),
):
    return _mailbox_out(_get_mailbox(session, principal.organization_id, mailbox_id))


@router.patch("/mailboxes/{mailbox_id}", response_model=MailboxOut)
def update_mailbox(
    mailbox_id: uuid.UUID,
    body: MailboxUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:manage")),
):
    mailbox = _get_mailbox(session, principal.organization_id, mailbox_id)
    if body.name is not None:
        mailbox.name = body.name
    if body.host is not None:
        mailbox.host = body.host
    if body.port is not None:
        mailbox.port = body.port
    if body.use_tls is not None:
        mailbox.use_tls = body.use_tls
    if body.username is not None:
        mailbox.username = body.username
    if body.folder is not None:
        mailbox.folder = body.folder
    if body.is_active is not None:
        mailbox.is_active = body.is_active
    if body.password is not None:
        try:
            mailbox.password_encrypted = encrypt(body.password)
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.flush()
    out = _mailbox_out(mailbox)
    session.commit()
    return out


@router.delete("/mailboxes/{mailbox_id}")
def delete_mailbox(
    mailbox_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:manage")),
):
    mailbox = _get_mailbox(session, principal.organization_id, mailbox_id)
    session.delete(mailbox)
    session.commit()
    return {"status": "deleted", "id": str(mailbox_id)}


@router.post("/mailboxes/{mailbox_id}/poll")
def poll_mailbox_now(
    mailbox_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:manage")),
):
    """Synchronously poll one mailbox (manual trigger; the Celery task
    does the scheduled sweep)."""
    mailbox = _get_mailbox(session, principal.organization_id, mailbox_id)
    result = poll_mailbox(session, mailbox)
    session.commit()
    return {"mailbox_id": str(mailbox_id), **result}


# --- Messages --------------------------------------------------------------


@router.get("/messages", response_model=list[MessageOut])
def list_messages(
    status_filter: str | None = None,
    mailbox_id: uuid.UUID | None = None,
    direction: str | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:read")),
):
    query = select(EmailMessage).where(EmailMessage.organization_id == principal.organization_id)
    if status_filter:
        query = query.where(EmailMessage.status == status_filter)
    if mailbox_id:
        query = query.where(EmailMessage.mailbox_id == mailbox_id)
    if direction:
        query = query.where(EmailMessage.direction == direction)
    rows = session.execute(query.order_by(EmailMessage.created_at.desc())).scalars()
    return [_message_out(m) for m in rows]


@router.get("/messages/{message_id}", response_model=MessageOut)
def get_message(
    message_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:read")),
):
    return _message_out(_get_message(session, principal.organization_id, message_id))


@router.post("/messages/{message_id}/reply", response_model=MessageOut, status_code=status.HTTP_201_CREATED)
def reply_to_message(
    message_id: uuid.UUID,
    body: ReplyRequest,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:manage")),
):
    message = _get_message(session, principal.organization_id, message_id)
    if not message.from_address:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message has no sender to reply to")
    subject = message.subject or ""
    reply_subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
    settings = get_settings()
    sent = email_service.send_reply_email(message.from_address, reply_subject, body.body)
    outbound = EmailMessage(
        organization_id=principal.organization_id,
        mailbox_id=message.mailbox_id,
        message_id=f"<reply-{uuid.uuid4()}@null.local>",
        from_address=settings.email_from,
        to_addresses=[message.from_address],
        subject=reply_subject,
        body_text=body.body,
        body_html=None,
        direction="outbound",
        status="replied",
        ticket_id=message.ticket_id,
    )
    session.add(outbound)
    session.flush()
    if message.ticket_id is not None:
        append_public_comment(session, principal.organization_id, message.ticket_id, principal.user_id, body.body)
    message.status = "replied"
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.EMAIL_REPLY_SENT,
        resource_type="email_message",
        resource_id=str(message.id),
        outcome="success",
        metadata={
            "to": message.from_address,
            "sent_via_smtp": sent,
            "ticket_id": str(message.ticket_id) if message.ticket_id else None,
        },
    )
    session.flush()
    out = _message_out(outbound)
    session.commit()
    return out


@router.post("/messages/{message_id}/convert")
def convert_message(
    message_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("email:manage")),
):
    """Triage: convert an unknown-sender message into a ticket."""
    message = _get_message(session, principal.organization_id, message_id)
    if message.ticket_id is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message already has a ticket")
    ticket = convert_message_to_ticket(session, principal.organization_id, message, principal.user_id)
    out = {"ticket_id": str(ticket.id), "ticket_number": ticket.number, "message_id": str(message.id)}
    session.commit()
    return out
