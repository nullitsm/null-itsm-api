"""Email ingest: RFC822 parsing, threading, email-to-ticket.

Standard library only (``email`` + ``imaplib`` in the poller task).
Never auto-create tickets for strangers: mail from an address that is
not an active member of the organization is stored with status
``received`` and no ticket, flagged for manual triage via
``POST /api/v1/email/messages/{id}/convert``.
"""

from __future__ import annotations

import re
import uuid
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.database import as_uuid
from app.models.email_portal import EmailMessage
from app.models.itsm import TicketComment
from app.models.platform import Membership
from app.models.ticket import Ticket
from app.services.portal_service import next_ticket_number

_TICKET_REF_RE = re.compile(r"\[(INC-\d{6})\]", re.IGNORECASE)
_VALID_PRIORITIES = {"low", "medium", "high", "critical"}


def _header_text(msg: Message, name: str) -> str:
    value = msg.get(name)
    return str(value).strip() if value is not None else ""


def _extract_bodies(msg: Message) -> tuple[str, str | None]:
    """Return (body_text, body_html) from a parsed message."""
    text_parts: list[str] = []
    html_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                continue
            if payload is None:
                continue
            try:
                text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            if content_type == "text/plain":
                text_parts.append(text)
            elif content_type == "text/html":
                html_parts.append(text)
    else:
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            payload = None
        if payload is not None:
            text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_parts.append(text)
            else:
                text_parts.append(text)
    return "\n".join(text_parts).strip(), ("\n".join(html_parts) if html_parts else None)


def parse_message(raw_bytes: bytes) -> dict:
    """Parse RFC822 bytes into a plain dict.

    Keys: from, to (list), subject, message_id, in_reply_to,
    references (list), body_text, body_html.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    from_addr = parseaddr(_header_text(msg, "From"))[1]
    to_addrs = [parseaddr(a)[1] for a in _header_text(msg, "To").split(",") if a.strip()]
    body_text, body_html = _extract_bodies(msg)
    references = [r for r in _header_text(msg, "References").split() if r]
    return {
        "from": from_addr,
        "to": to_addrs,
        "subject": _header_text(msg, "Subject"),
        "message_id": _header_text(msg, "Message-ID"),
        "in_reply_to": _header_text(msg, "In-Reply-To"),
        "references": references,
        "body_text": body_text,
        "body_html": body_html,
    }


def append_public_comment(
    session: Session, org_id: uuid.UUID, ticket_id: uuid.UUID, author_id: uuid.UUID | None, body: str
) -> TicketComment:
    """Append a public (customer-visible) reply to a ticket."""
    comment = TicketComment(
        organization_id=org_id,
        ticket_id=ticket_id,
        author_id=author_id,
        body=body,
        is_internal=False,
    )
    session.add(comment)
    return comment


def _find_member_id_by_email(session: Session, org_id: uuid.UUID, email: str) -> uuid.UUID | None:
    """The id of the active org member with this email address, if any.

    The user lookup goes through the SECURITY DEFINER function (the
    users SELECT policy hides rows when no user context is set, e.g.
    inside the Celery poller), then the membership is verified under
    the org RLS context. Only the id is returned — reading the full
    User row would need a user context this caller may not have.
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


def _find_member_by_email(session: Session, org_id: uuid.UUID, email: str) -> uuid.UUID | None:
    """Backwards-compatible alias: returns the member's id (see above)."""
    return _find_member_id_by_email(session, org_id, email)


def _find_ticket_by_number(session: Session, org_id: uuid.UUID, number: str) -> Ticket | None:
    return session.execute(
        select(Ticket).where(Ticket.organization_id == org_id, Ticket.number == number.upper())
    ).scalar_one_or_none()


def _create_ticket_from_mail(
    session: Session, org_id: uuid.UUID, parsed: dict, requester_id: uuid.UUID | None
) -> Ticket:
    ticket = Ticket(
        organization_id=org_id,
        number=next_ticket_number(session, org_id),
        title=(parsed["subject"] or "(no subject)")[:255],
        description=parsed["body_text"] or "",
        priority="medium",
        category="General",
        requester_id=requester_id,
        status="open",
    )
    session.add(ticket)
    # Flush here: the uuid_pk default fires on flush, so ticket.id (and
    # ticket.number's counter row) is only populated after this. Callers
    # assign row.ticket_id = ticket.id immediately, so it must be real.
    session.flush()
    return ticket


def ingest_message(session: Session, org_id: uuid.UUID, mailbox_id: uuid.UUID | None, raw_bytes: bytes) -> EmailMessage:
    """Store an inbound message and thread / triage it.

    Dedupe: a message whose RFC Message-ID is already stored for this
    org is returned as-is (no second ticket, no second comment).
    Threading, in order:
    1. In-Reply-To / References matching a stored OUTBOUND message_id
       for this org (with a ticket) — a reply to our reply.
    2. ``[INC-000123]`` in the subject — a reply referencing a ticket.
    3. Sender is an active org member — a new ticket, requester = member.
    4. Otherwise — stored with status ``received`` and NO ticket
       (unknown sender; manual triage only).
    """
    parsed = parse_message(raw_bytes)
    message_id = parsed["message_id"] or f"<ingest-{uuid.uuid4()}@null.local>"

    if parsed["message_id"]:
        existing = session.execute(
            select(EmailMessage).where(
                EmailMessage.organization_id == org_id, EmailMessage.message_id == parsed["message_id"]
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    row = EmailMessage(
        organization_id=org_id,
        mailbox_id=mailbox_id,
        message_id=message_id,
        from_address=parsed["from"],
        to_addresses=parsed["to"],
        subject=parsed["subject"][:500],
        body_text=parsed["body_text"],
        body_html=parsed["body_html"],
        direction="inbound",
        status="received",
        ticket_id=None,
    )
    session.add(row)
    session.flush()

    ticket: Ticket | None = None
    threaded = False

    # 1. Reply to one of our outbound messages.
    reply_ids = [r for r in [parsed["in_reply_to"], *parsed["references"]] if r]
    if reply_ids:
        outbound = session.execute(
            select(EmailMessage).where(
                EmailMessage.organization_id == org_id,
                EmailMessage.direction == "outbound",
                EmailMessage.message_id.in_(reply_ids),
                EmailMessage.ticket_id.is_not(None),
            )
        ).scalar_one_or_none()
        if outbound is not None:
            ticket = session.get(Ticket, outbound.ticket_id)
            threaded = ticket is not None

    # 2. [INC-000123] in the subject.
    if ticket is None:
        match = _TICKET_REF_RE.search(parsed["subject"])
        if match:
            ticket = _find_ticket_by_number(session, org_id, match.group(1))
            threaded = ticket is not None

    if ticket is not None:
        row.ticket_id = ticket.id
        row.status = "processed"
        if threaded and parsed["body_text"]:
            append_public_comment(session, org_id, ticket.id, None, parsed["body_text"])
    else:
        # 3. New mail from a member -> new ticket.
        member_id = _find_member_by_email(session, org_id, parsed["from"])
        if member_id is not None:
            ticket = _create_ticket_from_mail(session, org_id, parsed, member_id)
            row.ticket_id = ticket.id
            row.status = "processed"
        # 4. Unknown sender: stored, no ticket, status stays "received".

    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=None,
        action=audit_mod.EMAIL_MESSAGE_INGESTED,
        resource_type="email_message",
        resource_id=str(row.id),
        outcome="success",
        metadata={
            "message_id": message_id,
            "from": parsed["from"],
            "ticket_id": str(row.ticket_id) if row.ticket_id else None,
            "ticket_number": ticket.number if ticket is not None else None,
        },
    )
    session.flush()
    return row


def convert_message_to_ticket(
    session: Session, org_id: uuid.UUID, message: EmailMessage, actor_id: uuid.UUID
) -> Ticket:
    """Triage: turn a stored (unknown-sender) message into a ticket.

    The requester is the sender when they are an active member, else
    None (the ticket is still created — a human made this call).
    """
    member_id = _find_member_by_email(session, org_id, message.from_address)
    ticket = Ticket(
        organization_id=org_id,
        number=next_ticket_number(session, org_id),
        title=(message.subject or "(no subject)")[:255],
        description=message.body_text or "",
        priority="medium",
        category="General",
        requester_id=member_id,
        status="open",
    )
    session.add(ticket)
    session.flush()
    message.ticket_id = ticket.id
    message.status = "processed"
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.EMAIL_TRIAGED,
        resource_type="email_message",
        resource_id=str(message.id),
        outcome="success",
        metadata={"ticket_id": str(ticket.id), "ticket_number": ticket.number},
    )
    session.flush()
    return ticket
