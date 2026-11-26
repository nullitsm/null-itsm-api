"""Notification creation — shared by the ITSM engine, the SLA engine,
and the email worker.

Every notification is a row in ``notifications`` (created by the Phase 2
ITSM migration) plus, for the ``email`` channel, a send attempt through
the email service (dev: logged, never sent). The model import is deferred
to call time: this module is imported by workstreams whose models land
in different migrations, and the import must succeed before any of them
exist.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session


def create_notification(
    session: Session,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    type: str,
    title: str,
    body: str,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    channel: str = "in_app",
) -> Any:
    """Create one notification row (caller commits). Returns the row.

    ``channel`` is ``in_app`` or ``email``. Email-channel notifications
    are also sent through the email service when an address is known for
    the user; the send is best-effort and recorded in ``email_status``.
    """
    from app.models.itsm import Notification

    row = Notification(
        organization_id=organization_id,
        user_id=user_id,
        type=type,
        title=title,
        body=body,
        resource_type=resource_type,
        resource_id=resource_id,
        channel=channel,
        email_status="logged" if channel == "email" else "n/a",
    )
    session.add(row)
    session.flush()
    if channel == "email":
        from app.models.platform import User
        from app.services import email as email_service

        user = session.get(User, user_id)
        if user is not None:
            email_service.send_email(user.email, title, body)
            row.email_status = "sent"
    return row
