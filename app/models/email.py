"""Email delivery records (migration 0018).

One row per delivery attempt batch for one outbound email (invitation,
password reset, ...). The row is the durable record of what the
provider did: the provider message id on success, the error + attempt
count on failure. The rendered bodies are stored so a failed provider
submission can be retried by the Celery task without re-rendering —
and without ever needing the raw invitation token again (only its
SHA-256 hash is stored, on the invitation row). Bodies contain the
accept link, so they are readable only through the org-scoped RLS
policy — the API never returns them.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, updated_at_col, uuid_pk
from app.models.registration import _org_fk

# Delivery statuses.
STATUS_SENT = "sent"
STATUS_FAILED = "failed"
# Recorded in the local dev outbox; NOT actually delivered.
STATUS_DEV_RECORDED = "dev_recorded"


class EmailDelivery(Base):
    __tablename__ = "email_deliveries"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = _org_fk(nullable=True)
    # 'org' | 'platform'
    scope: Mapped[str] = mapped_column(String(20), nullable=False, server_default="org")
    # Which invitation this delivery is for (at most one is set).
    org_invitation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("invitations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    platform_invitation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_invitations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    to_email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    # 'org_invitation' | 'platform_invitation' | 'password_reset' | ...
    template: Mapped[str] = mapped_column(String(50), nullable=False, server_default="")
    provider: Mapped[str] = mapped_column(String(20), nullable=False, server_default="dev")
    provider_message_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # 'sent' | 'failed' | 'dev_recorded'
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default=STATUS_DEV_RECORDED)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Who triggered the send (inviting admin / platform admin) — the
    # retry task scopes its session to this identity for platform rows.
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    # Rendered content, stored so retries re-send the identical email.
    html_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    text_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
