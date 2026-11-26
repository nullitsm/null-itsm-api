"""Email / portal / import / export models (Phase 2, migration 0006).

- ``email_mailboxes`` / ``email_messages`` — email-to-ticket (IMAP ingest,
  SMTP replies). Mailbox passwords are Fernet-encrypted (see app.crypto);
  plaintext is never stored.
- ``portal_sessions`` — employee self-service sessions. Only the SHA-256
  hash of the portal token is stored (same rule as refresh tokens).
- ``imports`` / ``import_records`` — data imports (ServiceNow / Jira /
  generic CSV). ``import_records`` is idempotent on (import_id, source_id).
- ``exports`` — data exports (tickets / requests / users / audit / full).

Every table is tenant-owned (``organization_id``) and RLS-scoped; see
migration 0006 for the policies.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


class EmailMailbox(Base):
    __tablename__ = "email_mailboxes"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False, server_default="imap")
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, server_default="993")
    use_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    # Fernet-encrypted (app.crypto). NEVER plaintext.
    password_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    folder: Mapped[str] = mapped_column(String(100), nullable=False, server_default="INBOX")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    last_poll_at: Mapped[datetime | None] = tz_col()
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class EmailMessage(Base):
    __tablename__ = "email_messages"
    __table_args__ = (UniqueConstraint("organization_id", "message_id", name="uq_email_message_org_message_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    mailbox_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("email_mailboxes.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # RFC Message-ID. Synthetic (``<ingest-<uuid>@null.local>``) when the
    # inbound message carried none, so the uniqueness constraint still holds.
    message_id: Mapped[str] = mapped_column(String(255), nullable=False)
    from_address: Mapped[str] = mapped_column(String(255), nullable=False)
    to_addresses: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    subject: Mapped[str] = mapped_column(String(500), nullable=False, server_default="")
    body_text: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    # inbound | outbound
    direction: Mapped[str] = mapped_column(String(20), nullable=False, server_default="inbound")
    # received | processed | failed | replied
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="received")
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tickets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PortalSession(Base):
    __tablename__ = "portal_sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # SHA-256 hex of the portal token. The raw token is shown once, never stored.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    revoked_at: Mapped[datetime | None] = tz_col()
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Org branding snapshot taken at login (organizations.settings branding).
    branding_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class DataImport(Base):
    __tablename__ = "imports"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # servicenow | jira | csv
    source_system: Mapped[str] = mapped_column(String(50), nullable=False)
    # pending | running | completed | failed | partial
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    total_rows: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    processed_rows: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error_rows: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=False, index=True
    )
    started_at: Mapped[datetime | None] = tz_col()
    completed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ImportRecord(Base):
    __tablename__ = "import_records"
    __table_args__ = (UniqueConstraint("import_id", "source_id", name="uq_import_record_import_source"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    import_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("imports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # ticket | request | user
    target_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ticket")
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    # pending | imported | failed | skipped
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class DataExport(Base):
    __tablename__ = "exports"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # tickets | requests | users | audit | full
    export_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # csv | json
    format: Mapped[str] = mapped_column(String(20), nullable=False, server_default="csv")
    # pending | running | completed | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    storage_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=False, index=True
    )
    completed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
