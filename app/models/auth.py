"""Authentication models: refresh sessions, invitations, password resets.

Security notes
--------------
- Refresh tokens are stored ONLY as SHA-256 hashes. The raw token is shown
  to the client once and never persisted.
- Invitation and password-reset tokens are likewise stored as hashes.
- ``sessions`` is tenant-owned (organization_id) and RLS-scoped; a session
  row is created only after the organization has been resolved server-side.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, uuid_pk


class AuthSession(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    revoked_at: Mapped[datetime | None] = tz_col()
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()


class Invitation(Base):
    __tablename__ = "invitations"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    # Invitation form fields: the invitee's name and org structure. The
    # invitation carries the org + assigned roles; the invitee cannot
    # change either at acceptance.
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    department: Mapped[str] = mapped_column(String(100), nullable=False, server_default="")
    team: Mapped[str] = mapped_column(String(100), nullable=False, server_default="")
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    invited_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # pending | accepted | expired | revoked
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    accepted_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()


class InvitationRole(Base):
    __tablename__ = "invitation_roles"

    id: Mapped[uuid.UUID] = uuid_pk()
    invitation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("invitations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = created_at_col()


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    used_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
