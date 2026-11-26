"""Platform models: organizations, users, memberships.

Tenancy notes
-------------
- ``organizations`` is tenant-owned in the sense that only members may read
  it (RLS policy: membership-gated SELECT).
- ``users`` is a global identity table: one person can belong to many
  organizations. RLS: a caller may read their own row, or rows of users who
  share an organization with them (via memberships).
- ``memberships`` links a user to an organization and is the source of
  truth for "verified organization membership".
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk

if TYPE_CHECKING:
    from app.models.rbac import Role


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    # Registration profile (collected at public registration; all optional
    # after creation except the contact email).
    contact_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    website: Mapped[str | None] = mapped_column(String(255), nullable=True)
    industry: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # 1-10 | 11-50 | 51-200 | 201-1000 | 1000+
    size: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Free-form org settings (branding, timezone, defaults). JSONB in the DB.
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    # Marker retained for API compatibility; always False since the
    # sample-data removal (Nov 26, 2026) — no fixtures exist.
    is_dev_fixture: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # The user who created the organization. Recorded so the creator can
    # read the row back immediately: INSERT ... RETURNING is checked against
    # the SELECT policy, and at creation time no membership row exists yet,
    # so the SELECT policy must also pass for the creator (see 0001).
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    memberships: Mapped[list["Membership"]] = relationship(back_populates="organization")
    roles: Mapped[list["Role"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # TOTP secret, encrypted at rest in production (Secrets Manager/KMS).
    # In this codebase it is stored as an opaque string; the value is a
    # base32 TOTP secret, never a password.
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_login_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    memberships: Mapped[list["Membership"]] = relationship(back_populates="user")


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_membership_org_user"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # active | invited | suspended
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    is_owner: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # Access expiration: when set, the membership is suspended automatically
    # once this time passes (Celery task). NULL = no expiration.
    expires_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")
