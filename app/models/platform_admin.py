"""Platform administration domain models — the SECOND administrative domain.

This is a separate identity and authorization boundary from the
organization domain (``app/models/platform.py`` + ``app/models/rbac.py``):

- Organization users (``users``/``memberships``/``roles``) belong to a
  customer organization and are scoped to it.
- Platform users (``platform_users``) are internal NULL personnel who
  administer the SaaS platform itself. They have their own identities,
  their own sessions, their own roles, and a SEPARATE permission
  namespace (``platform:*``, see ``app/permissions.py``).

The two domains must never be confused:
- No organization role can grant a ``platform:*`` permission (the org
  catalog contains no such code).
- No platform role can be assigned through the organization role editor.
- An organization administrator is never automatically a platform
  administrator (and vice versa); platform identities are created
  explicitly (bootstrap script or a Platform Administrator).
- Platform access to customer tenant data requires an explicit,
  time-boxed ``PlatformAccessGrant`` and is written to the platform
  audit log.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


class PlatformUser(Base):
    __tablename__ = "platform_users"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # TOTP secret, encrypted at rest in production (Secrets Manager/KMS).
    # Stored as an opaque base32 string, never a password.
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    # How this identity was created: bootstrap | invited | sso.
    source: Mapped[str] = mapped_column(String(20), nullable=False, server_default="invited")
    # approved | pending_review. Accounts that cannot be classified safely
    # during migration are flagged pending_review for manual review instead
    # of being guessed at.
    review_status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="approved")
    last_login_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    # foreign_keys is required: PlatformUserRole also references
    # platform_users via granted_by_id, so the join is ambiguous without it.
    roles: Mapped[list["PlatformUserRole"]] = relationship(
        back_populates="platform_user", foreign_keys="PlatformUserRole.platform_user_id"
    )


class PlatformPermission(Base):
    __tablename__ = "platform_permissions"

    id: Mapped[uuid.UUID] = uuid_pk()
    code: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    module: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = created_at_col()


class PlatformRole(Base):
    __tablename__ = "platform_roles"
    __table_args__ = (UniqueConstraint("name", name="uq_platform_role_name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # Full Access | Privileged | Least Privilege | Read-Only
    access_level: Mapped[str] = mapped_column(String(30), nullable=False, server_default="Least Privilege")
    is_system: Mapped[bool] = mapped_column(nullable=False, server_default="false")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    permissions: Mapped[list["PlatformRolePermission"]] = relationship(
        back_populates="role", cascade="all, delete-orphan"
    )


class PlatformRolePermission(Base):
    __tablename__ = "platform_role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="uq_platform_role_permission"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_permissions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = created_at_col()

    role: Mapped[PlatformRole] = relationship(back_populates="permissions")
    permission: Mapped[PlatformPermission] = relationship()


class PlatformUserRole(Base):
    __tablename__ = "platform_user_roles"
    __table_args__ = (UniqueConstraint("platform_user_id", "role_id", name="uq_platform_user_role"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    platform_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = created_at_col()

    platform_user: Mapped[PlatformUser] = relationship(back_populates="roles", foreign_keys=[platform_user_id])
    role: Mapped[PlatformRole] = relationship()


class PlatformSession(Base):
    __tablename__ = "platform_sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    platform_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    revoked_at: Mapped[datetime | None] = tz_col()
    # True when the session was established with MFA verified (MFA challenge,
    # or a login by a user with MFA disabled — nothing to step up from).
    # The refresh flow copies this into the new access token's `mfa` claim,
    # so a password-only login can never escalate to a privileged token.
    # Added in migration 0003.
    mfa_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()


class PlatformAccessGrant(Base):
    """Explicit, time-boxed authorization for a platform admin to read a
    customer tenant's data (support work). No grant, no tenant access.
    Every tenant read under a grant is written to the platform audit log."""

    __tablename__ = "platform_access_grants"

    id: Mapped[uuid.UUID] = uuid_pk()
    platform_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    # pending | active | revoked | expired
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PlatformAuditLog(Base):
    """Append-only platform audit log. Same rule as the org audit log:
    the RLS policy set contains no UPDATE or DELETE policy, and there is
    no update/delete API. ``organization_id`` is NULL for platform-wide
    events and set when the event touched a customer tenant."""

    __tablename__ = "platform_audit_logs"

    id: Mapped[uuid.UUID] = uuid_pk()
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(100), nullable=False)
    # success | failure | denied
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, server_default="success")
    # Attribute is `meta` because `metadata` is reserved by SQLAlchemy's
    # declarative API; the column name stays "metadata".
    meta: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
