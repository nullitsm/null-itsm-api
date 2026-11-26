"""Registration + onboarding + invitation models (migration 0013).

- ``departments`` / ``teams``: organization structure. Created with
  defaults at registration; managed through the org API and onboarding.
- ``org_onboarding``: one row per organization tracking the guided
  setup flow (profile → departments → invite technicians → service
  desk → business hours/SLA → assets/endpoints → finish). Steps are
  skippable where optional; progress is stored per org.
- ``platform_invitations``: invitations into the platform
  administration domain (internal NULL personnel only). Separate table,
  separate flow, separate authorization from org invitations — an org
  invitation can never create a platform admin.
- ``dev_email_outbox``: local-testing record of emails the backend
  would have sent. Written only when no SMTP host is configured (dev);
  in production with SMTP configured nothing is recorded here. The
  invitation link is also returned to the inviting admin in the API
  response for testing. Append-only (SELECT + INSERT).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk(nullable: bool = False) -> Mapped[uuid.UUID | None]:
    return mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=nullable,
        index=True,
    )


class Department(Base):
    __tablename__ = "departments"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_department_org_name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class Team(Base):
    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("organization_id", "department_id", "name", name="uq_team_org_dept_name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    department_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


ONBOARDING_STEPS = [
    "profile",
    "departments",
    "invite_technicians",
    "service_desk",
    "business_hours_sla",
    "assets_endpoints",
    "finish",
]

# Steps that may be skipped. Profile is completed by registration itself;
# finish requires every other step to be complete or skipped.
SKIPPABLE_STEPS = {"departments", "invite_technicians", "service_desk", "business_hours_sla", "assets_endpoints"}


class OrgOnboarding(Base):
    __tablename__ = "org_onboarding"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    current_step: Mapped[str] = mapped_column(String(40), nullable=False, server_default="departments")
    # {step: "pending" | "in_progress" | "complete" | "skipped"}
    steps: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    completed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PlatformInvitation(Base):
    __tablename__ = "platform_invitations"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    invited_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("platform_roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # pending | accepted | expired | revoked
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    accepted_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()


class DevEmailOutbox(Base):
    __tablename__ = "dev_email_outbox"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = _org_fk(nullable=True)
    # 'org' | 'platform'
    scope: Mapped[str] = mapped_column(String(20), nullable=False, server_default="org")
    to_email: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = created_at_col()
