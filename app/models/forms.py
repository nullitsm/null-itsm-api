"""Custom forms, fields, and submitted field values (migration 0015).

Phase 4 workstream B — custom forms / dashboards / reports.

- ``custom_forms``: an org-scoped form builder definition. A form
  targets one entity type today (``ticket``); the target is stored so
  other entities can be added later without a schema change.
- ``custom_fields``: ordered fields belonging to a form. Types:
  text, number, select, multi_select, date, boolean, user. Select
  fields carry their options; validation rules (min/max, length,
  pattern) live in the ``validation`` JSONB column.
- ``field_values``: submitted values attached to a real entity
  (``entity_type`` + ``entity_id``; tickets first). One value per
  (field, entity) — enforced by a unique constraint. Values are
  validated server-side in :mod:`app.services.forms_service` before
  they are stored; the JSONB column itself holds the typed value
  (string, number, bool, list, or ISO date string).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, updated_at_col, uuid_pk


def _org_fk(nullable: bool = False) -> Mapped[uuid.UUID | None]:
    return mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=nullable,
        index=True,
    )


FIELD_TYPES = {"text", "number", "select", "multi_select", "date", "boolean", "user"}

# Entity types a form may target. Tickets first; other entities are a
# future extension (the column is validated in the service layer).
FORM_TARGET_TYPES = {"ticket"}


class CustomForm(Base):
    __tablename__ = "custom_forms"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_custom_form_org_name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    target_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ticket")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class CustomField(Base):
    __tablename__ = "custom_fields"
    __table_args__ = (
        UniqueConstraint("form_id", "key", name="uq_custom_field_form_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    form_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("custom_forms.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Machine key used when submitting values, e.g. "business_unit".
    key: Mapped[str] = mapped_column(String(100), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    # text | number | select | multi_select | date | boolean | user
    field_type: Mapped[str] = mapped_column(String(20), nullable=False)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    position: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # Allowed values for select / multi_select (list of strings).
    options: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    # Validation rules, e.g. {"min": 0, "max": 100} for number,
    # {"min_length": 2, "max_length": 200, "pattern": "^...$"} for text.
    validation: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class FieldValue(Base):
    __tablename__ = "field_values"
    __table_args__ = (
        UniqueConstraint("field_id", "entity_type", "entity_id", name="uq_field_value_field_entity"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    form_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("custom_forms.id", ondelete="CASCADE"), nullable=False, index=True
    )
    field_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("custom_fields.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # 'ticket' today; the column is generic for future entity types.
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ticket")
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    # The submitted value, stored as JSON (string, number, bool, list of
    # strings, or ISO date string, depending on the field type).
    value: Mapped[object] = mapped_column(JSONB, nullable=False)
    submitted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
