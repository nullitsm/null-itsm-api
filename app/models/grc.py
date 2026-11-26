"""GRC models (Phase 4 workstream D, migration 0017).

Every table here is tenant-owned: ``organization_id`` FK to organizations
(CASCADE, NOT NULL, indexed) plus ``created_at`` / ``updated_at``.
Row-Level Security policies live in migration 0017 (standard org-scoped
ALL policy).

Honesty rules (see docs/DATA_MODEL.md, "Honesty rule"): GRC helps
customers manage compliance; it does NOT certify NULL or the customer.
``GrcControl.status`` is DERIVED — never set by a client — from the
latest assessment covering the control and from active exceptions:

* an active (unexpired, unrevoked) exception  -> ``exception``
* latest assessment ``passed``                -> ``satisfied``
* latest assessment ``failed``                -> ``failed``
* latest assessment ``in_progress``           -> ``in_progress``
* no assessment                               -> ``not_assessed``

A control is never presented as "compliant": ``satisfied`` means only
that the latest assessment of that control passed on the evidence
recorded at the time. Evidence rows are metadata pointing at real
artifacts (a stored reference and/or a link to an existing entity in
the same org) — never file bytes, never invented outcomes.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable)


# Control statuses — derived only, never client-set.
CONTROL_STATUSES = {"not_assessed", "in_progress", "satisfied", "exception", "failed"}

# Frameworks a control mapping may reference.
FRAMEWORKS = {"soc2", "iso27001", "nist_csf", "cis"}

# Assessment outcomes. ``passed`` derives a control to ``satisfied``;
# ``failed`` derives it to ``failed``; ``in_progress`` to ``in_progress``.
ASSESSMENT_STATUSES = {"in_progress", "passed", "failed"}


class GrcControl(Base):
    """One compliance control tracked by an org.

    ``status`` is maintained by ``app.services.grc_service`` from
    assessments and exceptions; the API never accepts it from a client.
    """

    __tablename__ = "grc_controls"
    __table_args__ = (UniqueConstraint("organization_id", "code", name="uq_grc_control_org_code"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    owner_id: Mapped[uuid.UUID | None] = _user_fk()
    # not_assessed | in_progress | satisfied | exception | failed (derived)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="not_assessed")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class GrcControlMapping(Base):
    """One framework-clause mapping for a control.

    ``framework`` is one of soc2 | iso27001 | nist_csf | cis; ``clause``
    is the framework's own clause/control identifier (e.g. ``CC6.1``,
    ``A.5.1``, ``PR.AC-1``, ``CIS 3.3``).
    """

    __tablename__ = "grc_control_mappings"
    __table_args__ = (
        UniqueConstraint("control_id", "framework", "clause", name="uq_grc_mapping_control_framework_clause"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("grc_controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework: Mapped[str] = mapped_column(String(20), nullable=False)
    clause: Mapped[str] = mapped_column(String(100), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class GrcEvidence(Base):
    """Evidence for a control: metadata pointing at a real artifact.

    Either a stored ``reference`` (URL, document id, or other stable
    pointer supplied by the operator) or a link to an existing entity
    in the same org (``linked_entity_type`` + ``linked_entity_id``,
    validated on write against the linkable-entity allow-list), or
    both. No file bytes are stored here.
    """

    __tablename__ = "grc_evidence"
    __table_args__ = (UniqueConstraint("control_id", "title", name="uq_grc_evidence_control_title"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("grc_controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    # reference | link | document — how the artifact is identified.
    evidence_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="reference")
    reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    linked_entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    linked_entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    collected_by_id: Mapped[uuid.UUID | None] = _user_fk()
    collected_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class GrcAssessment(Base):
    """One assessment of a set of controls.

    Controls are attached via ``grc_assessment_controls``. ``status``
    is the assessor's recorded outcome (in_progress | passed | failed);
    ``findings`` is the assessor's own list of findings (JSONB list of
    objects with at least a title). Nothing here certifies anything:
    a ``passed`` assessment is a recorded outcome for the controls it
    covers, nothing more.
    """

    __tablename__ = "grc_assessments"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # in_progress | passed | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="in_progress")
    summary: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    findings: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    assessor_id: Mapped[uuid.UUID | None] = _user_fk()
    assessed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class GrcAssessmentControl(Base):
    """Join: which controls one assessment covers."""

    __tablename__ = "grc_assessment_controls"
    __table_args__ = (UniqueConstraint("assessment_id", "control_id", name="uq_grc_assessment_control"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("grc_assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("grc_controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = created_at_col()


class GrcException(Base):
    """A time-boxed exception for one control.

    ``expires_at`` is required — an exception always ends. Effective
    status is derived at read time (see ``grc_service``): ``revoked``
    when ``revoked_at`` is set, ``expired`` when ``expires_at`` has
    passed, otherwise ``active``. An active exception derives its
    control to ``exception``.
    """

    __tablename__ = "grc_exceptions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("grc_controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    approver_id: Mapped[uuid.UUID | None] = _user_fk()
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    revoked_at: Mapped[datetime | None] = tz_col()
    revoked_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
