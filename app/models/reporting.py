"""Dashboards, widgets, reports, and scheduled reports (migration 0015).

Phase 4 workstream B — custom forms / dashboards / reports.

- ``dashboards`` + ``dashboard_widgets``: an org-scoped dashboard holds
  widgets. A widget stores a *query definition* (entity + grouping +
  filters) — never a precomputed count. Its data endpoint computes the
  numbers from actual rows at request time (see
  :func:`app.services.reporting_service.compute_widget_data`), so a
  widget can never show an invented statistic.
- ``reports``: a report definition (entity + columns + filters).
  On-demand generation queries the live database and renders a real
  downloadable CSV (see :func:`app.services.reporting_service.generate_report_rows`).
- ``scheduled_reports``: a cron schedule + recipients for a report.
  The Celery task ``reporting.generate_scheduled_report`` (defined in
  :mod:`app.services.reporting_service`) generates the report and
  records the run outcome (``last_run_at`` / ``last_status`` /
  ``last_row_count``). Email delivery of the generated file is NOT
  built here — the task records the outcome honestly and the
  coordinator wires delivery at integration (see the workstream
  report).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
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


# Widget kinds. "count" returns a single total; "group_by" returns one
# count per distinct value of the grouping column.
WIDGET_TYPES = {"count", "group_by"}

# Entities a widget or report may query. Columns are whitelisted in
# app/services/reporting_service.py — the registry there is the source
# of truth for groupable/filterable/reportable columns.
REPORT_ENTITIES = {"tickets", "vulnerabilities", "endpoints"}


class Dashboard(Base):
    __tablename__ = "dashboards"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class DashboardWidget(Base):
    __tablename__ = "dashboard_widgets"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    dashboard_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dashboards.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    # count | group_by
    widget_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="count")
    # Query definition, e.g.:
    #   {"entity": "tickets", "group_by": "status",
    #    "filters": {"priority": "high"}}
    # Grouping/filter columns are validated against the registry in
    # app/services/reporting_service.py.
    query: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    position: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # tickets | vulnerabilities | endpoints
    entity: Mapped[str] = mapped_column(String(30), nullable=False)
    # Ordered column names, validated against the entity registry.
    columns: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    # Equality filters, e.g. {"status": "open"} or
    # {"priority": ["high", "critical"]}.
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Standard 5-field cron expression (minute hour day-of-month month
    # day-of-week), validated in app/services/reporting_service.py.
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    # Recipient email addresses (list of strings).
    recipients: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    # Output format for the scheduled run: "csv" today.
    format: Mapped[str] = mapped_column(String(10), nullable=False, server_default="csv")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    # Outcome of the most recent run (written by the Celery task).
    # last_status: never_run | success | failed
    last_run_at: Mapped[datetime | None] = tz_col()
    last_status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="never_run")
    last_row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
