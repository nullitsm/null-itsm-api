"""Dashboards + reports API.

Two routers in this module:

- ``dashboards_router`` — prefix ``/api/v1/dashboards``: dashboard
  CRUD, widget CRUD, and computed widget data (real rows, request time).
- ``reports_router`` — prefix ``/api/v1/reports``: report definition
  CRUD, on-demand generation (real CSV download), and scheduled-report
  CRUD + run-now.

Request/response models are defined locally in this module (the
coordinator centralizes schemas at integration).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.reporting import Dashboard, DashboardWidget, Report, ScheduledReport
from app.services import reporting_service
from app.services.itsm_service import get_org_row
from app.services.reporting_service import (
    compute_widget_data,
    generate_report_rows,
    render_csv,
    run_scheduled_report,
    validate_cron_expression,
    validate_report_definition,
    validate_widget_query,
)

# Audit actions for this module. These literals are not yet constants in
# Audit actions use the centralized constants in app/audit.py.


# --- Schemas (local to this router) -------------------------------------------


class DashboardCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    is_default: bool = False


class DashboardUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    is_default: bool | None = None


class WidgetCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    widget_type: str = "count"
    query: dict = {}
    position: int = 0


class WidgetUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    widget_type: str | None = None
    query: dict | None = None
    position: int | None = None


class WidgetOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    dashboard_id: uuid.UUID
    title: str
    widget_type: str
    query: dict
    position: int
    created_at: datetime
    updated_at: datetime


class DashboardOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    is_default: bool
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    widgets: list[WidgetOut] = []


class WidgetDataOut(BaseModel):
    widget_id: uuid.UUID
    entity: str
    widget_type: str
    group_by: str | None
    total: int
    groups: list[dict]


class DashboardDataOut(BaseModel):
    dashboard_id: uuid.UUID
    widgets: list[WidgetDataOut]


class ReportCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    entity: str
    columns: list[str] = []
    filters: dict = {}


class ReportUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    entity: str | None = None
    columns: list[str] | None = None
    filters: dict | None = None


class ReportOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    entity: str
    columns: list
    filters: dict
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class ScheduleCreate(BaseModel):
    cron_expression: str
    recipients: list[str] = []
    format: str = "csv"
    is_active: bool = True


class ScheduleUpdate(BaseModel):
    cron_expression: str | None = None
    recipients: list[str] | None = None
    format: str | None = None
    is_active: bool | None = None


class ScheduleOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    report_id: uuid.UUID
    cron_expression: str
    recipients: list
    format: str
    is_active: bool
    last_run_at: datetime | None
    last_status: str
    last_row_count: int | None
    last_error: str | None
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class ScheduleRunOut(BaseModel):
    scheduled_report_id: str
    report_id: str
    status: str
    row_count: int
    ran_at: str
    csv_bytes: int | None = None
    error: str | None = None


# --- Helpers ------------------------------------------------------------------


def _audit(
    session: Session, principal: Principal, action: str, resource_type: str, resource_id: str, **meta
) -> None:
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="success",
        metadata=meta,
    )


def _widget_out(w: DashboardWidget) -> WidgetOut:
    return WidgetOut(
        id=w.id,
        organization_id=w.organization_id,
        dashboard_id=w.dashboard_id,
        title=w.title,
        widget_type=w.widget_type,
        query=w.query or {},
        position=w.position,
        created_at=w.created_at,
        updated_at=w.updated_at,
    )


def _dashboard_out(d: Dashboard, widgets: list[DashboardWidget]) -> DashboardOut:
    return DashboardOut(
        id=d.id,
        organization_id=d.organization_id,
        name=d.name,
        description=d.description,
        is_default=d.is_default,
        created_by_id=d.created_by_id,
        created_at=d.created_at,
        updated_at=d.updated_at,
        widgets=[_widget_out(w) for w in widgets],
    )


def _load_widgets(session: Session, dashboard_id: uuid.UUID) -> list[DashboardWidget]:
    return session.execute(
        select(DashboardWidget)
        .where(DashboardWidget.dashboard_id == dashboard_id)
        .order_by(DashboardWidget.position, DashboardWidget.created_at)
    ).scalars().all()


def _get_dashboard(session: Session, principal: Principal, dashboard_id: uuid.UUID) -> Dashboard:
    return get_org_row(session, Dashboard, dashboard_id, principal.organization_id)


def _get_widget(session: Session, dashboard: Dashboard, widget_id: uuid.UUID) -> DashboardWidget:
    widget = session.get(DashboardWidget, widget_id)
    if widget is None or widget.dashboard_id != dashboard.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Widget not found")
    return widget


def _report_out(r: Report) -> ReportOut:
    return ReportOut(
        id=r.id,
        organization_id=r.organization_id,
        name=r.name,
        description=r.description,
        entity=r.entity,
        columns=r.columns or [],
        filters=r.filters or {},
        created_by_id=r.created_by_id,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _schedule_out(s: ScheduledReport) -> ScheduleOut:
    return ScheduleOut(
        id=s.id,
        organization_id=s.organization_id,
        report_id=s.report_id,
        cron_expression=s.cron_expression,
        recipients=s.recipients or [],
        format=s.format,
        is_active=s.is_active,
        last_run_at=s.last_run_at,
        last_status=s.last_status,
        last_row_count=s.last_row_count,
        last_error=s.last_error,
        created_by_id=s.created_by_id,
        created_at=s.created_at,
        updated_at=s.updated_at,
    )


def _get_report(session: Session, principal: Principal, report_id: uuid.UUID) -> Report:
    return get_org_row(session, Report, report_id, principal.organization_id)


def _get_schedule(session: Session, report: Report, schedule_id: uuid.UUID) -> ScheduledReport:
    schedule = session.get(ScheduledReport, schedule_id)
    if schedule is None or schedule.report_id != report.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled report not found")
    return schedule


def _validate_recipients(recipients: list[str]) -> None:
    if not isinstance(recipients, list) or not all(isinstance(r, str) and "@" in r for r in recipients):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="recipients must be a list of email addresses",
        )


# --- Dashboards ---------------------------------------------------------------

dashboards_router = APIRouter(prefix="/api/v1/dashboards", tags=["dashboards"])


@dashboards_router.post("", response_model=DashboardOut, status_code=status.HTTP_201_CREATED)
def create_dashboard(
    body: DashboardCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:manage")),
):
    dashboard = Dashboard(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        is_default=body.is_default,
        created_by_id=principal.user_id,
    )
    session.add(dashboard)
    session.flush()
    _audit(session, principal, audit_mod.DASHBOARD_CREATED, "dashboard", str(dashboard.id), name=dashboard.name)
    out = _dashboard_out(dashboard, [])
    session.commit()
    return out


@dashboards_router.get("", response_model=list[DashboardOut])
def list_dashboards(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:read")),
):
    rows = session.execute(
        select(Dashboard)
        .where(Dashboard.organization_id == principal.organization_id)
        .order_by(Dashboard.name)
    ).scalars().all()
    return [_dashboard_out(d, _load_widgets(session, d.id)) for d in rows]


@dashboards_router.get("/{dashboard_id}", response_model=DashboardOut)
def get_dashboard(
    dashboard_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:read")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    return _dashboard_out(dashboard, _load_widgets(session, dashboard.id))


@dashboards_router.patch("/{dashboard_id}", response_model=DashboardOut)
def update_dashboard(
    dashboard_id: uuid.UUID,
    body: DashboardUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:manage")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    if body.name is not None:
        dashboard.name = body.name
    if body.description is not None:
        dashboard.description = body.description
    if body.is_default is not None:
        dashboard.is_default = body.is_default
    session.flush()
    _audit(session, principal, audit_mod.DASHBOARD_UPDATED, "dashboard", str(dashboard.id), name=dashboard.name)
    out = _dashboard_out(dashboard, _load_widgets(session, dashboard.id))
    session.commit()
    return out


@dashboards_router.delete("/{dashboard_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dashboard(
    dashboard_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:manage")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    session.delete(dashboard)
    _audit(session, principal, audit_mod.DASHBOARD_DELETED, "dashboard", str(dashboard.id), name=dashboard.name)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@dashboards_router.post(
    "/{dashboard_id}/widgets", response_model=WidgetOut, status_code=status.HTTP_201_CREATED
)
def add_widget(
    dashboard_id: uuid.UUID,
    body: WidgetCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:manage")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    merged = dict(body.query or {})
    if "widget_type" in merged and merged["widget_type"] != body.widget_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="query.widget_type must match widget_type",
        )
    merged["widget_type"] = body.widget_type
    normalized = validate_widget_query(merged)
    widget = DashboardWidget(
        organization_id=principal.organization_id,
        dashboard_id=dashboard.id,
        title=body.title,
        widget_type=body.widget_type,
        query=normalized,
        position=body.position,
    )
    session.add(widget)
    session.flush()
    _audit(
        session, principal, audit_mod.DASHBOARD_WIDGET_CREATED, "dashboard_widget", str(widget.id),
        dashboard_id=str(dashboard.id), title=widget.title,
    )
    out = _widget_out(widget)
    session.commit()
    return out


@dashboards_router.patch("/{dashboard_id}/widgets/{widget_id}", response_model=WidgetOut)
def update_widget(
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    body: WidgetUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:manage")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    widget = _get_widget(session, dashboard, widget_id)
    new_type = body.widget_type if body.widget_type is not None else widget.widget_type
    new_query = body.query if body.query is not None else (widget.query or {})
    merged = dict(new_query)
    if "widget_type" in merged and merged["widget_type"] != new_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="query.widget_type must match widget_type",
        )
    merged["widget_type"] = new_type
    if "entity" not in merged:
        merged["entity"] = (widget.query or {}).get("entity")
    normalized = validate_widget_query(merged)
    if body.title is not None:
        widget.title = body.title
    widget.widget_type = new_type
    widget.query = normalized
    if body.position is not None:
        widget.position = body.position
    session.flush()
    _audit(
        session, principal, audit_mod.DASHBOARD_WIDGET_UPDATED, "dashboard_widget", str(widget.id),
        dashboard_id=str(dashboard.id), title=widget.title,
    )
    out = _widget_out(widget)
    session.commit()
    return out


@dashboards_router.delete("/{dashboard_id}/widgets/{widget_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_widget(
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:manage")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    widget = _get_widget(session, dashboard, widget_id)
    session.delete(widget)
    _audit(
        session, principal, audit_mod.DASHBOARD_WIDGET_DELETED, "dashboard_widget", str(widget.id),
        dashboard_id=str(dashboard.id), title=widget.title,
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@dashboards_router.get("/{dashboard_id}/data", response_model=DashboardDataOut)
def get_dashboard_data(
    dashboard_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:read")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    widgets = _load_widgets(session, dashboard.id)
    data = []
    for widget in widgets:
        computed = compute_widget_data(session, principal.organization_id, widget.query or {})
        data.append(
            WidgetDataOut(
                widget_id=widget.id,
                entity=computed["entity"],
                widget_type=computed["widget_type"],
                group_by=computed["group_by"],
                total=computed["total"],
                groups=computed["groups"],
            )
        )
    return DashboardDataOut(dashboard_id=dashboard.id, widgets=data)


@dashboards_router.get("/{dashboard_id}/widgets/{widget_id}/data", response_model=WidgetDataOut)
def get_widget_data(
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboards:read")),
):
    dashboard = _get_dashboard(session, principal, dashboard_id)
    widget = _get_widget(session, dashboard, widget_id)
    computed = compute_widget_data(session, principal.organization_id, widget.query or {})
    return WidgetDataOut(
        widget_id=widget.id,
        entity=computed["entity"],
        widget_type=computed["widget_type"],
        group_by=computed["group_by"],
        total=computed["total"],
        groups=computed["groups"],
    )


# --- Reports ------------------------------------------------------------------

reports_router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@reports_router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def create_report(
    body: ReportCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:manage")),
):
    validate_report_definition(body.entity, body.columns, body.filters or {})
    report = Report(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        entity=body.entity,
        columns=body.columns,
        filters=body.filters or {},
        created_by_id=principal.user_id,
    )
    session.add(report)
    session.flush()
    _audit(session, principal, audit_mod.REPORT_CREATED, "report", str(report.id), name=report.name)
    out = _report_out(report)
    session.commit()
    return out


@reports_router.get("", response_model=list[ReportOut])
def list_reports(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:read")),
):
    rows = session.execute(
        select(Report).where(Report.organization_id == principal.organization_id).order_by(Report.name)
    ).scalars().all()
    return [_report_out(r) for r in rows]


@reports_router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:read")),
):
    return _report_out(_get_report(session, principal, report_id))


@reports_router.patch("/{report_id}", response_model=ReportOut)
def update_report(
    report_id: uuid.UUID,
    body: ReportUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:manage")),
):
    report = _get_report(session, principal, report_id)
    entity = body.entity if body.entity is not None else report.entity
    columns = body.columns if body.columns is not None else (report.columns or [])
    filters = body.filters if body.filters is not None else (report.filters or {})
    validate_report_definition(entity, columns, filters)
    if body.name is not None:
        report.name = body.name
    if body.description is not None:
        report.description = body.description
    report.entity = entity
    report.columns = columns
    report.filters = filters
    session.flush()
    _audit(session, principal, audit_mod.REPORT_UPDATED, "report", str(report.id), name=report.name)
    out = _report_out(report)
    session.commit()
    return out


@reports_router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:manage")),
):
    report = _get_report(session, principal, report_id)
    session.delete(report)
    _audit(session, principal, audit_mod.REPORT_DELETED, "report", str(report.id), name=report.name)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@reports_router.post("/{report_id}/generate")
def generate_report(
    report_id: uuid.UUID,
    format: str = Query(default="csv"),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:export")),
):
    """Generate a report on demand and download it as a file.

    CSV is the supported format. ``xlsx`` is answered honestly with
    501: ``openpyxl`` is not installed in the venv, so no Excel file
    can be produced.
    """
    report = _get_report(session, principal, report_id)
    if format not in {"csv", "xlsx"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="format must be 'csv' or 'xlsx'"
        )
    if format == "xlsx":
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Excel export requires openpyxl, which is not installed",
        )
    columns, rows = generate_report_rows(session, principal.organization_id, report)
    csv_text = render_csv(columns, rows)
    _audit(
        session, principal, audit_mod.REPORT_GENERATED, "report", str(report.id),
        name=report.name, format=format, row_count=len(rows),
    )
    session.commit()
    filename = f"{report.name.lower().replace(' ', '-') or 'report'}.csv"
    return StreamingResponse(
        iter([csv_text]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --- Scheduled reports --------------------------------------------------------
# Static sub-paths (/{report_id}/schedules) are registered before the
# /{report_id}/schedules/{schedule_id} routes; none of them collide with
# the single-segment /{report_id} routes above.


@reports_router.post(
    "/{report_id}/schedules", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED
)
def create_schedule(
    report_id: uuid.UUID,
    body: ScheduleCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:manage")),
):
    report = _get_report(session, principal, report_id)
    validate_cron_expression(body.cron_expression)
    _validate_recipients(body.recipients)
    if body.format not in reporting_service.REPORT_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"format must be one of {sorted(reporting_service.REPORT_FORMATS)}",
        )
    schedule = ScheduledReport(
        organization_id=principal.organization_id,
        report_id=report.id,
        cron_expression=body.cron_expression,
        recipients=body.recipients,
        format=body.format,
        is_active=body.is_active,
        created_by_id=principal.user_id,
    )
    session.add(schedule)
    session.flush()
    _audit(
        session, principal, audit_mod.REPORT_SCHEDULE_CREATED, "scheduled_report", str(schedule.id),
        report_id=str(report.id), cron=body.cron_expression,
    )
    out = _schedule_out(schedule)
    session.commit()
    return out


@reports_router.get("/{report_id}/schedules", response_model=list[ScheduleOut])
def list_schedules(
    report_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:read")),
):
    report = _get_report(session, principal, report_id)
    rows = session.execute(
        select(ScheduledReport)
        .where(ScheduledReport.report_id == report.id)
        .order_by(ScheduledReport.created_at)
    ).scalars().all()
    return [_schedule_out(s) for s in rows]


@reports_router.patch("/{report_id}/schedules/{schedule_id}", response_model=ScheduleOut)
def update_schedule(
    report_id: uuid.UUID,
    schedule_id: uuid.UUID,
    body: ScheduleUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:manage")),
):
    report = _get_report(session, principal, report_id)
    schedule = _get_schedule(session, report, schedule_id)
    if body.cron_expression is not None:
        validate_cron_expression(body.cron_expression)
        schedule.cron_expression = body.cron_expression
    if body.recipients is not None:
        _validate_recipients(body.recipients)
        schedule.recipients = body.recipients
    if body.format is not None:
        if body.format not in reporting_service.REPORT_FORMATS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"format must be one of {sorted(reporting_service.REPORT_FORMATS)}",
            )
        schedule.format = body.format
    if body.is_active is not None:
        schedule.is_active = body.is_active
    session.flush()
    _audit(
        session, principal, audit_mod.REPORT_SCHEDULE_UPDATED, "scheduled_report", str(schedule.id),
        report_id=str(report.id),
    )
    out = _schedule_out(schedule)
    session.commit()
    return out


@reports_router.delete("/{report_id}/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    report_id: uuid.UUID,
    schedule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:manage")),
):
    report = _get_report(session, principal, report_id)
    schedule = _get_schedule(session, report, schedule_id)
    session.delete(schedule)
    _audit(
        session, principal, audit_mod.REPORT_SCHEDULE_DELETED, "scheduled_report", str(schedule.id),
        report_id=str(report.id),
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@reports_router.post("/{report_id}/schedules/{schedule_id}/run", response_model=ScheduleRunOut)
def run_schedule_now(
    report_id: uuid.UUID,
    schedule_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports:export")),
):
    """Run a scheduled report synchronously (same code the Celery task
    runs) and return the run summary. Useful for testing and for an
    admin-triggered immediate run; the beat schedule is wired by the
    coordinator at integration."""
    report = _get_report(session, principal, report_id)
    schedule = _get_schedule(session, report, schedule_id)
    if not schedule.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Scheduled report is inactive"
        )
    summary = run_scheduled_report(session, schedule)
    session.commit()
    return ScheduleRunOut(**summary)
