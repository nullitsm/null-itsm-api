"""Dashboard widgets, report generation, and scheduled reports (migration 0015).

All numbers come from live rows at request time — nothing is cached,
stored, or invented:

- :func:`compute_widget_data` runs a real ``GROUP BY`` over the
  widget's entity with its filters applied.
- :func:`generate_report_rows` queries the report's entity with its
  filters and returns the requested columns.
- :func:`render_csv` renders those rows as CSV. Excel (``xlsx``) is
  NOT available: ``openpyxl`` is not installed in the venv, so an
  ``xlsx`` request fails honestly with 501 instead of pretending.
- :func:`generate_scheduled_report` is the Celery task
  (``reporting.generate_scheduled_report``) the coordinator wires to
  the beat schedule. It generates the report for one scheduled report
  and records the run outcome on the row. Email delivery of the
  generated file is NOT built — the task records the outcome and the
  coordinator wires delivery at integration (see the workstream
  report).
"""

from __future__ import annotations

import csv
import html
import io
import logging
import re
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.database import list_organization_ids, system_session, tenant_session
from app.models.endpoints import Endpoint
from app.models.reporting import Report, ScheduledReport
from app.models.ticket import Ticket
from app.models.vulnerabilities import VulnerabilityFinding
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks.reporting")

# --- Entity registry ----------------------------------------------------------
# The single source of truth for which entities widgets/reports may query
# and which columns may be grouped, filtered, or exported. Column names
# are validated against this registry — arbitrary column names from the
# client never reach SQL.

_ENTITY_MODELS = {
    "tickets": Ticket,
    "vulnerabilities": VulnerabilityFinding,
    "endpoints": Endpoint,
}

# Columns that may be used in widget group_by / filters and report filters.
_FILTERABLE_COLUMNS = {
    "tickets": {"status", "priority", "category", "requester_id", "assignee_id"},
    "vulnerabilities": {"severity", "status", "endpoint_id", "cve_id"},
    "endpoints": {"status", "os_name", "os_version", "arch"},
}

# Columns that may appear in a report's column list (superset of the
# filterable set: identifiers and timestamps are exportable, not groupable).
_REPORTABLE_COLUMNS = {
    "tickets": {
        "number", "title", "description", "status", "priority", "category",
        "requester_id", "assignee_id", "created_at", "updated_at", "resolved_at",
    },
    "vulnerabilities": {
        "cve_id", "severity", "status", "endpoint_id", "first_seen_at",
        "last_seen_at", "created_at",
    },
    "endpoints": {
        "hostname", "display_name", "os_name", "os_version", "arch",
        "serial_number", "status", "ip_address", "last_seen_at", "created_at",
    },
}

WIDGET_TYPES = {"count", "group_by"}
REPORT_FORMATS = {"csv"}


def _entity_model(entity: str):
    model = _ENTITY_MODELS.get(entity)
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"entity must be one of {sorted(_ENTITY_MODELS)}",
        )
    return model


def _apply_filters(query, model, filters: dict, allowed: set[str]):
    """Apply equality filters (scalar or list) to a select query.

    Callers must validate ``filters`` first with
    :func:`_validate_filters` — an unknown column here would raise an
    AttributeError instead of a clean 400.
    """
    for column, value in (filters or {}).items():
        attr = getattr(model, column)
        if isinstance(value, list):
            query = query.where(attr.in_(value))
        else:
            query = query.where(attr == value)
    return query


def _validate_filters(filters: dict, allowed: set[str]) -> dict:
    """Validate filter keys/values (400 on bad input)."""
    if not filters:
        return {}
    if not isinstance(filters, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="filters must be an object"
        )
    for column, value in filters.items():
        if column not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cannot filter on column '{column}'",
            )
        if isinstance(value, list) and not value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"filter '{column}' must not be an empty list",
            )
    return filters


# --- Widget queries -----------------------------------------------------------


def validate_widget_query(query: dict) -> dict:
    """Validate a widget query definition (400 on bad input).

    Shape: ``{"entity": "tickets", "group_by": "status",
    "filters": {"priority": "high"}}``. ``group_by`` is required for
    ``group_by`` widgets and forbidden for ``count`` widgets.
    Returns the normalized query (filters default to ``{}``).
    """
    if not isinstance(query, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="widget query must be an object"
        )
    entity = query.get("entity")
    _entity_model(entity)
    widget_type = query.get("widget_type", "count")
    if widget_type not in WIDGET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"widget_type must be one of {sorted(WIDGET_TYPES)}",
        )
    group_by = query.get("group_by")
    allowed = _FILTERABLE_COLUMNS[entity]
    if widget_type == "group_by":
        if group_by not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"group_by must be one of {sorted(allowed)} for entity '{entity}'",
            )
    elif group_by is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="group_by is only allowed for group_by widgets",
        )
    filters = query.get("filters") or {}
    # Validate filter columns now so a bad widget cannot be saved.
    _validate_filters(filters, allowed)
    return {"entity": entity, "widget_type": widget_type, "group_by": group_by, "filters": filters}


def compute_widget_data(session: Session, org_id: uuid.UUID, query: dict) -> dict:
    """Compute a widget's numbers from live rows.

    Returns ``{"entity", "widget_type", "group_by", "total", "groups"}``
    where ``groups`` is ``[{"group": value, "count": n}]`` sorted by
    count descending. ``total`` is the filtered row count; for a
    ``group_by`` widget it equals the sum of the group counts.
    """
    normalized = validate_widget_query(query)
    entity = normalized["entity"]
    model = _ENTITY_MODELS[entity]
    filters = normalized["filters"]

    if normalized["widget_type"] == "count":
        stmt = select(func.count()).where(model.organization_id == org_id)
        stmt = _apply_filters(stmt, model, filters, _FILTERABLE_COLUMNS[entity])
        total = session.execute(stmt).scalar_one()
        return {
            "entity": entity,
            "widget_type": "count",
            "group_by": None,
            "total": total,
            "groups": [],
        }

    group_col = getattr(model, normalized["group_by"])
    stmt = select(group_col, func.count()).where(model.organization_id == org_id)
    stmt = _apply_filters(stmt, model, filters, _FILTERABLE_COLUMNS[entity])
    rows = session.execute(stmt.group_by(group_col).order_by(func.count().desc(), group_col)).all()
    groups = [
        {"group": str(value) if value is not None else None, "count": count} for value, count in rows
    ]
    return {
        "entity": entity,
        "widget_type": "group_by",
        "group_by": normalized["group_by"],
        "total": sum(g["count"] for g in groups),
        "groups": groups,
    }


# --- Report definitions -------------------------------------------------------


def validate_report_definition(entity: str, columns: list, filters: dict) -> None:
    """Validate a report definition (400 on bad input)."""
    _entity_model(entity)
    allowed_columns = _REPORTABLE_COLUMNS[entity]
    if not isinstance(columns, list) or not columns:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="columns must be a non-empty list"
        )
    bad = [c for c in columns if c not in allowed_columns]
    if bad:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid columns for entity '{entity}': {bad}",
        )
    if len(set(columns)) != len(columns):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="columns must be unique"
        )
    _validate_filters(filters or {}, _FILTERABLE_COLUMNS[entity])


def _cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)


def generate_report_rows(session: Session, org_id: uuid.UUID, report: Report) -> tuple[list[str], list[dict]]:
    """Run a report definition against live rows.

    Returns ``(columns, rows)`` where each row maps column name to its
    (already stringified) value. Rows are ordered by creation time.
    """
    validate_report_definition(report.entity, report.columns, report.filters or {})
    model = _ENTITY_MODELS[report.entity]
    query = select(model).where(model.organization_id == org_id).order_by(model.created_at)
    query = _apply_filters(query, model, report.filters or {}, _FILTERABLE_COLUMNS[report.entity])
    records = session.execute(query).scalars().all()
    columns = list(report.columns)
    rows = [{col: _cell(getattr(record, col, None)) for col in columns} for record in records]
    return columns, rows


def render_csv(columns: list[str], rows: list[dict]) -> str:
    """Render report rows as CSV text (header + one row per record)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({col: row.get(col, "") for col in columns})
    return buf.getvalue()


# --- Cron expressions ---------------------------------------------------------
# croniter is not installed in the venv, so scheduled-report cron
# expressions are validated with a small strict parser: five fields
# (minute hour day-of-month month day-of-week), each a comma list of
# "*", "*/n", "a", "a-b", "a-b/n", or "a/n" with numeric bounds.
# Month / weekday names are not accepted — numbers only.

_CRON_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
_CRON_FIELD_RE = re.compile(r"^(\*|\d+|\d+-\d+)(/(\d+))?$")


def _cron_field_values(field: str, low: int, high: int) -> set[int]:
    """Expand one validated cron field to the values it matches."""
    values: set[int] = set()
    for part in field.split(","):
        match = _CRON_FIELD_RE.match(part)
        assert match is not None  # validated by validate_cron_expression
        base, _slash, step_s = match.groups()
        step = int(step_s) if step_s else 1
        if base == "*":
            start, end = low, high
        elif "-" in base:
            start, end = (int(v) for v in base.split("-"))
        else:
            start = end = int(base)
        values.update(range(start, end + 1, step))
    return values


def cron_matches(expression: str, when: datetime) -> bool:
    """True when a 5-field cron expression fires at ``when`` (UTC).

    The expression must already have passed
    :func:`validate_cron_expression`. Day-of-month and day-of-week
    follow standard cron semantics: when both are restricted (not
    ``*``) the job fires when EITHER matches; when one is ``*`` the
    other decides. Sunday is both 0 and 7.
    """
    fields = expression.strip().split()
    minute, hour, dom_s, month_s, dow_s = fields
    when = when.astimezone(timezone.utc)
    if when.minute not in _cron_field_values(minute, 0, 59):
        return False
    if when.hour not in _cron_field_values(hour, 0, 23):
        return False
    if when.month not in _cron_field_values(month_s, 1, 12):
        return False
    dom_values = _cron_field_values(dom_s, 1, 31)
    dow_values = _cron_field_values(dow_s, 0, 7)
    dow_values = {0 if v == 7 else v for v in dow_values}
    dom_restricted = dom_s != "*"
    dow_restricted = dow_s != "*"
    dom_match = when.day in dom_values
    dow_match = (when.isoweekday() % 7) in dow_values
    if dom_restricted and dow_restricted:
        return dom_match or dow_match
    if dom_restricted:
        return dom_match
    if dow_restricted:
        return dow_match
    return True


def validate_cron_expression(expression: str) -> None:
    """Validate a 5-field cron expression (400 on bad input)."""
    if not isinstance(expression, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cron_expression must be a string"
        )
    fields = expression.strip().split()
    if len(fields) != 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cron_expression must have 5 fields: minute hour day-of-month month day-of-week",
        )
    for field, (low, high) in zip(fields, _CRON_RANGES):
        for part in field.split(","):
            match = _CRON_FIELD_RE.match(part)
            if not match:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"invalid cron field: '{part}'",
                )
            base, _slash, step = match.groups()
            if step is not None and int(step) < 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"invalid cron step in '{part}'",
                )
            if base == "*":
                continue
            if "-" in base:
                start, end = (int(v) for v in base.split("-"))
                if not (low <= start <= high and low <= end <= high and start <= end):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"cron range '{base}' is out of bounds ({low}-{high})",
                    )
            else:
                value = int(base)
                if not low <= value <= high:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"cron value {value} is out of bounds ({low}-{high})",
                    )


# --- Scheduled-report execution ----------------------------------------------


def _deliver_scheduled_report(
    session: Session, scheduled: ScheduledReport, report: Report, csv_text: str, now: datetime
) -> dict:
    """Email the generated CSV to every address in ``scheduled.recipients``.

    One email per recipient (no CC/BCC — each delivery is recorded
    separately). The CSV rides as a ``.csv`` attachment; the bodies
    name the report, the row count, and the run time. Delivery is
    best-effort per recipient: a failure is recorded in the
    ``email_deliveries`` table and returned, but never fails the run —
    generation already succeeded, and the next scheduled run re-sends.
    ``retry=False`` because the CSV bytes live only in this call: the
    retry task re-sends from stored bodies, which would drop the
    attachment. A missing email configuration is a failure for every
    recipient, not a raise — this runs inside a Celery task.
    """
    from app.services import email as email_service

    recipients = [r for r in (scheduled.recipients or []) if isinstance(r, str) and r.strip()]
    filename = (
        "".join(ch if ch.isalnum() else "-" for ch in report.name.lower()).strip("-") or "report"
    ) + f"-{now:%Y%m%d-%H%M}.csv"
    csv_bytes = csv_text.encode("utf-8")
    subject = f"NULL ITSM scheduled report: {report.name}"
    html_body = (
        "<div style=\"font-family: Georgia, serif; color: #171614; background: #F2EBDD; padding: 24px;\">"
        "<p style=\"letter-spacing: 0.2em; font-size: 12px;\">NULL</p>"
        f"<h2 style=\"font-size: 20px;\">Scheduled report: {html.escape(report.name)}</h2>"
        f"<p>Your scheduled report ran at {now.isoformat()} and produced "
        f"{scheduled.last_row_count or 0} rows.</p>"
        f"<p>The CSV is attached: {html.escape(filename)} ({len(csv_bytes)} bytes).</p>"
        "<p>If you did not expect this report, contact your organization administrator.</p>"
        "</div>"
    )
    text_body = (
        f"NULL ITSM scheduled report: {report.name}\n\n"
        f"Your scheduled report ran at {now.isoformat()} and produced "
        f"{scheduled.last_row_count or 0} rows.\n"
        f"Attached: {filename} ({len(csv_bytes)} bytes).\n\n"
        "If you did not expect this report, contact your organization administrator.\n"
    )
    delivered_to: list[str] = []
    delivery_failed: list[dict] = []
    for recipient in recipients:
        try:
            result = email_service.deliver_email(
                session,
                organization_id=scheduled.organization_id,
                scope="org",
                to=recipient,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                template="scheduled_report",
                created_by_id=scheduled.created_by_id,
                attachments=[{"filename": filename, "content": csv_bytes}],
                retry=False,
            )
        except email_service.EmailConfigurationError as exc:
            delivery_failed.append({"to": recipient, "error": str(exc)[:500]})
            continue
        if result.delivered or result.dev_recorded:
            delivered_to.append(recipient)
        else:
            delivery_failed.append({"to": recipient, "error": result.error or "delivery failed"})
    return {"delivered_to": delivered_to, "delivery_failed": delivery_failed}


def run_scheduled_report(session: Session, scheduled: ScheduledReport) -> dict:
    """Generate one scheduled report, email it, and record the run outcome.

    Runs the report definition, records ``last_run_at`` /
    ``last_status`` / ``last_row_count`` on the scheduled row, emails
    the CSV to ``scheduled.recipients`` (one message per recipient,
    CSV attached), and writes a ``report.generated`` audit event whose
    metadata carries the per-recipient delivery outcome.
    ``last_status`` reflects GENERATION (``success`` / ``failed``):
    a delivery failure does not rewrite it — the delivery outcome is
    in the audit metadata, the returned summary, and the durable
    ``email_deliveries`` rows, and the next scheduled run re-sends.
    Returns a run summary.
    """
    report = session.get(Report, scheduled.report_id)
    if report is None or report.organization_id != scheduled.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled report's report not found"
        )
    now = datetime.now(timezone.utc)
    try:
        columns, rows = generate_report_rows(session, scheduled.organization_id, report)
        csv_text = render_csv(columns, rows)
        scheduled.last_run_at = now
        scheduled.last_status = "success"
        scheduled.last_row_count = len(rows)
        scheduled.last_error = None
        delivery = _deliver_scheduled_report(session, scheduled, report, csv_text, now)
        audit_mod.write_audit(
            session,
            organization_id=scheduled.organization_id,
            actor_id=scheduled.created_by_id,
            action=audit_mod.REPORT_GENERATED,
            resource_type="scheduled_report",
            resource_id=str(scheduled.id),
            outcome="success",
            metadata={
                "report_id": str(report.id),
                "row_count": len(rows),
                "format": scheduled.format,
                "delivered_to": delivery["delivered_to"],
                "delivery_failed": delivery["delivery_failed"],
            },
        )
        session.flush()
        return {
            "scheduled_report_id": str(scheduled.id),
            "report_id": str(report.id),
            "status": "success",
            "row_count": len(rows),
            "ran_at": now.isoformat(),
            "csv_bytes": len(csv_text.encode("utf-8")),
            "delivered_to": delivery["delivered_to"],
            "delivery_failed": delivery["delivery_failed"],
        }
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - defensive; generation errors are 400s
        logger.exception("scheduled report %s failed", scheduled.id)
        scheduled.last_run_at = now
        scheduled.last_status = "failed"
        scheduled.last_row_count = None
        scheduled.last_error = str(exc)[:500]
        session.flush()
        return {
            "scheduled_report_id": str(scheduled.id),
            "report_id": str(report.id),
            "status": "failed",
            "row_count": 0,
            "ran_at": now.isoformat(),
            "error": str(exc)[:500],
        }


@celery_app.task(name="reporting.generate_scheduled_report")
def generate_scheduled_report(scheduled_report_id: str) -> dict:
    """Celery task: generate one scheduled report by id.

    The coordinator wires this into the beat schedule (one entry per
    active scheduled report, or a periodic sweep that calls this task
    per schedule — the task itself is idempotent per run: it regenerates
    from live rows and overwrites the last-run fields).
    """
    try:
        target = uuid.UUID(scheduled_report_id)
    except ValueError:
        return {"status": "failed", "error": f"invalid scheduled_report_id: {scheduled_report_id}"}
    with system_session() as session:
        org_ids = list_organization_ids(session)
    for org_id in org_ids:
        with tenant_session(org_id) as session:
            scheduled = session.get(ScheduledReport, target)
            if scheduled is None:
                continue
            if not scheduled.is_active:
                return {
                    "scheduled_report_id": scheduled_report_id,
                    "status": "skipped",
                    "reason": "scheduled report is inactive",
                }
            return run_scheduled_report(session, scheduled)
    return {"scheduled_report_id": scheduled_report_id, "status": "failed", "error": "scheduled report not found"}
