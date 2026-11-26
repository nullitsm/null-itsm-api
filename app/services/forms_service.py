"""Custom-form value validation and submission (migration 0015).

Server-side validation for ``field_values``: every submitted value is
checked against its field definition — required presence, JSON type,
select/multi-select membership, number bounds, text length/pattern,
ISO date shape, and (for ``user`` fields) that the referenced user is
an active member of the organization. Invalid values are rejected
with 400 and nothing is stored.
"""

from __future__ import annotations

import re
import uuid
from datetime import date

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.forms import FIELD_TYPES, CustomField, CustomForm, FieldValue
from app.models.platform import Membership
from app.models.ticket import Ticket

# --- Field-definition validation --------------------------------------------


def validate_field_definition(field: dict) -> None:
    """Validate a field definition dict (400 on bad input).

    ``field`` carries key, label, field_type, required, position,
    options, validation. Select fields must carry at least one option;
    non-select fields must not carry options.
    """
    field_type = field.get("field_type")
    if field_type not in FIELD_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"field_type must be one of {sorted(FIELD_TYPES)}",
        )
    key = field.get("key") or ""
    if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="field key must be lowercase snake_case starting with a letter",
        )
    label = field.get("label") or ""
    if not isinstance(label, str) or not label.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="field label is required"
        )
    options = field.get("options") or []
    if field_type in {"select", "multi_select"}:
        if not isinstance(options, list) or not options or not all(isinstance(o, str) and o for o in options):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_type} fields require a non-empty list of string options",
            )
        if len(set(options)) != len(options):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="field options must be unique"
            )
    elif options:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_type} fields do not take options",
        )
    validation = field.get("validation") or {}
    if not isinstance(validation, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="field validation must be an object"
        )
    if field_type == "number":
        for bound in ("min", "max"):
            if bound in validation and not isinstance(validation[bound], (int, float)):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"validation.{bound} must be a number",
                )
        if "min" in validation and "max" in validation and validation["min"] > validation["max"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="validation.min must not exceed validation.max"
            )
    if field_type == "text":
        for bound in ("min_length", "max_length"):
            if bound in validation and (not isinstance(validation[bound], int) or validation[bound] < 0):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"validation.{bound} must be a non-negative integer",
                )
        if "pattern" in validation:
            try:
                re.compile(validation["pattern"])
            except re.error:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="validation.pattern is not a valid regex"
                )


def validate_field_value(session: Session, org_id: uuid.UUID, field: CustomField, value: object) -> object:
    """Validate one submitted value against its field definition.

    Returns the value unchanged (normalized for dates: the ISO string is
    kept as-is). Raises 400 with a field-specific message on any
    violation. ``None`` is rejected here — absence is handled by the
    required-field check in :func:`submit_field_values`.
    """
    label = f"field '{field.key}'"
    if value is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must not be null")
    if field.field_type == "text":
        if not isinstance(value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be a string"
            )
        rules = field.validation or {}
        if "min_length" in rules and len(value) < rules["min_length"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{label} must be at least {rules['min_length']} characters",
            )
        if "max_length" in rules and len(value) > rules["max_length"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{label} must be at most {rules['max_length']} characters",
            )
        if "pattern" in rules and not re.search(rules["pattern"], value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} does not match the required pattern"
            )
    elif field.field_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be a number"
            )
        rules = field.validation or {}
        if "min" in rules and value < rules["min"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be at least {rules['min']}"
            )
        if "max" in rules and value > rules["max"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be at most {rules['max']}"
            )
    elif field.field_type == "select":
        if not isinstance(value, str) or value not in (field.options or []):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{label} must be one of {field.options or []}",
            )
    elif field.field_type == "multi_select":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be a list of strings"
            )
        bad = [v for v in value if v not in (field.options or [])]
        if bad:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{label} contains invalid options: {bad}",
            )
    elif field.field_type == "date":
        if not isinstance(value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be an ISO date string (YYYY-MM-DD)"
            )
        try:
            date.fromisoformat(value)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{label} must be an ISO date string (YYYY-MM-DD)",
            )
    elif field.field_type == "boolean":
        if not isinstance(value, bool):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be a boolean"
            )
    elif field.field_type == "user":
        if not isinstance(value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be a user id (UUID string)"
            )
        try:
            user_id = uuid.UUID(value)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} must be a user id (UUID string)"
            )
        member = session.execute(
            select(Membership).where(
                Membership.organization_id == org_id,
                Membership.user_id == user_id,
                Membership.status == "active",
            )
        ).scalar_one_or_none()
        if member is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{label} must reference an active member of this organization",
            )
    else:  # pragma: no cover - field_type is validated at creation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"unknown field type '{field.field_type}'"
        )
    return value


# --- Submission ---------------------------------------------------------------

def submit_field_values(
    session: Session,
    org_id: uuid.UUID,
    form: CustomForm,
    ticket: Ticket,
    values: list[dict],
    submitted_by_id: uuid.UUID | None,
) -> list[FieldValue]:
    """Validate and upsert submitted values for a ticket.

    ``values`` is a list of ``{"field_key": ..., "value": ...}`` (or
    ``{"field_id": ..., "value": ...}``). Every required field of the
    form must end up with a value — either submitted now or already
    stored. Existing values for submitted fields are replaced (one
    value per field per ticket). Raises 400 on any invalid value and
    stores nothing for the failed submission (the caller commits).
    """
    fields = session.execute(
        select(CustomField)
        .where(CustomField.form_id == form.id, CustomField.organization_id == org_id)
        .order_by(CustomField.position, CustomField.key)
    ).scalars().all()
    by_key = {f.key: f for f in fields}
    by_id = {str(f.id): f for f in fields}

    submitted: dict[uuid.UUID, object] = {}
    for entry in values:
        if not isinstance(entry, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="each value must be an object with field_key and value"
            )
        field = None
        if entry.get("field_key"):
            field = by_key.get(entry["field_key"])
        elif entry.get("field_id"):
            field = by_id.get(str(entry["field_id"]))
        if field is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unknown field: {entry.get('field_key') or entry.get('field_id')}",
            )
        if field.id in submitted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"duplicate value for field '{field.key}'"
            )
        submitted[field.id] = validate_field_value(session, org_id, field, entry.get("value"))

    existing = session.execute(
        select(FieldValue).where(
            FieldValue.form_id == form.id,
            FieldValue.entity_type == "ticket",
            FieldValue.entity_id == ticket.id,
        )
    ).scalars().all()
    existing_by_field = {row.field_id: row for row in existing}

    # Required fields must have a value after this submission.
    for field in fields:
        if field.required and field.id not in submitted and field.id not in existing_by_field:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"required field '{field.key}' is missing"
            )

    rows: list[FieldValue] = []
    for field_id, value in submitted.items():
        row = existing_by_field.get(field_id)
        if row is None:
            row = FieldValue(
                organization_id=org_id,
                form_id=form.id,
                field_id=field_id,
                entity_type="ticket",
                entity_id=ticket.id,
                value=value,
                submitted_by_id=submitted_by_id,
            )
            session.add(row)
        else:
            row.value = value
            row.submitted_by_id = submitted_by_id
        rows.append(row)
    session.flush()
    return rows


def list_field_values(
    session: Session, form: CustomForm, ticket: Ticket
) -> list[FieldValue]:
    """All stored values for one ticket under one form, field order."""
    return session.execute(
        select(FieldValue)
        .join(CustomField, CustomField.id == FieldValue.field_id)
        .where(
            FieldValue.form_id == form.id,
            FieldValue.entity_type == "ticket",
            FieldValue.entity_id == ticket.id,
        )
        .order_by(CustomField.position, CustomField.key)
    ).scalars().all()
