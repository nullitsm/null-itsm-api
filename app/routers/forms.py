"""Custom forms API — form builder CRUD + ticket field values.

Prefix ``/api/v1/forms``. Request/response models are defined locally
in this module (the coordinator centralizes schemas at integration).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.forms import FORM_TARGET_TYPES, CustomField, CustomForm
from app.models.ticket import Ticket
from app.services.forms_service import (
    list_field_values,
    submit_field_values,
    validate_field_definition,
)
from app.services.itsm_service import get_org_row

router = APIRouter(prefix="/api/v1/forms", tags=["forms"])

# Audit actions for this module. These literals are not yet constants in
# Audit actions use the centralized constants in app/audit.py.


# --- Schemas (local to this router) -------------------------------------------


class FieldDefinitionIn(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=255)
    field_type: str
    required: bool = False
    position: int = 0
    options: list[str] = []
    validation: dict = {}


class FieldDefinitionOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    form_id: uuid.UUID
    key: str
    label: str
    field_type: str
    required: bool
    position: int
    options: list
    validation: dict
    created_at: datetime
    updated_at: datetime


class FieldUpdate(BaseModel):
    label: str | None = Field(default=None, max_length=255)
    required: bool | None = None
    position: int | None = None
    options: list[str] | None = None
    validation: dict | None = None


class FormCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    target_type: str = "ticket"
    is_active: bool = True
    fields: list[FieldDefinitionIn] = []


class FormUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    target_type: str | None = None
    is_active: bool | None = None


class FormOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    target_type: str
    is_active: bool
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    fields: list[FieldDefinitionOut] = []


class ValueIn(BaseModel):
    field_key: str | None = None
    field_id: uuid.UUID | None = None
    value: object = None


class ValuesSubmit(BaseModel):
    values: list[ValueIn] = []


class FieldValueOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    form_id: uuid.UUID
    field_id: uuid.UUID
    field_key: str
    entity_type: str
    entity_id: uuid.UUID
    value: object
    submitted_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


# --- Helpers ------------------------------------------------------------------


def _field_out(f: CustomField) -> FieldDefinitionOut:
    return FieldDefinitionOut(
        id=f.id,
        organization_id=f.organization_id,
        form_id=f.form_id,
        key=f.key,
        label=f.label,
        field_type=f.field_type,
        required=f.required,
        position=f.position,
        options=f.options or [],
        validation=f.validation or {},
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


def _form_out(form: CustomForm, fields: list[CustomField]) -> FormOut:
    return FormOut(
        id=form.id,
        organization_id=form.organization_id,
        name=form.name,
        description=form.description,
        target_type=form.target_type,
        is_active=form.is_active,
        created_by_id=form.created_by_id,
        created_at=form.created_at,
        updated_at=form.updated_at,
        fields=[_field_out(f) for f in fields],
    )


def _load_fields(session: Session, form_id: uuid.UUID) -> list[CustomField]:
    return session.execute(
        select(CustomField).where(CustomField.form_id == form_id).order_by(CustomField.position, CustomField.key)
    ).scalars().all()


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


def _get_form(session: Session, principal: Principal, form_id: uuid.UUID) -> CustomForm:
    return get_org_row(session, CustomForm, form_id, principal.organization_id)


def _get_field(session: Session, form: CustomForm, field_id: uuid.UUID) -> CustomField:
    field = session.get(CustomField, field_id)
    if field is None or field.form_id != form.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Field not found")
    return field


def _create_fields(
    session: Session, principal: Principal, form: CustomForm, definitions: list[FieldDefinitionIn]
) -> list[CustomField]:
    seen_keys: set[str] = set()
    rows: list[CustomField] = []
    for index, definition in enumerate(definitions):
        payload = definition.model_dump()
        validate_field_definition(payload)
        if definition.key in seen_keys:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"duplicate field key '{definition.key}'"
            )
        seen_keys.add(definition.key)
        row = CustomField(
            organization_id=principal.organization_id,
            form_id=form.id,
            key=definition.key,
            label=definition.label,
            field_type=definition.field_type,
            required=definition.required,
            position=definition.position if definition.position else index,
            options=definition.options or [],
            validation=definition.validation or {},
        )
        session.add(row)
        rows.append(row)
    session.flush()
    return rows


# --- Form CRUD ----------------------------------------------------------------


@router.post("", response_model=FormOut, status_code=status.HTTP_201_CREATED)
def create_form(
    body: FormCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:manage")),
):
    if body.target_type not in FORM_TARGET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"target_type must be one of {sorted(FORM_TARGET_TYPES)}",
        )
    form = CustomForm(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        target_type=body.target_type,
        is_active=body.is_active,
        created_by_id=principal.user_id,
    )
    session.add(form)
    try:
        session.flush()
        fields = _create_fields(session, principal, form, body.fields)
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A form with this name already exists"
        )
    _audit(session, principal, audit_mod.FORM_CREATED, "custom_form", str(form.id), name=form.name)
    out = _form_out(form, fields)
    session.commit()
    return out


@router.get("", response_model=list[FormOut])
def list_forms(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:read")),
):
    forms = session.execute(
        select(CustomForm)
        .where(CustomForm.organization_id == principal.organization_id)
        .order_by(CustomForm.name)
    ).scalars().all()
    return [_form_out(f, _load_fields(session, f.id)) for f in forms]


@router.get("/{form_id}", response_model=FormOut)
def get_form(
    form_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:read")),
):
    form = _get_form(session, principal, form_id)
    return _form_out(form, _load_fields(session, form.id))


@router.patch("/{form_id}", response_model=FormOut)
def update_form(
    form_id: uuid.UUID,
    body: FormUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:manage")),
):
    form = _get_form(session, principal, form_id)
    if body.target_type is not None and body.target_type not in FORM_TARGET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"target_type must be one of {sorted(FORM_TARGET_TYPES)}",
        )
    if body.name is not None:
        form.name = body.name
    if body.description is not None:
        form.description = body.description
    if body.target_type is not None:
        form.target_type = body.target_type
    if body.is_active is not None:
        form.is_active = body.is_active
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A form with this name already exists"
        )
    _audit(session, principal, audit_mod.FORM_UPDATED, "custom_form", str(form.id), name=form.name)
    out = _form_out(form, _load_fields(session, form.id))
    session.commit()
    return out


@router.delete("/{form_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_form(
    form_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:manage")),
):
    form = _get_form(session, principal, form_id)
    session.delete(form)
    _audit(session, principal, audit_mod.FORM_DELETED, "custom_form", str(form.id), name=form.name)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Field CRUD ---------------------------------------------------------------


@router.post("/{form_id}/fields", response_model=FieldDefinitionOut, status_code=status.HTTP_201_CREATED)
def add_field(
    form_id: uuid.UUID,
    body: FieldDefinitionIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:manage")),
):
    form = _get_form(session, principal, form_id)
    validate_field_definition(body.model_dump())
    existing = session.execute(
        select(CustomField).where(CustomField.form_id == form.id, CustomField.key == body.key)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=f"field key '{body.key}' already exists on this form"
        )
    field = CustomField(
        organization_id=principal.organization_id,
        form_id=form.id,
        key=body.key,
        label=body.label,
        field_type=body.field_type,
        required=body.required,
        position=body.position,
        options=body.options or [],
        validation=body.validation or {},
    )
    session.add(field)
    session.flush()
    _audit(
        session, principal, audit_mod.FORM_FIELD_CREATED, "custom_field", str(field.id),
        form_id=str(form.id), key=field.key,
    )
    out = _field_out(field)
    session.commit()
    return out


@router.patch("/{form_id}/fields/{field_id}", response_model=FieldDefinitionOut)
def update_field(
    form_id: uuid.UUID,
    field_id: uuid.UUID,
    body: FieldUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:manage")),
):
    form = _get_form(session, principal, form_id)
    field = _get_field(session, form, field_id)
    merged = {
        "key": field.key,
        "label": body.label if body.label is not None else field.label,
        "field_type": field.field_type,
        "required": body.required if body.required is not None else field.required,
        "position": body.position if body.position is not None else field.position,
        "options": body.options if body.options is not None else (field.options or []),
        "validation": body.validation if body.validation is not None else (field.validation or {}),
    }
    validate_field_definition(merged)
    if body.label is not None:
        field.label = body.label
    if body.required is not None:
        field.required = body.required
    if body.position is not None:
        field.position = body.position
    if body.options is not None:
        field.options = body.options
    if body.validation is not None:
        field.validation = body.validation
    session.flush()
    _audit(
        session, principal, audit_mod.FORM_FIELD_UPDATED, "custom_field", str(field.id),
        form_id=str(form.id), key=field.key,
    )
    out = _field_out(field)
    session.commit()
    return out


@router.delete("/{form_id}/fields/{field_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_field(
    form_id: uuid.UUID,
    field_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:manage")),
):
    form = _get_form(session, principal, form_id)
    field = _get_field(session, form, field_id)
    session.delete(field)
    _audit(
        session, principal, audit_mod.FORM_FIELD_DELETED, "custom_field", str(field.id),
        form_id=str(form.id), key=field.key,
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Ticket field values ------------------------------------------------------
# Registered after the /{form_id} routes above only in path depth: these
# two-segment paths (/{form_id}/tickets/{ticket_id}/...) never collide
# with the single-segment /{form_id}/fields routes.


@router.post("/{form_id}/tickets/{ticket_id}/values", response_model=list[FieldValueOut])
def submit_ticket_values(
    form_id: uuid.UUID,
    ticket_id: uuid.UUID,
    body: ValuesSubmit,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:manage")),
):
    form = _get_form(session, principal, form_id)
    ticket = session.get(Ticket, ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")
    if form.target_type != "ticket":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="This form does not target tickets"
        )
    rows = submit_field_values(
        session,
        principal.organization_id,
        form,
        ticket,
        [v.model_dump() for v in body.values],
        principal.user_id,
    )
    fields_by_id = {f.id: f for f in _load_fields(session, form.id)}
    _audit(
        session, principal, audit_mod.FORM_VALUES_SUBMITTED, "custom_form", str(form.id),
        ticket_id=str(ticket.id), field_count=len(rows),
    )
    out = [
        FieldValueOut(
            id=r.id,
            organization_id=r.organization_id,
            form_id=r.form_id,
            field_id=r.field_id,
            field_key=fields_by_id[r.field_id].key,
            entity_type=r.entity_type,
            entity_id=r.entity_id,
            value=r.value,
            submitted_by_id=r.submitted_by_id,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]
    session.commit()
    return out


@router.get("/{form_id}/tickets/{ticket_id}/values", response_model=list[FieldValueOut])
def list_ticket_values(
    form_id: uuid.UUID,
    ticket_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("forms:read")),
):
    form = _get_form(session, principal, form_id)
    ticket = session.get(Ticket, ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")
    rows = list_field_values(session, form, ticket)
    fields_by_id = {f.id: f for f in _load_fields(session, form.id)}
    return [
        FieldValueOut(
            id=r.id,
            organization_id=r.organization_id,
            form_id=r.form_id,
            field_id=r.field_id,
            field_key=fields_by_id[r.field_id].key,
            entity_type=r.entity_type,
            entity_id=r.entity_id,
            value=r.value,
            submitted_by_id=r.submitted_by_id,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]
