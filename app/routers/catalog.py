"""Service catalog — Phase 2 ITSM engine.

Categories (tree via parent_id) and items. Items move
draft -> published -> retired. ``GET /items/published`` is the
requester-facing list of published items.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.itsm import CatalogCategory, CatalogItem
from app.services.itsm_service import get_org_row

router = APIRouter(prefix="/api/v1/catalog", tags=["catalog"])

ITEM_STATUSES = {"draft", "published", "retired"}


class CategoryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = ""
    parent_id: uuid.UUID | None = None
    sort_order: int = 0


class CategoryUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    description: str | None = None
    parent_id: uuid.UUID | None = None
    sort_order: int | None = None


class CategoryOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    parent_id: uuid.UUID | None
    sort_order: int
    created_at: datetime
    updated_at: datetime


class ItemCreate(BaseModel):
    category_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    approval_required: bool = False
    fulfillment_instructions: str = ""
    form_schema: dict = {}
    sort_order: int = 0


class ItemUpdate(BaseModel):
    category_id: uuid.UUID | None = None
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    status: str | None = None
    approval_required: bool | None = None
    fulfillment_instructions: str | None = None
    form_schema: dict | None = None
    sort_order: int | None = None


class ItemOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    category_id: uuid.UUID | None
    name: str
    description: str
    status: str
    approval_required: bool
    fulfillment_instructions: str
    form_schema: dict
    sort_order: int
    created_at: datetime
    updated_at: datetime


def _cat_out(c: CatalogCategory) -> CategoryOut:
    return CategoryOut(
        id=c.id,
        organization_id=c.organization_id,
        name=c.name,
        description=c.description,
        parent_id=c.parent_id,
        sort_order=c.sort_order,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _item_out(i: CatalogItem) -> ItemOut:
    return ItemOut(
        id=i.id,
        organization_id=i.organization_id,
        category_id=i.category_id,
        name=i.name,
        description=i.description,
        status=i.status,
        approval_required=i.approval_required,
        fulfillment_instructions=i.fulfillment_instructions,
        form_schema=i.form_schema or {},
        sort_order=i.sort_order,
        created_at=i.created_at,
        updated_at=i.updated_at,
    )


def _check_parent(session: Session, principal: Principal, parent_id: uuid.UUID | None) -> None:
    if parent_id is None:
        return
    parent = session.get(CatalogCategory, parent_id)
    if parent is None or parent.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Parent category not found")


def _check_category(session: Session, principal: Principal, category_id: uuid.UUID | None) -> None:
    if category_id is None:
        return
    cat = session.get(CatalogCategory, category_id)
    if cat is None or cat.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Category not found")


# --- Categories ------------------------------------------------------------


@router.get("/categories", response_model=list[CategoryOut])
def list_categories(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("catalog:read"))
):
    rows = session.execute(
        select(CatalogCategory)
        .where(CatalogCategory.organization_id == principal.organization_id)
        .order_by(CatalogCategory.sort_order, CatalogCategory.name)
    ).scalars()
    return [_cat_out(c) for c in rows]


@router.post("/categories", response_model=CategoryOut, status_code=status.HTTP_201_CREATED)
def create_category(
    body: CategoryCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    _check_parent(session, principal, body.parent_id)
    cat = CatalogCategory(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        parent_id=body.parent_id,
        sort_order=body.sort_order,
    )
    session.add(cat)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_CATEGORY_CREATED,
        resource_type="catalog_category",
        resource_id=str(cat.id),
        outcome="success",
        metadata={"name": cat.name},
    )
    out = _cat_out(cat)
    session.commit()
    return out


@router.get("/categories/{category_id}", response_model=CategoryOut)
def get_category(
    category_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:read")),
):
    return _cat_out(get_org_row(session, CatalogCategory, category_id, principal.organization_id))


@router.patch("/categories/{category_id}", response_model=CategoryOut)
def update_category(
    category_id: uuid.UUID,
    body: CategoryUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    cat = get_org_row(session, CatalogCategory, category_id, principal.organization_id)
    if body.parent_id is not None:
        if body.parent_id == cat.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A category cannot be its own parent")
        _check_parent(session, principal, body.parent_id)
        cat.parent_id = body.parent_id
    if body.name is not None:
        cat.name = body.name
    if body.description is not None:
        cat.description = body.description
    if body.sort_order is not None:
        cat.sort_order = body.sort_order
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_CATEGORY_UPDATED,
        resource_type="catalog_category",
        resource_id=str(cat.id),
        outcome="success",
        metadata={"name": cat.name},
    )
    session.flush()
    out = _cat_out(cat)
    session.commit()
    return out


@router.delete("/categories/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(
    category_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    cat = get_org_row(session, CatalogCategory, category_id, principal.organization_id)
    session.delete(cat)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_CATEGORY_DELETED,
        resource_type="catalog_category",
        resource_id=str(cat.id),
        outcome="success",
        metadata={"name": cat.name},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Items -------------------------------------------------------------------


@router.get("/items/published", response_model=list[ItemOut])
def list_published_items(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("catalog:read"))
):
    rows = session.execute(
        select(CatalogItem)
        .where(CatalogItem.organization_id == principal.organization_id, CatalogItem.status == "published")
        .order_by(CatalogItem.sort_order, CatalogItem.name)
    ).scalars()
    return [_item_out(i) for i in rows]


@router.get("/items", response_model=list[ItemOut])
def list_items(session: Session = Depends(get_db), principal: Principal = Depends(require_permission("catalog:read"))):
    rows = session.execute(
        select(CatalogItem)
        .where(CatalogItem.organization_id == principal.organization_id)
        .order_by(CatalogItem.sort_order, CatalogItem.name)
    ).scalars()
    return [_item_out(i) for i in rows]


@router.post("/items", response_model=ItemOut, status_code=status.HTTP_201_CREATED)
def create_item(
    body: ItemCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    _check_category(session, principal, body.category_id)
    item = CatalogItem(
        organization_id=principal.organization_id,
        category_id=body.category_id,
        name=body.name,
        description=body.description,
        approval_required=body.approval_required,
        fulfillment_instructions=body.fulfillment_instructions,
        form_schema=body.form_schema or {},
        sort_order=body.sort_order,
        status="draft",
    )
    session.add(item)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_ITEM_CREATED,
        resource_type="catalog_item",
        resource_id=str(item.id),
        outcome="success",
        metadata={"name": item.name},
    )
    out = _item_out(item)
    session.commit()
    return out


@router.get("/items/{item_id}", response_model=ItemOut)
def get_item(
    item_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:read")),
):
    return _item_out(get_org_row(session, CatalogItem, item_id, principal.organization_id))


@router.patch("/items/{item_id}", response_model=ItemOut)
def update_item(
    item_id: uuid.UUID,
    body: ItemUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    item = get_org_row(session, CatalogItem, item_id, principal.organization_id)
    if body.status is not None:
        if body.status not in ITEM_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        item.status = body.status
    if body.category_id is not None:
        _check_category(session, principal, body.category_id)
        item.category_id = body.category_id
    if body.name is not None:
        item.name = body.name
    if body.description is not None:
        item.description = body.description
    if body.approval_required is not None:
        item.approval_required = body.approval_required
    if body.fulfillment_instructions is not None:
        item.fulfillment_instructions = body.fulfillment_instructions
    if body.form_schema is not None:
        item.form_schema = body.form_schema
    if body.sort_order is not None:
        item.sort_order = body.sort_order
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_ITEM_UPDATED,
        resource_type="catalog_item",
        resource_id=str(item.id),
        outcome="success",
        metadata={"status": item.status},
    )
    session.flush()
    out = _item_out(item)
    session.commit()
    return out


@router.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(
    item_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    item = get_org_row(session, CatalogItem, item_id, principal.organization_id)
    session.delete(item)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_ITEM_UPDATED,
        resource_type="catalog_item",
        resource_id=str(item.id),
        outcome="success",
        metadata={"deleted": True},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/items/{item_id}/publish", response_model=ItemOut)
def publish_item(
    item_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    item = get_org_row(session, CatalogItem, item_id, principal.organization_id)
    if item.status == "published":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Item is already published")
    item.status = "published"
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_ITEM_UPDATED,
        resource_type="catalog_item",
        resource_id=str(item.id),
        outcome="success",
        metadata={"status": "published"},
    )
    session.flush()
    out = _item_out(item)
    session.commit()
    return out


@router.post("/items/{item_id}/retire", response_model=ItemOut)
def retire_item(
    item_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("catalog:manage")),
):
    item = get_org_row(session, CatalogItem, item_id, principal.organization_id)
    if item.status != "published":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot retire an item in status {item.status}"
        )
    item.status = "retired"
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.CATALOG_ITEM_UPDATED,
        resource_type="catalog_item",
        resource_id=str(item.id),
        outcome="success",
        metadata={"status": "retired"},
    )
    session.flush()
    out = _item_out(item)
    session.commit()
    return out
