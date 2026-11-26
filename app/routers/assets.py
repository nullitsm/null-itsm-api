"""Asset routes: assets + lifecycle, vendors, purchase orders,
warranties, licenses + seats + compliance, offboarding.

Permissions: ``assets:read`` / ``assets:manage``, ``licenses:read`` /
``licenses:manage``, ``vendors:read`` / ``vendors:manage``.

Depreciation is recomputed on read (straight-line, or double-declining
at a fixed 2x rate — see asset_service.compute_current_value); the
stored ``current_value_cents`` is only a snapshot.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.identity_assets import (
    Asset,
    AssetAssignment,
    AssetLifecycleEvent,
    License,
    LicenseAssignment,
    PurchaseOrder,
    Vendor,
    Warranty,
)
from app.models.platform import Membership, User
from app.services import asset_service, identity_service

UTC = timezone.utc

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])

ASSET_TYPES = {"laptop", "desktop", "monitor", "phone", "server", "other"}
ASSET_STATUSES = {"in_stock", "assigned", "in_repair", "lost", "stolen", "retired", "disposed"}


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class AssetCreate(BaseModel):
    asset_tag: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=255)
    type: str = "laptop"
    serial_number: str | None = None
    department: str = ""
    location: str = ""
    purchase_order_id: uuid.UUID | None = None
    purchase_date: datetime | None = None
    purchase_price_cents: int | None = None
    depreciation_method: str = "straight_line"
    depreciation_years: int | None = None
    notes: str = ""


class AssetUpdate(BaseModel):
    name: str | None = None
    type: str | None = None
    serial_number: str | None = None
    department: str | None = None
    location: str | None = None
    purchase_date: datetime | None = None
    purchase_price_cents: int | None = None
    depreciation_method: str | None = None
    depreciation_years: int | None = None
    notes: str | None = None


class AssetOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_tag: str
    name: str
    type: str
    serial_number: str | None
    status: str
    assigned_to_id: uuid.UUID | None
    department: str
    location: str
    purchase_order_id: uuid.UUID | None
    purchase_date: datetime | None
    purchase_price_cents: int | None
    depreciation_method: str
    depreciation_years: int | None
    current_value_cents: int | None
    notes: str
    created_at: datetime
    updated_at: datetime


class AssetUserAction(BaseModel):
    user_id: uuid.UUID
    notes: str = ""


class AssetLifecycleOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    event_type: str
    actor_id: uuid.UUID | None
    notes: str
    metadata: dict
    created_at: datetime


class VendorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    contact_name: str | None = None
    contact_email: str | None = None
    website: str | None = None
    notes: str = ""
    is_active: bool = True


class VendorOut(BaseModel):
    id: uuid.UUID
    name: str
    contact_name: str | None
    contact_email: str | None
    website: str | None
    notes: str
    is_active: bool
    created_at: datetime


class PurchaseOrderCreate(BaseModel):
    vendor_id: uuid.UUID
    po_number: str = Field(min_length=1, max_length=100)
    total_cents: int = 0
    notes: str = ""


class PurchaseOrderUpdate(BaseModel):
    status: str | None = None
    total_cents: int | None = None
    notes: str | None = None


class PurchaseOrderOut(BaseModel):
    id: uuid.UUID
    vendor_id: uuid.UUID
    po_number: str
    status: str
    total_cents: int
    ordered_at: datetime | None
    received_at: datetime | None
    notes: str
    created_at: datetime


class WarrantyCreate(BaseModel):
    asset_id: uuid.UUID
    vendor_id: uuid.UUID | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    coverage: str = ""
    status: str = "active"


class WarrantyOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    vendor_id: uuid.UUID | None
    starts_at: datetime | None
    ends_at: datetime | None
    coverage: str
    status: str
    created_at: datetime


class LicenseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    vendor: str = ""
    license_key: str | None = None
    total_seats: int = 1
    expires_at: datetime | None = None
    cost_cents: int = 0
    compliance_notes: str = ""


class LicenseUpdate(BaseModel):
    name: str | None = None
    vendor: str | None = None
    license_key: str | None = None
    total_seats: int | None = None
    expires_at: datetime | None = None
    cost_cents: int | None = None
    compliance_notes: str | None = None


class LicenseOut(BaseModel):
    id: uuid.UUID
    name: str
    vendor: str
    total_seats: int
    seats_used: int
    seats_available: int
    expires_at: datetime | None
    cost_cents: int
    status: str
    compliance_notes: str
    has_key: bool
    created_at: datetime


class LicenseAssign(BaseModel):
    user_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    override: bool = False


class LicenseAssignmentOut(BaseModel):
    id: uuid.UUID
    license_id: uuid.UUID
    user_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    revoked_at: datetime | None
    created_at: datetime


class OffboardRequest(BaseModel):
    user_id: uuid.UUID


# --- Helpers ----------------------------------------------------------------


def _asset_out(session: Session, org_id: uuid.UUID, asset: Asset) -> AssetOut:
    return AssetOut(
        id=asset.id,
        organization_id=asset.organization_id,
        asset_tag=asset.asset_tag,
        name=asset.name,
        type=asset.type,
        serial_number=asset.serial_number,
        status=asset.status,
        assigned_to_id=asset.assigned_to_id,
        department=asset.department,
        location=asset.location,
        purchase_order_id=asset.purchase_order_id,
        purchase_date=asset.purchase_date,
        purchase_price_cents=asset.purchase_price_cents,
        depreciation_method=asset.depreciation_method,
        depreciation_years=asset.depreciation_years,
        current_value_cents=asset_service.compute_current_value(asset),
        notes=asset.notes,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def _get_asset(session: Session, org_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None or asset.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


def _license_out(session: Session, org_id: uuid.UUID, lic: License) -> LicenseOut:
    used = asset_service.license_seats_used(session, org_id, lic.id)
    return LicenseOut(
        id=lic.id,
        name=lic.name,
        vendor=lic.vendor,
        total_seats=lic.total_seats,
        seats_used=used,
        seats_available=max(0, lic.total_seats - used),
        expires_at=lic.expires_at,
        cost_cents=lic.cost_cents,
        status=lic.status,
        compliance_notes=lic.compliance_notes,
        has_key=bool(lic.license_key_encrypted),
        created_at=lic.created_at,
    )


def _get_license(session: Session, org_id: uuid.UUID, license_id: uuid.UUID) -> License:
    lic = session.get(License, license_id)
    if lic is None or lic.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    return lic


# --- Assets -----------------------------------------------------------------


@router.get("", response_model=list[AssetOut])
def list_assets(session: Session = Depends(get_db), principal: Principal = Depends(require_permission("assets:read"))):
    rows = session.execute(
        select(Asset).where(Asset.organization_id == principal.organization_id).order_by(Asset.created_at.desc())
    ).scalars()
    return [_asset_out(session, principal.organization_id, a) for a in rows]


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    body: AssetCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    if body.type not in ASSET_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid asset type")
    if body.depreciation_method not in ("straight_line", "declining", "none"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid depreciation method")
    if body.purchase_order_id is not None:
        po = session.get(PurchaseOrder, body.purchase_order_id)
        if po is None or po.organization_id != principal.organization_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Purchase order not found")
    asset = Asset(
        organization_id=principal.organization_id,
        asset_tag=body.asset_tag,
        name=body.name,
        type=body.type,
        serial_number=body.serial_number,
        department=body.department,
        location=body.location,
        purchase_order_id=body.purchase_order_id,
        purchase_date=body.purchase_date,
        purchase_price_cents=body.purchase_price_cents,
        depreciation_method=body.depreciation_method,
        depreciation_years=body.depreciation_years,
        current_value_cents=body.purchase_price_cents,
        notes=body.notes,
    )
    session.add(asset)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Asset tag '{body.asset_tag}' already exists"
        )
    asset_service._log_event(session, principal.organization_id, asset, "procured", principal.user_id, "Asset created")
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.ASSET_CREATED,
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        metadata={"asset_tag": asset.asset_tag},
    )
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:read")),
):
    return _asset_out(session, principal.organization_id, _get_asset(session, principal.organization_id, asset_id))


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    if body.name is not None:
        asset.name = body.name
    if body.type is not None:
        if body.type not in ASSET_TYPES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid asset type")
        asset.type = body.type
    for field in (
        "serial_number",
        "department",
        "location",
        "purchase_date",
        "purchase_price_cents",
        "depreciation_years",
        "notes",
    ):
        value = getattr(body, field)
        if value is not None:
            setattr(asset, field, value)
    if body.depreciation_method is not None:
        if body.depreciation_method not in ("straight_line", "declining", "none"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid depreciation method")
        asset.depreciation_method = body.depreciation_method
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.ASSET_UPDATED,
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        metadata={"asset_tag": asset.asset_tag},
    )
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    if asset.status == "assigned":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete an assigned asset")
    session.delete(asset)
    session.commit()
    return None


def _transition_endpoint(
    asset_id: uuid.UUID, target: str, session: Session, principal: Principal, notes: str = ""
) -> AssetOut:
    asset = _get_asset(session, principal.organization_id, asset_id)
    try:
        asset_service.transition_asset(session, principal.organization_id, asset, target, principal.user_id, notes)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.post("/{asset_id}/assign", response_model=AssetOut)
def assign_asset_endpoint(
    asset_id: uuid.UUID,
    body: AssetUserAction,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    try:
        asset_service.assign_asset(session, principal.organization_id, asset, body.user_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.post("/{asset_id}/check-out", response_model=AssetOut)
def check_out_asset_endpoint(
    asset_id: uuid.UUID,
    body: AssetUserAction,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    try:
        asset_service.assign_asset(
            session, principal.organization_id, asset, body.user_id, principal.user_id, event_type="checked_out"
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.post("/{asset_id}/check-in", response_model=AssetOut)
def check_in_asset_endpoint(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    try:
        asset_service.check_in_asset(session, principal.organization_id, asset, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.post("/{asset_id}/transfer", response_model=AssetOut)
def transfer_asset_endpoint(
    asset_id: uuid.UUID,
    body: AssetUserAction,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    try:
        asset_service.transfer_asset(session, principal.organization_id, asset, body.user_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.post("/{asset_id}/mark-lost", response_model=AssetOut)
def mark_lost(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    return _transition_endpoint(asset_id, "lost", session, principal)


@router.post("/{asset_id}/mark-stolen", response_model=AssetOut)
def mark_stolen(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    return _transition_endpoint(asset_id, "stolen", session, principal)


@router.post("/{asset_id}/recover", response_model=AssetOut)
def recover_asset_endpoint(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    try:
        asset_service.recover_asset(session, principal.organization_id, asset, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = _asset_out(session, principal.organization_id, asset)
    session.commit()
    return out


@router.post("/{asset_id}/retire", response_model=AssetOut)
def retire_asset(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    return _transition_endpoint(asset_id, "retired", session, principal)


@router.post("/{asset_id}/dispose", response_model=AssetOut)
def dispose_asset(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    return _transition_endpoint(asset_id, "disposed", session, principal)


@router.get("/{asset_id}/lifecycle", response_model=list[AssetLifecycleOut])
def asset_lifecycle(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:read")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    rows = session.execute(
        select(AssetLifecycleEvent)
        .where(AssetLifecycleEvent.asset_id == asset.id)
        .order_by(AssetLifecycleEvent.created_at)
    ).scalars()
    return [
        AssetLifecycleOut(
            id=e.id,
            asset_id=e.asset_id,
            event_type=e.event_type,
            actor_id=e.actor_id,
            notes=e.notes,
            metadata=e.meta or {},
            created_at=e.created_at,
        )
        for e in rows
    ]


@router.get("/{asset_id}/assignments", response_model=list[dict])
def asset_assignments(
    asset_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:read")),
):
    asset = _get_asset(session, principal.organization_id, asset_id)
    rows = session.execute(
        select(AssetAssignment).where(AssetAssignment.asset_id == asset.id).order_by(AssetAssignment.created_at.desc())
    ).scalars()
    return [
        {
            "id": str(r.id),
            "user_id": str(r.user_id),
            "status": r.status,
            "assigned_at": r.created_at.isoformat(),
            "returned_at": r.returned_at.isoformat() if r.returned_at else None,
            "assigned_by_id": str(r.assigned_by_id) if r.assigned_by_id else None,
        }
        for r in rows
    ]


# --- Offboarding ------------------------------------------------------------


@router.post("/offboard")
def offboard(
    body: OffboardRequest,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("assets:manage")),
):
    try:
        report = asset_service.offboard_user(session, principal.organization_id, body.user_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return report


# --- Vendors ----------------------------------------------------------------


def _vendor_out(v: Vendor) -> VendorOut:
    return VendorOut(
        id=v.id,
        name=v.name,
        contact_name=v.contact_name,
        contact_email=v.contact_email,
        website=v.website,
        notes=v.notes,
        is_active=v.is_active,
        created_at=v.created_at,
    )


@router.get("/vendors", response_model=list[VendorOut])
def list_vendors(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("vendors:read"))
):
    rows = session.execute(
        select(Vendor).where(Vendor.organization_id == principal.organization_id).order_by(Vendor.created_at)
    ).scalars()
    return [_vendor_out(v) for v in rows]


@router.post("/vendors", response_model=VendorOut, status_code=status.HTTP_201_CREATED)
def create_vendor(
    body: VendorCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:manage")),
):
    vendor = Vendor(
        organization_id=principal.organization_id,
        name=body.name,
        contact_name=body.contact_name,
        contact_email=body.contact_email,
        website=body.website,
        notes=body.notes,
        is_active=body.is_active,
    )
    session.add(vendor)
    session.flush()
    out = _vendor_out(vendor)
    session.commit()
    return out


@router.get("/vendors/{vendor_id}", response_model=VendorOut)
def get_vendor(
    vendor_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:read")),
):
    vendor = session.get(Vendor, vendor_id)
    if vendor is None or vendor.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
    return _vendor_out(vendor)


@router.patch("/vendors/{vendor_id}", response_model=VendorOut)
def update_vendor(
    vendor_id: uuid.UUID,
    body: VendorCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:manage")),
):
    vendor = session.get(Vendor, vendor_id)
    if vendor is None or vendor.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
    vendor.name = body.name
    vendor.contact_name = body.contact_name
    vendor.contact_email = body.contact_email
    vendor.website = body.website
    vendor.notes = body.notes
    vendor.is_active = body.is_active
    session.flush()
    out = _vendor_out(vendor)
    session.commit()
    return out


# --- Purchase orders ---------------------------------------------------------


def _po_out(p: PurchaseOrder) -> PurchaseOrderOut:
    return PurchaseOrderOut(
        id=p.id,
        vendor_id=p.vendor_id,
        po_number=p.po_number,
        status=p.status,
        total_cents=p.total_cents,
        ordered_at=p.ordered_at,
        received_at=p.received_at,
        notes=p.notes,
        created_at=p.created_at,
    )


@router.get("/purchase-orders", response_model=list[PurchaseOrderOut])
def list_purchase_orders(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("vendors:read"))
):
    rows = session.execute(
        select(PurchaseOrder)
        .where(PurchaseOrder.organization_id == principal.organization_id)
        .order_by(PurchaseOrder.created_at.desc())
    ).scalars()
    return [_po_out(p) for p in rows]


@router.post("/purchase-orders", response_model=PurchaseOrderOut, status_code=status.HTTP_201_CREATED)
def create_purchase_order(
    body: PurchaseOrderCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:manage")),
):
    vendor = session.get(Vendor, body.vendor_id)
    if vendor is None or vendor.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor not found")
    po = PurchaseOrder(
        organization_id=principal.organization_id,
        vendor_id=body.vendor_id,
        po_number=body.po_number,
        total_cents=body.total_cents,
        notes=body.notes,
    )
    session.add(po)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"PO number '{body.po_number}' already exists"
        )
    out = _po_out(po)
    session.commit()
    return out


@router.get("/purchase-orders/{po_id}", response_model=PurchaseOrderOut)
def get_purchase_order(
    po_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:read")),
):
    po = session.get(PurchaseOrder, po_id)
    if po is None or po.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Purchase order not found")
    return _po_out(po)


@router.patch("/purchase-orders/{po_id}", response_model=PurchaseOrderOut)
def update_purchase_order(
    po_id: uuid.UUID,
    body: PurchaseOrderUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:manage")),
):
    po = session.get(PurchaseOrder, po_id)
    if po is None or po.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Purchase order not found")
    if body.status is not None:
        if body.status not in ("draft", "ordered", "received", "cancelled"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid PO status")
        now = datetime.now(UTC)
        if body.status == "ordered" and po.ordered_at is None:
            po.ordered_at = now
        if body.status == "received" and po.received_at is None:
            po.received_at = now
        po.status = body.status
    if body.total_cents is not None:
        po.total_cents = body.total_cents
    if body.notes is not None:
        po.notes = body.notes
    session.flush()
    out = _po_out(po)
    session.commit()
    return out


# --- Warranties --------------------------------------------------------------


def _warranty_out(w: Warranty) -> WarrantyOut:
    return WarrantyOut(
        id=w.id,
        asset_id=w.asset_id,
        vendor_id=w.vendor_id,
        starts_at=w.starts_at,
        ends_at=w.ends_at,
        coverage=w.coverage,
        status=w.status,
        created_at=w.created_at,
    )


@router.get("/warranties", response_model=list[WarrantyOut])
def list_warranties(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("vendors:read"))
):
    rows = session.execute(
        select(Warranty).where(Warranty.organization_id == principal.organization_id).order_by(Warranty.created_at)
    ).scalars()
    return [_warranty_out(w) for w in rows]


@router.post("/warranties", response_model=WarrantyOut, status_code=status.HTTP_201_CREATED)
def create_warranty(
    body: WarrantyCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:manage")),
):
    asset = session.get(Asset, body.asset_id)
    if asset is None or asset.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asset not found")
    if body.vendor_id is not None:
        vendor = session.get(Vendor, body.vendor_id)
        if vendor is None or vendor.organization_id != principal.organization_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor not found")
    if body.status not in ("active", "expired"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid warranty status")
    warranty = Warranty(
        organization_id=principal.organization_id,
        asset_id=body.asset_id,
        vendor_id=body.vendor_id,
        starts_at=body.starts_at,
        ends_at=body.ends_at,
        coverage=body.coverage,
        status=body.status,
    )
    session.add(warranty)
    session.flush()
    out = _warranty_out(warranty)
    session.commit()
    return out


@router.get("/warranties/{warranty_id}", response_model=WarrantyOut)
def get_warranty(
    warranty_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vendors:read")),
):
    warranty = session.get(Warranty, warranty_id)
    if warranty is None or warranty.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Warranty not found")
    return _warranty_out(warranty)


# --- Licenses ----------------------------------------------------------------


@router.get("/licenses/compliance")
def license_compliance(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("licenses:read"))
):
    now = datetime.now(UTC)
    licenses = (
        session.execute(select(License).where(License.organization_id == principal.organization_id)).scalars().all()
    )
    entries = []
    expiring = []
    over_allocated = []
    for lic in licenses:
        used = asset_service.license_seats_used(session, principal.organization_id, lic.id)
        entries.append(
            {
                "license_id": str(lic.id),
                "name": lic.name,
                "vendor": lic.vendor,
                "total_seats": lic.total_seats,
                "seats_used": used,
                "seats_available": max(0, lic.total_seats - used),
                "status": lic.status,
                "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            }
        )
        if lic.expires_at is not None and lic.expires_at <= now + timedelta(days=30):
            expiring.append({"license_id": str(lic.id), "name": lic.name, "expires_at": lic.expires_at.isoformat()})
        if used > lic.total_seats:
            over_allocated.append(
                {"license_id": str(lic.id), "name": lic.name, "seats_used": used, "total_seats": lic.total_seats}
            )
    return {"licenses": entries, "expiring_within_30_days": expiring, "over_allocated": over_allocated}


@router.get("/licenses", response_model=list[LicenseOut])
def list_licenses(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("licenses:read"))
):
    rows = session.execute(
        select(License).where(License.organization_id == principal.organization_id).order_by(License.created_at)
    ).scalars()
    return [_license_out(session, principal.organization_id, lic) for lic in rows]


@router.post("/licenses", response_model=LicenseOut, status_code=status.HTTP_201_CREATED)
def create_license(
    body: LicenseCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("licenses:manage")),
):
    encrypted_key = None
    if body.license_key:
        try:
            encrypted_key = identity_service.encrypt_secret(body.license_key)
        except identity_service.SecretStorageError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    lic = License(
        organization_id=principal.organization_id,
        name=body.name,
        vendor=body.vendor,
        license_key_encrypted=encrypted_key,
        total_seats=body.total_seats,
        expires_at=body.expires_at,
        cost_cents=body.cost_cents,
        compliance_notes=body.compliance_notes,
    )
    session.add(lic)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.LICENSE_CREATED,
        resource_type="license",
        resource_id=str(lic.id),
        outcome="success",
        metadata={"name": body.name},
    )
    out = _license_out(session, principal.organization_id, lic)
    session.commit()
    return out


@router.get("/licenses/{license_id}", response_model=LicenseOut)
def get_license(
    license_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("licenses:read")),
):
    return _license_out(
        session, principal.organization_id, _get_license(session, principal.organization_id, license_id)
    )


@router.patch("/licenses/{license_id}", response_model=LicenseOut)
def update_license(
    license_id: uuid.UUID,
    body: LicenseUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("licenses:manage")),
):
    lic = _get_license(session, principal.organization_id, license_id)
    if body.name is not None:
        lic.name = body.name
    if body.vendor is not None:
        lic.vendor = body.vendor
    if body.license_key is not None:
        try:
            lic.license_key_encrypted = identity_service.encrypt_secret(body.license_key)
        except identity_service.SecretStorageError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    if body.total_seats is not None:
        lic.total_seats = body.total_seats
    if body.expires_at is not None:
        lic.expires_at = body.expires_at
    if body.cost_cents is not None:
        lic.cost_cents = body.cost_cents
    if body.compliance_notes is not None:
        lic.compliance_notes = body.compliance_notes
    session.flush()
    out = _license_out(session, principal.organization_id, lic)
    session.commit()
    return out


@router.delete("/licenses/{license_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_license(
    license_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("licenses:manage")),
):
    lic = _get_license(session, principal.organization_id, license_id)
    if asset_service.license_seats_used(session, principal.organization_id, lic.id) > 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete a license with active seats")
    session.delete(lic)
    session.commit()
    return None


@router.post("/licenses/{license_id}/assign", response_model=LicenseAssignmentOut, status_code=status.HTTP_201_CREATED)
def assign_license_seat_endpoint(
    license_id: uuid.UUID,
    body: LicenseAssign,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("licenses:manage")),
):
    lic = _get_license(session, principal.organization_id, license_id)
    if body.user_id is not None:
        user = session.get(User, body.user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
        membership = session.execute(
            select(Membership).where(
                Membership.organization_id == principal.organization_id, Membership.user_id == body.user_id
            )
        ).scalar_one_or_none()
        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not a member of this organization"
            )
    if body.asset_id is not None:
        _get_asset(session, principal.organization_id, body.asset_id)
    try:
        row = asset_service.assign_license_seat(
            session,
            principal.organization_id,
            lic,
            body.user_id,
            body.asset_id,
            principal.user_id,
            override=body.override,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = LicenseAssignmentOut(
        id=row.id,
        license_id=row.license_id,
        user_id=row.user_id,
        asset_id=row.asset_id,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
    )
    session.commit()
    return out


@router.post("/licenses/assignments/{assignment_id}/revoke", response_model=LicenseAssignmentOut)
def revoke_license_seat_endpoint(
    assignment_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("licenses:manage")),
):
    try:
        row = asset_service.revoke_license_seat(session, principal.organization_id, assignment_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    out = LicenseAssignmentOut(
        id=row.id,
        license_id=row.license_id,
        user_id=row.user_id,
        asset_id=row.asset_id,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
    )
    session.commit()
    return out


@router.get("/licenses/{license_id}/assignments", response_model=list[LicenseAssignmentOut])
def list_license_assignments(
    license_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("licenses:read")),
):
    lic = _get_license(session, principal.organization_id, license_id)
    rows = session.execute(
        select(LicenseAssignment)
        .where(LicenseAssignment.license_id == lic.id, LicenseAssignment.revoked_at.is_(None))
        .order_by(LicenseAssignment.created_at)
    ).scalars()
    return [
        LicenseAssignmentOut(
            id=r.id,
            license_id=r.license_id,
            user_id=r.user_id,
            asset_id=r.asset_id,
            revoked_at=r.revoked_at,
            created_at=r.created_at,
        )
        for r in rows
    ]
