"""Asset service: lifecycle transitions, depreciation, license seats,
offboarding.

Every lifecycle transition is validated against the asset's current
status (illegal transitions raise ValueError -> 400) and writes an
``asset_lifecycle_events`` row. Depreciation is computed, never
invented: straight-line spreads the purchase price evenly over the
depreciation years; declining-balance uses a fixed 2x (double-declining)
rate; ``none`` (or a missing price/years) leaves the value at the
purchase price.

Offboarding is one transaction: suspend membership, revoke sessions,
create one recovery ticket per assigned asset (row-locked INC counter,
same pattern as tickets.py), return assets to in_repair, revoke
temporary grants, audit the full report.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.models.auth import AuthSession
from app.models.identity_assets import (
    Asset,
    AssetAssignment,
    AssetLifecycleEvent,
    License,
    LicenseAssignment,
    TemporaryAccessGrant,
)
from app.models.platform import Membership, User
from app.models.rbac import UserRole
from app.models.ticket import Ticket, TicketCounter

UTC = timezone.utc

# Allowed status transitions (target -> set of source statuses).
# assign/check-out/transfer are handled by their own functions.
_TRANSITIONS: dict[str, set[str]] = {
    "in_stock": {"assigned", "in_repair", "lost", "stolen"},
    "in_repair": {"in_stock", "assigned", "lost", "stolen"},
    "lost": {"in_stock", "assigned", "in_repair"},
    "stolen": {"in_stock", "assigned", "in_repair"},
    "retired": {"in_stock", "assigned", "in_repair", "lost", "stolen"},
    "disposed": {"in_stock", "assigned", "in_repair", "lost", "stolen", "retired"},
}

_EVENT_FOR_STATUS = {
    "in_stock": "checked_in",
    "in_repair": "repaired",
    "lost": "lost",
    "stolen": "stolen",
    "retired": "retired",
    "disposed": "disposed",
}


def _log_event(
    session: Session,
    org_id: uuid.UUID,
    asset: Asset,
    event_type: str,
    actor_id: uuid.UUID | None,
    notes: str = "",
    metadata: dict | None = None,
) -> AssetLifecycleEvent:
    event = AssetLifecycleEvent(
        organization_id=org_id,
        asset_id=asset.id,
        event_type=event_type,
        actor_id=actor_id,
        notes=notes,
        meta=metadata or {},
    )
    session.add(event)
    session.flush()
    return event


def compute_current_value(asset: Asset, now: datetime | None = None) -> int | None:
    """Depreciated value in cents, recomputed from purchase data.

    straight_line: price * max(0, 1 - elapsed_years / years).
    declining (double-declining, fixed 2x rate): price * (1 - 2/years) **
    elapsed_years, floored at 0. ``none`` or missing price/years returns
    the purchase price (or None when there is no price at all).
    """
    price = asset.purchase_price_cents
    if price is None:
        return None
    if asset.depreciation_method == "none" or not asset.depreciation_years or not asset.purchase_date:
        return price
    years = asset.depreciation_years
    now = now or datetime.now(UTC)
    elapsed_years = max(0.0, (now - asset.purchase_date).total_seconds() / (365.25 * 24 * 3600))
    if asset.depreciation_method == "declining":
        value = price * max(0.0, (1 - 2.0 / years)) ** elapsed_years
    else:  # straight_line
        value = price * max(0.0, 1 - elapsed_years / years)
    return int(round(value))


def transition_asset(
    session: Session,
    org_id: uuid.UUID,
    asset: Asset,
    target_status: str,
    actor_id: uuid.UUID,
    notes: str = "",
) -> Asset:
    """Move an asset to ``target_status`` after validating the transition."""
    if target_status not in _TRANSITIONS:
        raise ValueError(f"Unknown asset status: {target_status}")
    if asset.status == target_status:
        raise ValueError(f"Asset is already {target_status}")
    if asset.status not in _TRANSITIONS[target_status]:
        raise ValueError(f"Cannot move asset from {asset.status} to {target_status}")
    if asset.status == "assigned":
        # Leaving "assigned" always closes the active assignment row(s):
        # lost/stolen/recovered/retired/disposed/in_stock alike, so an
        # asset never accumulates more than one active assignment.
        _close_assignment(session, org_id, asset)
    previous = asset.status
    asset.status = target_status
    if target_status in ("in_stock", "retired", "disposed", "lost", "stolen"):
        asset.assigned_to_id = None
    _log_event(
        session,
        org_id,
        asset,
        _EVENT_FOR_STATUS[target_status],
        actor_id,
        notes or f"Status {previous} -> {target_status}",
        {"from": previous, "to": target_status},
    )
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.ASSET_STATUS_CHANGED,
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        metadata={"from": previous, "to": target_status, "asset_tag": asset.asset_tag},
    )
    session.flush()
    return asset


def recover_asset(session: Session, org_id: uuid.UUID, asset: Asset, actor_id: uuid.UUID) -> Asset:
    """Recover a lost/stolen asset back to stock (event type "recovered")."""
    if asset.status not in ("lost", "stolen"):
        raise ValueError(f"Cannot recover asset in status {asset.status} (must be lost or stolen)")
    previous = asset.status
    asset.status = "in_stock"
    asset.assigned_to_id = None
    _log_event(
        session,
        org_id,
        asset,
        "recovered",
        actor_id,
        f"Recovered (was {previous})",
        {"from": previous, "to": "in_stock"},
    )
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.ASSET_STATUS_CHANGED,
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        metadata={"from": previous, "to": "in_stock", "asset_tag": asset.asset_tag},
    )
    session.flush()
    return asset


def _close_assignment(session: Session, org_id: uuid.UUID, asset: Asset) -> list[AssetAssignment]:
    """Close the asset's active assignment row(s), if any.

    Closes ALL active rows (defensive: a bug or a race must never leave
    two active assignments for one asset).
    """
    rows = (
        session.execute(
            select(AssetAssignment).where(
                AssetAssignment.organization_id == org_id,
                AssetAssignment.asset_id == asset.id,
                AssetAssignment.status == "active",
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for row in rows:
        row.status = "returned"
        row.returned_at = now
    if rows:
        session.flush()
    return rows


def assign_asset(
    session: Session,
    org_id: uuid.UUID,
    asset: Asset,
    user_id: uuid.UUID,
    actor_id: uuid.UUID,
    event_type: str = "assigned",
) -> Asset:
    """Assign (or check out) an asset to a user. Only from in_stock."""
    if asset.status != "in_stock":
        raise ValueError(f"Cannot assign asset in status {asset.status} (must be in_stock)")
    user = session.get(User, user_id)
    if user is None:
        raise ValueError("User not found")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None or membership.status != "active":
        raise ValueError("User has no active membership in this organization")
    asset.status = "assigned"
    asset.assigned_to_id = user_id
    session.add(AssetAssignment(organization_id=org_id, asset_id=asset.id, user_id=user_id, assigned_by_id=actor_id))
    _log_event(session, org_id, asset, event_type, actor_id, f"Assigned to {user.email}", {"user_id": str(user_id)})
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.ASSET_ASSIGNED,
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        metadata={"user_id": str(user_id), "asset_tag": asset.asset_tag},
    )
    session.flush()
    return asset


def check_in_asset(session: Session, org_id: uuid.UUID, asset: Asset, actor_id: uuid.UUID) -> Asset:
    """Return an assigned asset to stock (closes the assignment)."""
    if asset.status != "assigned":
        raise ValueError(f"Cannot check in asset in status {asset.status} (must be assigned)")
    _close_assignment(session, org_id, asset)
    previous_user = asset.assigned_to_id
    asset.status = "in_stock"
    asset.assigned_to_id = None
    _log_event(session, org_id, asset, "checked_in", actor_id, "Checked in", {"user_id": str(previous_user or "")})
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.ASSET_RETURNED,
        resource_type="asset",
        resource_id=str(asset.id),
        outcome="success",
        metadata={"asset_tag": asset.asset_tag},
    )
    session.flush()
    return asset


def transfer_asset(session: Session, org_id: uuid.UUID, asset: Asset, user_id: uuid.UUID, actor_id: uuid.UUID) -> Asset:
    """Transfer an assigned asset to another user (stays assigned)."""
    if asset.status != "assigned":
        raise ValueError(f"Cannot transfer asset in status {asset.status} (must be assigned)")
    user = session.get(User, user_id)
    if user is None:
        raise ValueError("User not found")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None or membership.status != "active":
        raise ValueError("User has no active membership in this organization")
    previous_user = asset.assigned_to_id
    _close_assignment(session, org_id, asset)
    asset.assigned_to_id = user_id
    session.add(AssetAssignment(organization_id=org_id, asset_id=asset.id, user_id=user_id, assigned_by_id=actor_id))
    _log_event(
        session,
        org_id,
        asset,
        "transferred",
        actor_id,
        f"Transferred to {user.email}",
        {"from_user_id": str(previous_user or ""), "to_user_id": str(user_id)},
    )
    session.flush()
    return asset


# --- Licenses --------------------------------------------------------------


def license_seats_used(session: Session, org_id: uuid.UUID, license_id: uuid.UUID) -> int:
    rows = (
        session.execute(
            select(LicenseAssignment).where(
                LicenseAssignment.organization_id == org_id,
                LicenseAssignment.license_id == license_id,
                LicenseAssignment.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    return len(rows)


def assign_license_seat(
    session: Session,
    org_id: uuid.UUID,
    license_: License,
    user_id: uuid.UUID | None,
    asset_id: uuid.UUID | None,
    actor_id: uuid.UUID,
    override: bool = False,
) -> LicenseAssignment:
    """Assign one license seat.

    Blocked with ValueError when all seats are used — unless ``override``
    is set, in which case the seat is assigned and the license flips to
    "exceeded" (an explicit admin override, never silent).
    """
    if user_id is None and asset_id is None:
        raise ValueError("A license seat must be assigned to a user or an asset")
    used = license_seats_used(session, org_id, license_.id)
    if used >= license_.total_seats and not override:
        raise ValueError(f"License '{license_.name}' has no free seats ({used}/{license_.total_seats} used)")
    row = LicenseAssignment(organization_id=org_id, license_id=license_.id, user_id=user_id, asset_id=asset_id)
    session.add(row)
    if used + 1 > license_.total_seats:
        license_.status = "exceeded"
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.LICENSE_ASSIGNED,
        resource_type="license",
        resource_id=str(license_.id),
        outcome="success",
        metadata={
            "user_id": str(user_id) if user_id else None,
            "asset_id": str(asset_id) if asset_id else None,
            "override": override,
            "seats_used": used + 1,
            "total_seats": license_.total_seats,
        },
    )
    return row


def revoke_license_seat(
    session: Session, org_id: uuid.UUID, assignment_id: uuid.UUID, actor_id: uuid.UUID
) -> LicenseAssignment:
    row = session.get(LicenseAssignment, assignment_id)
    if row is None or row.organization_id != org_id:
        raise ValueError("License assignment not found")
    if row.revoked_at is not None:
        raise ValueError("License assignment is already revoked")
    row.revoked_at = datetime.now(UTC)
    session.flush()
    license_ = session.get(License, row.license_id)
    if license_ is not None and license_.status == "exceeded":
        used = license_seats_used(session, org_id, license_.id)
        if used <= license_.total_seats:
            license_.status = "active"
            session.flush()
    return row


# --- Offboarding -----------------------------------------------------------


def _next_ticket_number(session: Session, org_id: uuid.UUID) -> str:
    """Row-locked per-org INC counter (same pattern as tickets.py)."""
    counter = session.execute(
        select(TicketCounter).where(TicketCounter.organization_id == org_id).with_for_update()
    ).scalar_one_or_none()
    if counter is None:
        counter = TicketCounter(organization_id=org_id, last_number=0)
        session.add(counter)
        session.flush()
    counter.last_number += 1
    return f"INC-{counter.last_number:06d}"


def offboard_user(session: Session, org_id: uuid.UUID, user_id: uuid.UUID, actor_id: uuid.UUID) -> dict:
    """Offboard a user, all-or-nothing in the caller's transaction.

    (1) list assigned assets; (2) suspend the membership; (3) revoke the
    user's sessions; (4) one recovery ticket per assigned asset
    (requester = assignee = caller); (5) assets to in_repair with a
    lifecycle event + closed assignment; (6) revoke temporary grants;
    (7) audit OFFBOARDING_COMPLETED with the full report.
    """
    user = session.get(User, user_id)
    if user is None:
        raise ValueError("User not found")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise ValueError("User has no membership in this organization")
    if membership.is_owner:
        raise ValueError("The organization owner cannot be offboarded")

    assigned = (
        session.execute(select(Asset).where(Asset.organization_id == org_id, Asset.assigned_to_id == user_id))
        .scalars()
        .all()
    )

    # (2) Suspend the membership.
    membership.status = "suspended"
    session.flush()

    # (3) Revoke the user's sessions in this org.
    sessions = (
        session.execute(
            select(AuthSession).where(
                AuthSession.organization_id == org_id,
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for s in sessions:
        s.revoked_at = now
    session.flush()

    # (4)+(5) Recovery tickets + asset return to in_repair.
    tickets_created: list[dict] = []
    assets_recovered: list[str] = []
    for asset in assigned:
        ticket = Ticket(
            organization_id=org_id,
            number=_next_ticket_number(session, org_id),
            title=f"Recover {asset.asset_tag} from {user.full_name}",
            description=(
                f"Offboarding recovery: collect asset {asset.asset_tag} ({asset.name}) "
                f"from {user.full_name} ({user.email})."
            ),
            priority="medium",
            category="General",
            requester_id=actor_id,
            assignee_id=actor_id,
            status="open",
        )
        session.add(ticket)
        session.flush()
        audit_mod.write_audit(
            session,
            organization_id=org_id,
            actor_id=actor_id,
            action=audit_mod.TICKET_CREATED,
            resource_type="ticket",
            resource_id=str(ticket.id),
            outcome="success",
            metadata={"number": ticket.number, "source": "offboarding"},
        )
        tickets_created.append({"ticket_id": str(ticket.id), "number": ticket.number, "asset_tag": asset.asset_tag})
        _close_assignment(session, org_id, asset)
        asset.assigned_to_id = None
        asset.status = "in_repair"
        _log_event(
            session,
            org_id,
            asset,
            "checked_in",
            actor_id,
            f"Offboarded {user.full_name}: asset returned for inspection",
            {"offboarded_user_id": str(user_id)},
        )
        assets_recovered.append(asset.asset_tag)

    # (6) Revoke temporary access grants (role rows removed).
    grants = (
        session.execute(
            select(TemporaryAccessGrant).where(
                TemporaryAccessGrant.organization_id == org_id,
                TemporaryAccessGrant.user_id == user_id,
                TemporaryAccessGrant.status == "active",
            )
        )
        .scalars()
        .all()
    )
    grants_revoked = 0
    for grant in grants:
        from sqlalchemy import delete as _delete

        session.execute(
            _delete(UserRole).where(
                UserRole.organization_id == org_id,
                UserRole.user_id == user_id,
                UserRole.role_id == grant.role_id,
            )
        )
        grant.status = "revoked"
        grant.revoked_at = now
        grants_revoked += 1
    session.flush()

    # (7) Audit the full report.
    report = {
        "user_id": str(user_id),
        "user_email": user.email,
        "assets_recovered": assets_recovered,
        "tickets_created": tickets_created,
        "sessions_revoked": len(sessions),
        "temp_grants_revoked": grants_revoked,
        "membership_status": "suspended",
    }
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.OFFBOARDING_COMPLETED,
        resource_type="user",
        resource_id=str(user_id),
        outcome="success",
        metadata=report,
    )
    session.flush()
    return report
