"""Organization routes: provisioning, settings, members, policy, reviews."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import (
    Forbidden,
    Principal,
    get_db,
    get_principal,
    get_user_from_token,
    require_permission,
)
from app.models.auth import Invitation
from app.models.platform import Organization, User
from app.schemas import (
    InvitationOut,
    InviteRequest,
    MemberOut,
    MembershipStatusUpdate,
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
    PolicyUpdate,
)
from app.services import org_service

router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


def _org_out(org: Organization) -> OrganizationOut:
    return OrganizationOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        is_active=org.is_active,
        is_dev_fixture=org.is_dev_fixture,
        created_at=org.created_at,
    )


@router.post("", response_model=OrganizationOut, status_code=status.HTTP_201_CREATED)
def create_organization(
    body: OrganizationCreate,
    session: Session = Depends(get_db),
    user_id_email=Depends(get_user_from_token),
):
    """Provision a new organization. The caller becomes its owner and
    Administrator. Works for users with no organization yet."""
    user_id, _ = user_id_email
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    try:
        org = org_service.create_organization(session, user, body.name, body.slug)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return _org_out(org)


@router.get("/mine", response_model=list[OrganizationOut])
def my_organizations(session: Session = Depends(get_db), principal: Principal = Depends(get_principal)):
    """Organizations the caller belongs to (used by the org switcher)."""
    from app.models.platform import Membership

    rows = session.execute(
        select(Organization)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == principal.user_id, Membership.status == "active")
    ).scalars()
    return [_org_out(o) for o in rows]


@router.get("/{org_id}", response_model=OrganizationOut)
def get_organization(
    org_id: uuid.UUID, session: Session = Depends(get_db), principal: Principal = Depends(get_principal)
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return _org_out(org)


@router.patch("/{org_id}", response_model=OrganizationOut)
def update_organization(
    org_id: uuid.UUID,
    body: OrganizationUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("org:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if body.name is not None:
        org.name = body.name
    session.commit()
    return _org_out(org)


# --- Members ---------------------------------------------------------------


@router.get("/{org_id}/members", response_model=list[MemberOut])
def list_members(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    return [MemberOut(**m) for m in org_service.list_members(session, org_id)]


@router.patch("/{org_id}/members/{user_id}")
def update_member(
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    body: MembershipStatusUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    try:
        membership = org_service.update_membership_status(session, org, principal.user_id, user_id, body.status)
        if body.expires_at is not None:
            membership.expires_at = body.expires_at
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return {"status": "ok", "membership_status": membership.status}


# --- Least-privilege policy -------------------------------------------------


@router.get("/{org_id}/policy")
def get_policy(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    return org_service.get_policy(org)


@router.put("/{org_id}/policy")
def set_policy(
    org_id: uuid.UUID,
    body: PolicyUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    policy = org_service.set_policy(session, org, principal.user_id, body.model_dump(exclude_none=True))
    session.commit()
    return policy


# --- Invitations -------------------------------------------------------------


@router.post("/{org_id}/invitations", response_model=InvitationOut, status_code=status.HTTP_201_CREATED)
def invite(
    org_id: uuid.UUID,
    body: InviteRequest,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:invite")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    try:
        invitation, _token = org_service.invite_technician(
            session, org, session.get(User, principal.user_id), body.email, body.role_ids
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return InvitationOut(
        id=invitation.id,
        email=invitation.email,
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
    )


@router.get("/{org_id}/invitations", response_model=list[InvitationOut])
def list_invitations(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:invite")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    rows = session.execute(
        select(Invitation).where(Invitation.organization_id == org_id).order_by(Invitation.created_at.desc())
    ).scalars()
    return [
        InvitationOut(id=r.id, email=r.email, status=r.status, expires_at=r.expires_at, created_at=r.created_at)
        for r in rows
    ]


@router.post("/{org_id}/invitations/{invitation_id}/revoke")
def revoke_invitation(
    org_id: uuid.UUID,
    invitation_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:invite")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    try:
        org_service.revoke_invitation(session, org, principal.user_id, invitation_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    session.commit()
    return {"status": "ok"}


# --- Access reviews -----------------------------------------------------------


@router.post("/{org_id}/access-reviews", status_code=status.HTTP_201_CREATED)
def start_access_review(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    review = org_service.start_access_review(session, org, principal.user_id)
    session.commit()
    return {"id": str(review.id), "status": review.status, "created_at": review.created_at.isoformat()}


@router.post("/{org_id}/access-reviews/{review_id}/complete")
def complete_access_review(
    org_id: uuid.UUID,
    review_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    try:
        review = org_service.complete_access_review(session, org, principal.user_id, review_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    session.commit()
    return {"id": str(review.id), "status": review.status}
