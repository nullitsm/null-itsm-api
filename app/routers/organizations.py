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
    get_user_principal,
    require_permission,
)
from app.models.auth import Invitation
from app.models.email import EmailDelivery
from app.models.platform import Organization, User
from app.models.registration import DevEmailOutbox
from app.schemas import (
    DepartmentCreate,
    DepartmentOut,
    InvitationOut,
    InviteRequest,
    MemberOut,
    MemberRemoveOut,
    MemberRemoveRequest,
    MembershipStatusUpdate,
    OnboardingOut,
    OnboardingUpdate,
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
    OutboxOut,
    PolicyUpdate,
    TeamCreate,
    TeamOut,
)
from app.services import email as email_service
from app.services import onboarding_service, org_service

router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


def _org_out(org: Organization) -> OrganizationOut:
    return OrganizationOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        is_active=org.is_active,
        is_dev_fixture=org.is_dev_fixture,
        contact_email=org.contact_email,
        website=org.website,
        industry=org.industry,
        size=org.size,
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
def my_organizations(session: Session = Depends(get_db), principal: Principal = Depends(get_user_principal)):
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


@router.post("/{org_id}/members/{user_id}/remove", response_model=MemberRemoveOut)
def remove_member(
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    body: MemberRemoveRequest | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    """Remove a technician from the organization (deactivate, not delete).

    Access is revoked immediately, assigned assets are flagged for
    recovery with a recovery ticket each, and any pending invitation
    for the member's email is cancelled. The user record and audit
    history are preserved; re-adding requires a fresh invitation.
    Refused (400): the organization owner, the last Organization
    Administrator, or a member who is already removed.
    """
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    try:
        report = org_service.remove_technician(
            session, org, principal.user_id, user_id, body.reason if body else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return MemberRemoveOut(**report)


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


def _invitation_out(
    invitation: Invitation,
    accept_url: str | None = None,
    delivery: dict | None = None,
) -> InvitationOut:
    return InvitationOut(
        id=invitation.id,
        email=invitation.email,
        full_name=invitation.full_name,
        department=invitation.department,
        team=invitation.team,
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        accept_url=accept_url,
        delivery=delivery,
    )


def _delivery_row_dict(session: Session, result) -> dict | None:
    """Delivery dict for a just-completed send, from its recorded row."""
    if result is None or result.delivery_id is None:
        return None
    row = session.get(EmailDelivery, uuid.UUID(result.delivery_id))
    return email_service.delivery_to_dict(row)


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
        invitation, _token, accept_url, delivery = org_service.invite_technician(
            session,
            org,
            session.get(User, principal.user_id),
            body.email,
            body.role_ids,
            full_name=body.full_name,
            department=body.department,
            team=body.team,
        )
    except email_service.EmailConfigurationError as exc:
        # Provider selected but no key: fail loudly, create nothing.
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    delivery_out = _delivery_row_dict(session, delivery)
    session.commit()
    # The accept link is returned to the inviting admin ONLY in dev mode
    # (no provider configured) for local testing. When a provider is
    # configured the email is the delivery channel and no link is exposed.
    return _invitation_out(
        invitation,
        accept_url=accept_url if not email_service.email_delivery_configured() else None,
        delivery=delivery_out,
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
        _invitation_out(
            r,
            delivery=email_service.delivery_to_dict(
                email_service.latest_delivery_for_invitation(session, org_invitation_id=r.id)
            ),
        )
        for r in rows
    ]


@router.post("/{org_id}/invitations/{invitation_id}/resend", response_model=InvitationOut)
def resend_invitation(
    org_id: uuid.UUID,
    invitation_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:invite")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    try:
        invitation, _token, accept_url, delivery = org_service.resend_invitation(
            session, org, principal.user_id, invitation_id
        )
    except email_service.EmailConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    delivery_out = _delivery_row_dict(session, delivery)
    session.commit()
    return _invitation_out(
        invitation,
        accept_url=accept_url if not email_service.email_delivery_configured() else None,
        delivery=delivery_out,
    )


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


# --- Departments & teams -------------------------------------------------------


@router.get("/{org_id}/departments", response_model=list[DepartmentOut])
def list_departments(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:read")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    return [
        DepartmentOut(
            id=d.id,
            organization_id=d.organization_id,
            name=d.name,
            description=d.description,
            created_at=d.created_at,
        )
        for d in org_service.list_departments(session, org_id)
    ]


@router.post("/{org_id}/departments", response_model=DepartmentOut, status_code=status.HTTP_201_CREATED)
def create_department(
    org_id: uuid.UUID,
    body: DepartmentCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    try:
        dept = org_service.create_department(session, org_id, body.name, body.description)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return DepartmentOut(
        id=dept.id,
        organization_id=dept.organization_id,
        name=dept.name,
        description=dept.description,
        created_at=dept.created_at,
    )


@router.get("/{org_id}/teams", response_model=list[TeamOut])
def list_teams(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:read")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    return [
        TeamOut(
            id=t.id,
            organization_id=t.organization_id,
            department_id=t.department_id,
            name=t.name,
            description=t.description,
            created_at=t.created_at,
        )
        for t in org_service.list_teams(session, org_id)
    ]


@router.post("/{org_id}/teams", response_model=TeamOut, status_code=status.HTTP_201_CREATED)
def create_team(
    org_id: uuid.UUID,
    body: TeamCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    try:
        team = org_service.create_team(session, org_id, body.name, body.department_id, body.description)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return TeamOut(
        id=team.id,
        organization_id=team.organization_id,
        department_id=team.department_id,
        name=team.name,
        description=team.description,
        created_at=team.created_at,
    )


# --- Onboarding ----------------------------------------------------------------


@router.get("/{org_id}/onboarding", response_model=OnboardingOut)
def get_onboarding(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:read")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    row = onboarding_service.get_or_init_onboarding(session, org_id)
    return OnboardingOut(
        organization_id=row.organization_id,
        current_step=row.current_step,
        steps=dict(row.steps or {}),
        completed_at=row.completed_at,
    )


@router.patch("/{org_id}/onboarding", response_model=OnboardingOut)
def update_onboarding(
    org_id: uuid.UUID,
    body: OnboardingUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    org = session.get(Organization, org_id)
    try:
        row = onboarding_service.update_step(
            session, org, principal.user_id, body.step, body.status, body.data
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return OnboardingOut(
        organization_id=row.organization_id,
        current_step=row.current_step,
        steps=dict(row.steps or {}),
        completed_at=row.completed_at,
    )


# --- Dev email outbox (local testing only) -------------------------------------


@router.get("/{org_id}/outbox", response_model=list[OutboxOut])
def list_outbox(
    org_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:invite")),
):
    """Read the dev outbox: every invitation email the backend would
    have sent for this org (SMTP unconfigured in local dev). The
    invitation link is in the body. Local testing only."""
    if org_id != principal.organization_id:
        raise Forbidden("Organization mismatch")
    rows = session.execute(
        select(DevEmailOutbox)
        .where(DevEmailOutbox.organization_id == org_id)
        .order_by(DevEmailOutbox.created_at.desc())
    ).scalars()
    return [
        OutboxOut(
            id=r.id,
            organization_id=r.organization_id,
            scope=r.scope,
            to_email=r.to_email,
            subject=r.subject,
            body=r.body,
            created_at=r.created_at,
        )
        for r in rows
    ]


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
