"""Role routes: CRUD, permission configuration, assignment, approvals."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import Principal, get_db, require_permission
from app.models.access import AccessApproval
from app.models.platform import Organization
from app.schemas import (
    ApprovalDecision,
    ApprovalOut,
    AssignRoleRequest,
    RevokeRoleRequest,
    RoleCreate,
    RoleOut,
    RolePermissionsUpdate,
    RoleUpdate,
)
from app.services import role_service

router = APIRouter(prefix="/api/v1/roles", tags=["roles"])


def _role_out(session: Session, role) -> RoleOut:
    return RoleOut(
        id=role.id,
        name=role.name,
        description=role.description,
        access_level=role.access_level,
        is_system=role.is_system,
        permissions=role_service.role_permission_codes(session, role.id),
    )


@router.get("", response_model=list[RoleOut])
def list_roles(session: Session = Depends(get_db), principal: Principal = Depends(require_permission("roles:manage"))):
    return [_role_out(session, r) for r in role_service.list_roles(session, principal.organization_id)]


@router.post("", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_role(
    body: RoleCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    org = session.get(Organization, principal.organization_id)
    try:
        role = role_service.create_role(
            session, org, principal, body.name, body.description, body.access_level, body.permission_codes
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return _role_out(session, role)


@router.get("/{role_id}", response_model=RoleOut)
def get_role(
    role_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    role = role_service.get_role(session, principal.organization_id, role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return _role_out(session, role)


@router.patch("/{role_id}", response_model=RoleOut)
def update_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    role = role_service.get_role(session, principal.organization_id, role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    org = session.get(Organization, principal.organization_id)
    try:
        role = role_service.update_role(session, org, principal, role, body.description, body.access_level)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return _role_out(session, role)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    role = role_service.get_role(session, principal.organization_id, role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    org = session.get(Organization, principal.organization_id)
    try:
        role_service.delete_role(session, org, principal, role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return None


@router.put("/{role_id}/permissions", response_model=RoleOut)
def configure_permissions(
    role_id: uuid.UUID,
    body: RolePermissionsUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("permissions:manage")),
):
    role = role_service.get_role(session, principal.organization_id, role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    org = session.get(Organization, principal.organization_id)
    try:
        role = role_service.configure_role_permissions(session, org, principal, role, body.permission_codes)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return _role_out(session, role)


@router.post("/assign")
def assign_role(
    body: AssignRoleRequest,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    role = role_service.get_role(session, principal.organization_id, body.role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    org = session.get(Organization, principal.organization_id)
    try:
        result = role_service.assign_role(session, org, principal, body.user_id, role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return result


@router.post("/revoke")
def revoke_role(
    body: RevokeRoleRequest,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    role = role_service.get_role(session, principal.organization_id, body.role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    org = session.get(Organization, principal.organization_id)
    try:
        role_service.revoke_role(session, org, principal, body.user_id, role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return {"status": "ok"}


# --- Elevated-access approvals ----------------------------------------------


@router.get("/approvals/pending", response_model=list[ApprovalOut])
def pending_approvals(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("roles:manage"))
):
    rows = session.execute(
        select(AccessApproval).where(
            AccessApproval.organization_id == principal.organization_id,
            AccessApproval.status == "pending",
        )
    ).scalars()
    return [
        ApprovalOut(
            id=r.id,
            requested_by_id=r.requested_by_id,
            target_user_id=r.target_user_id,
            role_id=r.role_id,
            status=r.status,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("/approvals/{approval_id}/decide")
def decide_approval(
    approval_id: uuid.UUID,
    body: ApprovalDecision,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("roles:manage")),
):
    org = session.get(Organization, principal.organization_id)
    try:
        approval = role_service.decide_approval(session, org, principal, approval_id, body.approve)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    session.commit()
    return {"status": approval.status}
