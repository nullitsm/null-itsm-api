"""Users & Roles routes — the backend behind the Users & Roles screen.

The screen's data model: users with roles, access levels, departments
(from membership metadata in later phases), and the six seeded roles.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import Principal, get_db, require_permission
from app.models.platform import Membership, User
from app.models.rbac import Permission
from app.schemas import PermissionOut, UserOut
from app.services import role_service

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(session: Session = Depends(get_db), principal: Principal = Depends(require_permission("users:manage"))):
    """All users in the caller's organization, with their roles."""
    rows = session.execute(
        select(User)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.organization_id == principal.organization_id, Membership.status == "active")
        .order_by(User.full_name)
    ).scalars()
    out = []
    for user in rows:
        roles = role_service.user_roles(session, principal.organization_id, user.id)
        out.append(
            UserOut(
                id=user.id,
                email=user.email,
                full_name=user.full_name,
                is_active=user.is_active,
                mfa_enabled=user.mfa_enabled,
                roles=[r.name for r in roles],
            )
        )
    return out


@router.get("/permissions/catalog", response_model=list[PermissionOut])
def permission_catalog(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("roles:manage"))
):
    rows = session.execute(select(Permission).order_by(Permission.module, Permission.code)).scalars()
    return [PermissionOut(code=p.code, module=p.module, description=p.description) for p in rows]


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    membership = session.execute(
        select(Membership).where(Membership.organization_id == principal.organization_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in this organization")
    user = session.get(User, user_id)
    roles = role_service.user_roles(session, principal.organization_id, user_id)
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        roles=[r.name for r in roles],
    )


@router.get("/{user_id}/roles", response_model=list[str])
def get_user_roles(
    user_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:manage")),
):
    membership = session.execute(
        select(Membership).where(Membership.organization_id == principal.organization_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in this organization")
    return [r.name for r in role_service.user_roles(session, principal.organization_id, user_id)]
