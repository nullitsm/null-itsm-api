"""Request/response schemas (Pydantic v2)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

# --- Auth -----------------------------------------------------------------


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    status: str  # ok | mfa_required | org_required | no_org
    access_token: str | None = None
    refresh_token: str | None = None
    mfa_token: str | None = None
    org_select_token: str | None = None
    user_id: str | None = None
    organizations: list[dict] | None = None


class MfaChallengeRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=6)


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class SelectOrganizationRequest(BaseModel):
    # Called with the org_select_token from a multi-org login; the user id
    # comes from that token, never from the request body.
    organization_id: uuid.UUID


class SwitchOrganizationRequest(BaseModel):
    refresh_token: str
    organization_id: uuid.UUID


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=12)


class AcceptInvitationRequest(BaseModel):
    token: str
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# --- Organizations --------------------------------------------------------


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str | None = Field(default=None, max_length=100)


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)


class OrganizationOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    is_dev_fixture: bool
    created_at: datetime


class PolicyUpdate(BaseModel):
    enforce_least_privilege: bool | None = None
    require_approval_for_elevated: bool | None = None
    periodic_access_review: bool | None = None
    access_expiration: bool | None = None
    access_review_schedule: str | None = None


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str
    status: str
    is_owner: bool
    expires_at: str | None
    joined_at: str


class MembershipStatusUpdate(BaseModel):
    status: str  # active | suspended
    expires_at: datetime | None = None


# --- Invitations ----------------------------------------------------------


class InviteRequest(BaseModel):
    email: EmailStr
    role_ids: list[uuid.UUID] = Field(default_factory=list)


class InvitationOut(BaseModel):
    id: uuid.UUID
    email: str
    status: str
    expires_at: datetime
    created_at: datetime


# --- Users & Roles --------------------------------------------------------


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    mfa_enabled: bool
    roles: list[str] = []


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = ""
    access_level: str = "Least Privilege"
    permission_codes: list[str] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    description: str | None = None
    access_level: str | None = None


class RolePermissionsUpdate(BaseModel):
    permission_codes: list[str]


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    access_level: str
    is_system: bool
    permissions: list[str] = []


class AssignRoleRequest(BaseModel):
    user_id: uuid.UUID
    role_id: uuid.UUID


class RevokeRoleRequest(BaseModel):
    user_id: uuid.UUID
    role_id: uuid.UUID


class ApprovalDecision(BaseModel):
    approve: bool


class ApprovalOut(BaseModel):
    id: uuid.UUID
    requested_by_id: uuid.UUID
    target_user_id: uuid.UUID
    role_id: uuid.UUID
    status: str
    created_at: datetime


class PermissionOut(BaseModel):
    code: str
    module: str
    description: str


# --- Audit ----------------------------------------------------------------


class AuditLogOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    metadata: dict
    created_at: datetime


# --- Tickets (Phase 1 isolation proof) ------------------------------------


class TicketCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    priority: str = "medium"
    category: str = "General"


class TicketUpdate(BaseModel):
    status: str | None = None
    priority: str | None = None
    assignee_id: uuid.UUID | None = None


class TicketOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    number: str
    title: str
    description: str
    status: str
    priority: str
    category: str
    requester_id: uuid.UUID | None
    assignee_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    # SLA state (Phase 2, migration 0005) — None when no policy matches.
    first_response_due_at: datetime | None = None
    resolution_due_at: datetime | None = None
    first_response_at: datetime | None = None
    resolved_at: datetime | None = None
    sla_policy_id: uuid.UUID | None = None
    sla_breached: bool = False


# --- Platform administration ----------------------------------------------
# The platform domain reuses the shared auth request/response schemas
# (LoginRequest, MfaChallengeRequest, RefreshRequest, LogoutRequest,
# MfaVerifyRequest, MfaEnrollResponse, LoginResponse, TokenResponse) and
# the shared role schemas (RoleCreate, RoleUpdate, RolePermissionsUpdate,
# RoleOut) — platform roles use the same shape as org roles, with the
# platform:* permission catalog instead of the org catalog.


class PlatformUserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12)


class PlatformUserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    mfa_enabled: bool
    source: str
    review_status: str
    roles: list[str] = []
    created_at: datetime


class AssignPlatformRoleRequest(BaseModel):
    role_id: uuid.UUID


class SupportGrantCreate(BaseModel):
    organization_id: uuid.UUID
    purpose: str = Field(min_length=1)
    expires_at: datetime


class SupportGrantOut(BaseModel):
    id: uuid.UUID
    platform_user_id: uuid.UUID
    organization_id: uuid.UUID
    purpose: str
    status: str
    granted_by_id: uuid.UUID | None
    approved_by_id: uuid.UUID | None
    expires_at: datetime
    created_at: datetime


class TenantOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    is_dev_fixture: bool
    created_at: datetime


class TenantUserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool


class PlatformAuditLogOut(BaseModel):
    id: uuid.UUID
    actor_id: uuid.UUID | None
    organization_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    metadata: dict
    created_at: datetime
