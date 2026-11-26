"""Model registry — importing this module registers every model."""

from app.models.access import AccessApproval, AccessReview
from app.models.audit import AuditLog
from app.models.auth import AuthSession, Invitation, InvitationRole, PasswordReset
from app.models.base import Base
from app.models.platform import Membership, Organization, User
from app.models.platform_admin import (
    PlatformAccessGrant,
    PlatformAuditLog,
    PlatformPermission,
    PlatformRole,
    PlatformRolePermission,
    PlatformSession,
    PlatformUser,
    PlatformUserRole,
)
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.models.ticket import Ticket, TicketCounter

__all__ = [
    "AccessApproval",
    "AccessReview",
    "AuditLog",
    "AuthSession",
    "Base",
    "Invitation",
    "InvitationRole",
    "Membership",
    "Organization",
    "PasswordReset",
    "Permission",
    "PlatformAccessGrant",
    "PlatformAuditLog",
    "PlatformPermission",
    "PlatformRole",
    "PlatformRolePermission",
    "PlatformSession",
    "PlatformUser",
    "PlatformUserRole",
    "Role",
    "RolePermission",
    "Ticket",
    "TicketCounter",
    "User",
    "UserRole",
]
