"""Public organization registration.

One endpoint creates the organization, its first administrator, the
owner membership, the Organization Administrator role grant, default
settings, default departments, and the onboarding record — atomically.
Registration NEVER creates a platform administrator: it stays strictly
in the org domain (no platform tables are touched here at all).

If the admin email already belongs to an account, registration is
refused: the owner signs in and creates another organization through
the authenticated endpoint instead. This keeps registration
unauthenticated but safe — nobody can attach a new org to someone
else's account.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.database import set_rls_context
from app.models.platform import Organization, User
from app.models.registration import OrgOnboarding
from app.security import hash_password
from app.services import org_service


def register_organization(
    session: Session,
    *,
    org_name: str,
    org_email: str,
    website: str | None,
    industry: str | None,
    org_size: str | None,
    admin_name: str,
    admin_email: str,
    password: str,
) -> tuple[Organization, User]:
    """Register a new organization + its first administrator."""
    admin_email = admin_email.strip().lower()
    org_email = org_email.strip().lower()
    # Raw ORM reads are RLS-filtered with no context set: resolve the
    # email through the SECURITY DEFINER lookup (same as login).
    from app.services import auth_service

    if auth_service._lookup_user_by_email(session, admin_email) is not None:
        raise ValueError("An account with this email already exists — sign in to create another organization")

    admin_id = uuid.uuid4()
    # The users INSERT policy requires a non-empty org context; the
    # account belongs to no org yet, so a throwaway UUID is used (same
    # rule as the no-org user creation in the test harness). The SELECT
    # policy passes for the row's own id, set as the user context.
    set_rls_context(session, uuid.uuid4(), admin_id)
    admin = User(
        id=admin_id,
        email=admin_email,
        full_name=admin_name.strip(),
        password_hash=hash_password(password),
        email_verified=True,
    )
    session.add(admin)
    session.flush()

    org = org_service.create_organization(session, admin, org_name)
    org.contact_email = org_email
    org.website = website
    org.industry = industry
    org.size = org_size
    session.flush()

    org_service.create_default_departments(session, org.id)

    session.add(
        OrgOnboarding(
            organization_id=org.id,
            current_step="departments",
            steps={
                "profile": "complete",
                "departments": "pending",
                "invite_technicians": "pending",
                "service_desk": "pending",
                "business_hours_sla": "pending",
                "assets_endpoints": "pending",
                "finish": "pending",
            },
        )
    )
    audit_mod.write_audit(
        session,
        organization_id=org.id,
        actor_id=admin.id,
        action=audit_mod.ORG_REGISTERED,
        resource_type="organization",
        resource_id=str(org.id),
        outcome="success",
        metadata={
            "name": org.name,
            "slug": org.slug,
            "contact_email": org_email,
            "industry": industry,
            "size": org_size,
        },
    )
    return org, admin
