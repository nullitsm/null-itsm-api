"""Development fixtures — TWO test organizations, clearly labelled.

This module seeds ONLY development/test data and is gated by
``NULL_SEED_DEV_FIXTURES=true``. It never runs in production.

Organizations:
- Acme IT Services (slug ``acme``) — admin alice@acme.example.com, technician
  tom@acme.example.com
- Globex Manufacturing (slug ``globex``) — admin gina@globex.example.com,
  technician greg@globex.example.com

All fixture users share the documented dev password ``DevPass123!@#``.
Fixture organizations are marked ``is_dev_fixture=True`` so they are
unmistakable in any listing. Each organization also gets one fixture
ticket so tenant isolation can be observed immediately.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.platform import Membership, Organization, User
from app.models.rbac import UserRole
from app.models.ticket import Ticket, TicketCounter
from app.security import hash_password
from app.services.org_service import seed_org_roles

DEV_PASSWORD = "DevPass123!@#"

FIXTURES = [
    {
        "name": "Acme IT Services",
        "slug": "acme",
        "admin": ("Alice Admin", "alice@acme.example.com"),
        "technician": ("Tom Technician", "tom@acme.example.com"),
        "technician_role": "Service Desk Technician",
        "ticket_title": "Acme fixture: VPN drops on laptop",
    },
    {
        "name": "Globex Manufacturing",
        "slug": "globex",
        "admin": ("Gina Admin", "gina@globex.example.com"),
        "technician": ("Greg Technician", "greg@globex.example.com"),
        "technician_role": "IT Operations",
        "ticket_title": "Globex fixture: Printer offline on floor 2",
    },
]


def seed_dev_fixtures(session: Session) -> list[Organization]:
    """Create the two fixture organizations. Idempotent: existing slugs
    are skipped. RLS context is set per organization before its rows are
    inserted (the seed runs as the owner role, which is also RLS-bound).

    Also creates one clearly-labelled dev platform super admin
    (platform@null.example.com) so the platform domain can be exercised
    in tests; it is NOT an organization user and belongs to no org.
    """
    from app.database import set_rls_context
    from app.models.platform_admin import PlatformUser, PlatformUserRole
    from app.services.platform_service import seed_platform_roles

    created: list[Organization] = []
    for fixture in FIXTURES:
        existing = session.execute(
            select(Organization).where(Organization.slug == fixture["slug"])
        ).scalar_one_or_none()
        if existing is not None:
            continue
        org_id = uuid.uuid4()
        admin_id = uuid.uuid4()
        tech_id = uuid.uuid4()
        set_rls_context(session, org_id, admin_id)

        # The admin user must exist BEFORE the organization row: the org
        # records created_by_id (FK to users) and its INSERT ... RETURNING
        # is checked against the SELECT policy, which passes for the creator.
        admin = User(
            id=admin_id,
            email=fixture["admin"][1],
            full_name=fixture["admin"][0],
            password_hash=hash_password(DEV_PASSWORD),
            email_verified=True,
        )
        session.add(admin)
        session.flush()

        org = Organization(
            id=org_id,
            name=fixture["name"],
            slug=fixture["slug"],
            settings={
                "least_privilege_policy": {
                    "enforce_least_privilege": True,
                    "require_approval_for_elevated": True,
                    "periodic_access_review": True,
                    "access_expiration": False,
                    "access_review_schedule": "90d",
                }
            },
            is_dev_fixture=True,
            created_by_id=admin_id,
        )
        session.add(org)
        session.flush()

        tech = User(
            id=tech_id,
            email=fixture["technician"][1],
            full_name=fixture["technician"][0],
            password_hash=hash_password(DEV_PASSWORD),
            email_verified=True,
        )
        # Same rule as the admin: the RLS user context must be the row's
        # own id before its INSERT ... RETURNING is checked.
        set_rls_context(session, org_id, tech_id)
        session.add(tech)
        session.flush()
        set_rls_context(session, org_id, admin_id)

        session.add_all(
            [
                Membership(organization_id=org.id, user_id=admin.id, status="active", is_owner=True),
                Membership(organization_id=org.id, user_id=tech.id, status="active"),
            ]
        )
        roles = seed_org_roles(session, org.id)
        session.add_all(
            [
                UserRole(
                    organization_id=org.id,
                    user_id=admin.id,
                    role_id=roles["Organization Administrator"].id,
                    granted_by_id=admin.id,
                ),
                UserRole(
                    organization_id=org.id,
                    user_id=tech.id,
                    role_id=roles[fixture["technician_role"]].id,
                    granted_by_id=admin.id,
                ),
            ]
        )
        session.add(
            Ticket(
                organization_id=org.id,
                number="INC-000001",
                title=fixture["ticket_title"],
                description="Seeded development fixture ticket.",
                status="open",
                priority="medium",
                category="General",
                requester_id=admin.id,
                assignee_id=tech.id,
            )
        )
        # The fixture ticket consumes INC-000001: advance the per-org
        # counter past it, or the first API-created ticket collides on
        # the (organization_id, number) unique constraint.
        session.add(TicketCounter(organization_id=org.id, last_number=1))
        session.flush()
        created.append(org)
    # Dev platform super admin (clearly labelled fixture, no org).
    platform_admin_id = uuid.uuid4()
    set_rls_context(session, None, None, platform_admin_id)
    existing_platform = session.execute(
        select(PlatformUser).where(PlatformUser.email == "platform@null.example.com")
    ).scalar_one_or_none()
    if existing_platform is None:
        platform_admin = PlatformUser(
            id=platform_admin_id,
            email="platform@null.example.com",
            full_name="NULL Platform Admin",
            password_hash=hash_password(DEV_PASSWORD),
            source="bootstrap",
            review_status="approved",
        )
        session.add(platform_admin)
        session.flush()
        roles = seed_platform_roles(session)
        session.add(
            PlatformUserRole(
                platform_user_id=platform_admin.id,
                role_id=roles["Platform Super Admin"].id,
                granted_by_id=platform_admin.id,
            )
        )
        session.flush()
    session.commit()
    return created


def seed_dev_fixtures_count(session: Session) -> int:
    return len(session.execute(select(Organization).where(Organization.is_dev_fixture.is_(True))).scalars().all())
