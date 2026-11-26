"""Test-only data factory.

Creates organizations and users FRESH inside the test run, against the
test database that conftest recreates on every run. Nothing here is a
shipped fixture: there is no seed module, no seed CLI, and no
``NULL_SEED_DEV_FIXTURES`` switch anywhere in the app. The two
organizations below exist only for the duration of one test run and are
dropped with the test database.

The mechanics (RLS context before each INSERT ... RETURNING, admin user
before the organization row, role seeding) mirror what the production
org-provisioning path does; they live here because tests need
authenticated principals without going through a public registration
endpoint, which this API does not expose.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.platform import Membership, Organization, User
from app.models.platform_admin import PlatformUser, PlatformUserRole
from app.models.rbac import UserRole
from app.security import hash_password
from app.services.org_service import seed_org_roles
from app.services.platform_service import seed_platform_roles

TEST_PASSWORD = "TestPass123!@#"

# Organizations created fresh for each test run (test database only).
TEST_ORGS = [
    {
        "name": "Acme IT Services",
        "slug": "acme",
        "admin": ("Alice Admin", "alice@acme.example.com"),
        "technician": ("Tom Technician", "tom@acme.example.com"),
        "technician_role": "Service Desk Technician",
    },
    {
        "name": "Globex Manufacturing",
        "slug": "globex",
        "admin": ("Gina Admin", "gina@globex.example.com"),
        "technician": ("Greg Technician", "greg@globex.example.com"),
        "technician_role": "IT Operations",
    },
]

PLATFORM_ADMIN_EMAIL = "platform@null.example.com"


def _least_privilege_settings() -> dict:
    return {
        "least_privilege_policy": {
            "enforce_least_privilege": True,
            "require_approval_for_elevated": True,
            "periodic_access_review": True,
            "access_expiration": False,
            "access_review_schedule": "90d",
        }
    }


def create_test_org(session: Session, spec: dict) -> Organization:
    """Create one test organization with an admin and a technician.

    Idempotent within a run: an existing slug is skipped. The ticket
    counter is created lazily by ticket creation, so no ticket is
    created here — the organization starts empty.
    """
    from app.database import set_rls_context

    existing = session.execute(
        select(Organization).where(Organization.slug == spec["slug"])
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    org_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    tech_id = uuid.uuid4()
    set_rls_context(session, org_id, admin_id)

    # The admin user must exist BEFORE the organization row: the org
    # records created_by_id (FK to users) and its INSERT ... RETURNING
    # is checked against the SELECT policy, which passes for the creator.
    admin = User(
        id=admin_id,
        email=spec["admin"][1],
        full_name=spec["admin"][0],
        password_hash=hash_password(TEST_PASSWORD),
        email_verified=True,
    )
    session.add(admin)
    session.flush()

    org = Organization(
        id=org_id,
        name=spec["name"],
        slug=spec["slug"],
        settings=_least_privilege_settings(),
        is_dev_fixture=False,
        created_by_id=admin_id,
    )
    session.add(org)
    session.flush()

    tech = User(
        id=tech_id,
        email=spec["technician"][1],
        full_name=spec["technician"][0],
        password_hash=hash_password(TEST_PASSWORD),
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
                role_id=roles[spec["technician_role"]].id,
                granted_by_id=admin.id,
            ),
        ]
    )
    session.flush()
    return org


def create_test_platform_admin(session: Session, email: str = PLATFORM_ADMIN_EMAIL) -> PlatformUser:
    """Create the test platform super admin (belongs to no org).

    Idempotent within a run. MFA is NOT enabled on this user, so its
    login yields an mfa=true token directly. Tests that need an
    MFA-enabled platform user create a fresh one.
    """
    from app.database import set_rls_context

    platform_admin_id = uuid.uuid4()
    set_rls_context(session, None, None, platform_admin_id)
    existing = session.execute(
        select(PlatformUser).where(PlatformUser.email == email)
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    platform_admin = PlatformUser(
        id=platform_admin_id,
        email=email,
        full_name="NULL Platform Admin",
        password_hash=hash_password(TEST_PASSWORD),
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
    return platform_admin


def create_test_data(session: Session) -> list[Organization]:
    """Create the test organizations and the test platform admin."""
    created = [create_test_org(session, spec) for spec in TEST_ORGS]
    create_test_platform_admin(session)
    session.commit()
    return created
