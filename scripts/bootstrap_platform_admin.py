"""Bootstrap the FIRST Platform Super Admin (CLI).

Usage:
    NULL_PLATFORM_ADMIN_EMAIL=admin@null.example.com \\
    NULL_PLATFORM_ADMIN_PASSWORD='<strong password>' \\
        python -m scripts.bootstrap_platform_admin

    python -m scripts.bootstrap_platform_admin --email admin@null.example.com \\
        --password '<strong password>' [--full-name "NULL Platform Admin"]

Credentials come from the environment or CLI arguments ONLY — never
from the repo, and never logged. The password must be at least 12
characters. The script:

- refuses to run if a Platform Super Admin already exists, unless
  ``--force`` is passed AND the operator types YES at the prompt;
- creates the user with source='bootstrap', review_status='approved';
- assigns the Platform Super Admin role;
- generates a TOTP secret and prints its provisioning URI ONCE to
  stdout so the admin can add it to an authenticator app, then verify
  it via POST /api/v1/platform/auth/mfa-verify. The URI is printed,
  never logged to a file.

Runs against the owner database URL (see scripts/seed_dev.py for the
session pattern): the owner role bypasses RLS, but the platform RLS
context is still set explicitly before each insert, matching the
application's insert discipline.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.database import set_rls_context
from app.models.platform_admin import PlatformUser, PlatformUserRole
from app.security import hash_password, new_totp_secret, totp_uri
from app.services.platform_service import SUPER_ADMIN_ROLE_NAME, seed_platform_roles

MIN_PASSWORD_LENGTH = 12


def _existing_super_admin(session) -> PlatformUser | None:
    """Return any platform user holding the Platform Super Admin role."""
    from app.models.platform_admin import PlatformRole

    row = (
        session.execute(
            select(PlatformUser)
            .join(PlatformUserRole, PlatformUserRole.platform_user_id == PlatformUser.id)
            .join(PlatformRole, PlatformRole.id == PlatformUserRole.role_id)
            .where(PlatformRole.name == SUPER_ADMIN_ROLE_NAME)
        )
        .scalars()
        .first()
    )
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the first Platform Super Admin.")
    parser.add_argument("--email", default=os.environ.get("NULL_PLATFORM_ADMIN_EMAIL"))
    parser.add_argument("--password", default=os.environ.get("NULL_PLATFORM_ADMIN_PASSWORD"))
    parser.add_argument("--full-name", default="NULL Platform Admin")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow creating another Super Admin when one already exists (requires typing YES).",
    )
    args = parser.parse_args(argv)

    if not args.email or not args.password:
        print(
            "Missing credentials: provide --email/--password or set "
            "NULL_PLATFORM_ADMIN_EMAIL / NULL_PLATFORM_ADMIN_PASSWORD.",
            file=sys.stderr,
        )
        return 2
    if len(args.password) < MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
        return 2

    settings = get_settings()
    engine = create_engine(settings.database_owner_url)
    session = sessionmaker(bind=engine)()
    try:
        # The platform_users SELECT policy gates on a non-empty platform
        # context; use a throwaway id for the pre-flight checks.
        set_rls_context(session, None, None, uuid.uuid4())
        existing = session.execute(select(PlatformUser).where(PlatformUser.email == args.email)).scalar_one_or_none()
        if existing is not None:
            print(f"Refusing: a platform user with email {args.email} already exists.", file=sys.stderr)
            return 1
        super_admin = _existing_super_admin(session)
        if super_admin is not None:
            if not args.force:
                print(
                    "Refusing: a Platform Super Admin already exists "
                    f"({super_admin.email}). Pass --force to create another one.",
                    file=sys.stderr,
                )
                return 1
            confirm = input("A Platform Super Admin already exists. Type YES to create another one: ").strip()
            if confirm != "YES":
                print("Aborted: confirmation not given.", file=sys.stderr)
                return 1

        user_id = uuid.uuid4()
        set_rls_context(session, None, None, user_id)
        secret = new_totp_secret()
        user = PlatformUser(
            id=user_id,
            email=args.email,
            full_name=args.full_name,
            password_hash=hash_password(args.password),
            mfa_secret=secret,
            mfa_enabled=False,
            source="bootstrap",
            review_status="approved",
        )
        session.add(user)
        session.flush()
        roles = seed_platform_roles(session)
        super_admin_role = roles[SUPER_ADMIN_ROLE_NAME]
        session.add(
            PlatformUserRole(
                platform_user_id=user.id,
                role_id=super_admin_role.id,
                granted_by_id=user.id,
            )
        )
        session.commit()
        print(f"Created Platform Super Admin: {user.email} ({user.id})")
        print("MFA is NOT enabled yet. Add this authenticator URI to your TOTP app,")
        print("then verify it via POST /api/v1/platform/auth/mfa-verify.")
        print("Provisioning URI (shown ONCE — store it in your authenticator now):")
        print(totp_uri(secret, user.email))
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
