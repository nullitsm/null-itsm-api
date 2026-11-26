"""Database engine, sessions, and Row-Level Security (RLS) context.

Multi-tenancy model
-------------------
Every tenant-owned row carries ``organization_id``. PostgreSQL Row-Level
Security policies (see alembic/versions/0001_initial.py) enforce that a
database session only sees rows belonging to the organization recorded in
the session variable ``app.current_org_id``.

The application connects as the ``null_app`` role, which is NOT a table
owner, so RLS applies to it. Migrations and seed run as ``null_owner``.

Per-request flow (see app/deps.py):
  1. Authenticate the caller and resolve their organization server-side
     (from the session row — never from a client-supplied org id alone).
  2. Open a DB session, ``BEGIN``, then ``SET LOCAL app.current_org_id``
     and ``SET LOCAL app.current_user_id``.
  3. All queries in that transaction are RLS-filtered automatically.

``SET LOCAL`` only lives for the current transaction, so a leaked session
variable cannot bleed into the next request.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

#: The nil UUID is used as the RLS org context only inside the controlled
#: authentication flows (login / invitation / password-reset lookups), which
#: reach user rows through SECURITY DEFINER functions instead of raw table
#: reads. No ordinary request ever runs with a nil org context.
NIL_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")


def as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    """Accept a UUID value in either form.

    psycopg returns UUID columns as ``uuid.UUID`` objects, while JWT claims
    and API input arrive as strings. ``uuid.UUID()`` rejects an already-
    parsed UUID, so normalize through this helper wherever a value may
    come from either source.
    """
    return value if isinstance(value, uuid.UUID) else uuid.UUID(value)


def set_rls_context(
    session: Session,
    org_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    platform_user_id: uuid.UUID | None = None,
) -> None:
    """Set the per-transaction RLS context variables.

    Must be called after the session has begun a transaction. Callers should
    use :func:`tenant_session` / :func:`platform_session` instead of calling
    this directly.

    ``app.current_platform_user_id`` is the platform domain's identity
    (see app/models/platform_admin.py). It is separate from the org
    ``app.current_user_id``: platform users are not organization members,
    so the two ids must never be conflated.
    """
    org_value = str(org_id) if org_id is not None else ""
    user_value = str(user_id) if user_id is not None else ""
    platform_value = str(platform_user_id) if platform_user_id is not None else ""
    session.execute(text("SELECT set_config('app.current_org_id', :v, true)"), {"v": org_value})
    session.execute(text("SELECT set_config('app.current_user_id', :v, true)"), {"v": user_value})
    session.execute(text("SELECT set_config('app.current_platform_user_id', :v, true)"), {"v": platform_value})


@contextmanager
def tenant_session(org_id: uuid.UUID | None, user_id: uuid.UUID | None = None) -> Iterator[Session]:
    """Yield a session whose transaction is RLS-scoped to ``org_id``.

    Use for background jobs (Celery tasks carry ``org_id``) and scripts.
    Request handlers use the ``get_db`` dependency instead.
    """
    session = SessionLocal()
    try:
        session.begin()
        set_rls_context(session, org_id, user_id)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def platform_session(platform_user_id: uuid.UUID) -> Iterator[Session]:
    """Yield a session whose transaction is scoped to a platform identity.

    Platform tables are RLS-gated on ``app.current_platform_user_id``;
    org tables stay invisible (no org context is set), so a platform
    session cannot read tenant data through the ORM. Tenant reads under
    a support grant go through the SECURITY DEFINER functions in
    migration 0002 instead.
    """
    session = SessionLocal()
    try:
        session.begin()
        set_rls_context(session, None, None, platform_user_id)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def system_session() -> Iterator[Session]:
    """Yield a session with NO tenant context (RLS denies tenant rows).

    Used only for operations that must not see tenant data at all (health
    checks, global permission-catalog reads). Authentication lookups do NOT
    use this — they go through SECURITY DEFINER functions.
    """
    session = SessionLocal()
    try:
        session.begin()
        set_rls_context(session, None, None)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
