"""Pytest fixtures: real PostgreSQL, real migrations, real API.

The suite runs against a dedicated test database (``null_itsm_test``).
Setup order (session-scoped):
  1. Create the test database and the null_app / null_owner roles (as the
     postgres superuser).
  2. Run `alembic upgrade head` as the owner role.
  3. Seed the two clearly-labelled dev fixture organizations.
  4. Serve the FastAPI app with TestClient (database URLs pointed at the
     test database via environment variables set BEFORE importing the app).

Rate limiting is disabled for tests (slowapi limiter switch).
"""

from __future__ import annotations

import os
import uuid

import pytest

# --- Test database configuration (must be set before importing the app) ---
TEST_DB = "null_itsm_test"
SUPERUSER_URL = "postgresql+psycopg://postgres:dev_postgres_password@127.0.0.1:5432/postgres"
TEST_APP_URL = "postgresql+psycopg://null_app:dev_app_password@127.0.0.1:5432/null_itsm_test"
TEST_OWNER_URL = "postgresql+psycopg://null_owner:dev_owner_password@127.0.0.1:5432/null_itsm_test"

os.environ["NULL_ENV"] = "test"
os.environ["NULL_JWT_SECRET"] = "test-only-jwt-secret-for-pytest"
os.environ["NULL_DATABASE_URL"] = TEST_APP_URL
os.environ["NULL_DATABASE_OWNER_URL"] = TEST_OWNER_URL
os.environ["NULL_SEED_DEV_FIXTURES"] = "true"


def _setup_database() -> None:
    """Create roles + test database + migrations + fixtures (superuser).

    Runs exactly once per process, guarded by the NULL_TEST_DB_READY
    environment flag: pytest loads this file as ``conftest``, but test
    bodies also do ``from tests.conftest import ...``, which imports it
    a second time as ``tests.conftest`` — a distinct module object whose
    module-level code would otherwise run again. A second run would drop
    the database mid-test, terminate live connections, and re-seed new
    user ids (invalidating the session fixtures' JWTs).
    """
    if os.environ.get("NULL_TEST_DB_READY") == "1":
        return
    import psycopg
    from alembic.config import Config as AlembicConfig
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from alembic import command as alembic_command

    conn = psycopg.connect(SUPERUSER_URL.replace("+psycopg", ""), autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'null_app'")
            if cur.fetchone() is None:
                cur.execute("CREATE ROLE null_app LOGIN PASSWORD 'dev_app_password'")
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'null_owner'")
            if cur.fetchone() is None:
                cur.execute("CREATE ROLE null_owner LOGIN PASSWORD 'dev_owner_password'")
            # Terminate stray connections, then recreate the test database.
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                (TEST_DB,),
            )
            cur.execute(f'DROP DATABASE IF EXISTS "{TEST_DB}"')
            cur.execute(f'CREATE DATABASE "{TEST_DB}" OWNER null_owner')
    finally:
        conn.close()

    cfg = AlembicConfig(os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini"))
    alembic_command.upgrade(cfg, "head")

    from app.seed import seed_dev_fixtures

    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        seed_dev_fixtures(session)
    finally:
        session.close()
    os.environ["NULL_TEST_DB_READY"] = "1"


_setup_database()

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app, limiter  # noqa: E402
from app.seed import DEV_PASSWORD  # noqa: E402

limiter.enabled = False


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


def _login(client: TestClient, email: str, password: str = DEV_PASSWORD) -> dict:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture(scope="session")
def acme_admin(client) -> dict:
    data = _login(client, "alice@acme.example.com")
    assert data["status"] == "ok"
    return {"headers": {"Authorization": f"Bearer {data['access_token']}"}, "tokens": data}


@pytest.fixture(scope="session")
def acme_tech(client) -> dict:
    data = _login(client, "tom@acme.example.com")
    assert data["status"] == "ok"
    return {"headers": {"Authorization": f"Bearer {data['access_token']}"}, "tokens": data}


@pytest.fixture(scope="session")
def globex_admin(client) -> dict:
    data = _login(client, "gina@globex.example.com")
    assert data["status"] == "ok"
    return {"headers": {"Authorization": f"Bearer {data['access_token']}"}, "tokens": data}


@pytest.fixture(scope="session")
def globex_tech(client) -> dict:
    data = _login(client, "greg@globex.example.com")
    assert data["status"] == "ok"
    return {"headers": {"Authorization": f"Bearer {data['access_token']}"}, "tokens": data}


def _platform_login(client: TestClient, email: str, password: str = DEV_PASSWORD) -> dict:
    resp = client.post("/api/v1/platform/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture(scope="session")
def platform_admin(client) -> dict:
    """The dev platform super admin (platform@null.example.com).

    MFA is NOT enabled for this fixture user, so its login yields an
    mfa=true token directly. Never enable MFA on this user — tests that
    need an MFA-enabled platform user create a fresh one.
    """
    data = _platform_login(client, "platform@null.example.com")
    assert data["status"] == "ok"
    me = client.get("/api/v1/platform/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert me.status_code == 200, me.text
    return {
        "headers": {"Authorization": f"Bearer {data['access_token']}"},
        "token": data["access_token"],
        "tokens": data,
        "user_id": me.json()["platform_user_id"],
    }


@pytest.fixture(scope="session")
def org_ids(client, acme_admin, globex_admin) -> dict:
    """Organization ids for the two fixture orgs."""
    acme = client.get("/api/v1/auth/me", headers=acme_admin["headers"]).json()
    globex = client.get("/api/v1/auth/me", headers=globex_admin["headers"]).json()
    return {"acme": acme["organization_id"], "globex": globex["organization_id"]}


@pytest.fixture()
def app_db():
    """A raw psycopg connection as null_app (the application role)."""
    import psycopg

    conn = psycopg.connect(TEST_APP_URL.replace("+psycopg", ""), autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def set_rls(conn, org_id: str | None, user_id: str | None = None) -> None:
    """Set the RLS session variables on a raw connection."""
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.current_org_id', %s, false)", (org_id or "",))
        cur.execute("SELECT set_config('app.current_user_id', %s, false)", (user_id or "",))


def make_user_with_no_org(client: TestClient, email: str) -> dict:
    """Create a user directly in the DB (owner session) with no memberships,
    then log in: the API returns status 'no_org' with an org-less token."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from app.models.platform import User
    from app.security import hash_password

    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        # The users INSERT policy requires a non-empty org context (the
        # server controls this variable; a throwaway UUID is used here
        # because this user belongs to no organization yet).
        session.execute(
            text("SELECT set_config('app.current_org_id', :v, false)"),
            {"v": str(uuid.uuid4())},
        )
        user = User(
            id=uuid.uuid4(),
            email=email,
            full_name="No Org User",
            password_hash=hash_password(DEV_PASSWORD),
            email_verified=True,
        )
        # The user INSERT ... RETURNING is checked against the SELECT
        # policy (own row), so the user context must be this user's id.
        session.execute(
            text("SELECT set_config('app.current_user_id', :v, false)"),
            {"v": str(user.id)},
        )
        session.add(user)
        session.commit()
        user_id = str(user.id)
    finally:
        session.close()
    data = _login(client, email)
    assert data["status"] == "no_org", data
    return {"user_id": user_id, "access_token": data["access_token"]}
