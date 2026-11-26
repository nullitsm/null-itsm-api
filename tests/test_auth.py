"""Health + authentication tests."""

from __future__ import annotations

import time

import jwt

from app.seed import DEV_PASSWORD


def test_liveness(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_readiness_database_ok(client):
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["checks"]["database"] == "ok"


def test_login_wrong_password_rejected(client):
    resp = client.post("/api/v1/auth/login", json={"email": "alice@acme.example.com", "password": "wrong-password"})
    assert resp.status_code == 401


def test_login_unknown_user_rejected(client):
    resp = client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "whatever123"})
    assert resp.status_code == 401


def test_me_returns_principal(client, acme_admin):
    resp = client.get("/api/v1/auth/me", headers=acme_admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "alice@acme.example.com"
    assert body["is_org_owner"] is True
    assert "tickets:create" in body["permissions"]


def test_me_without_token_unauthorized(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_expired_access_token_rejected(client):
    token = jwt.encode(
        {
            "sub": "00000000-0000-0000-0000-000000000000",
            "org": None,
            "email": "x@y.z",
            "type": "access",
            "iat": int(time.time()) - 3600,
            "exp": int(time.time()) - 60,
        },
        "test-only-jwt-secret-for-pytest",
        algorithm="HS256",
    )
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_refresh_rotation_rejects_old_token(client, acme_admin):
    refresh_token = acme_admin["tokens"]["refresh_token"]
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    new_refresh = resp.json()["refresh_token"]
    assert new_refresh != refresh_token
    # The old refresh token must now be rejected (rotation).
    resp2 = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp2.status_code == 401
    # The new one works.
    resp3 = client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert resp3.status_code == 200


def test_logout_revokes_refresh_token(client):
    login = client.post("/api/v1/auth/login", json={"email": "alice@acme.example.com", "password": DEV_PASSWORD}).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    resp = client.post("/api/v1/auth/logout", json={"refresh_token": login["refresh_token"]}, headers=headers)
    assert resp.status_code == 200
    resp2 = client.post("/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert resp2.status_code == 401


def test_mfa_enrol_verify_and_login(client):
    # Log in as the Acme technician, enrol MFA, verify, then prove that
    # the next login requires the TOTP challenge.
    import pyotp

    login = client.post("/api/v1/auth/login", json={"email": "tom@acme.example.com", "password": DEV_PASSWORD}).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    enrol = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert enrol.status_code == 200
    secret = enrol.json()["secret"]
    code = pyotp.TOTP(secret).now()
    verify = client.post("/api/v1/auth/mfa/verify-enrollment", json={"code": code}, headers=headers)
    assert verify.status_code == 200
    assert verify.json()["mfa_enabled"] is True

    login2 = client.post("/api/v1/auth/login", json={"email": "tom@acme.example.com", "password": DEV_PASSWORD})
    assert login2.status_code == 200
    assert login2.json()["status"] == "mfa_required"
    mfa_token = login2.json()["mfa_token"]
    challenge = client.post(
        "/api/v1/auth/mfa/challenge",
        json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()},
    )
    assert challenge.status_code == 200
    assert challenge.json()["status"] == "ok"

    # Wrong TOTP code is rejected.
    login3 = client.post("/api/v1/auth/login", json={"email": "tom@acme.example.com", "password": DEV_PASSWORD}).json()
    bad = client.post(
        "/api/v1/auth/mfa/challenge",
        json={"mfa_token": login3["mfa_token"], "code": "000000"},
    )
    assert bad.status_code == 401

    # Disable MFA again so later tests are unaffected.
    login4 = client.post("/api/v1/auth/login", json={"email": "tom@acme.example.com", "password": DEV_PASSWORD}).json()
    mfa_token4 = login4["mfa_token"]
    challenge4 = client.post(
        "/api/v1/auth/mfa/challenge",
        json={"mfa_token": mfa_token4, "code": pyotp.TOTP(secret).now()},
    ).json()
    headers4 = {"Authorization": f"Bearer {challenge4['access_token']}"}
    disable = client.post("/api/v1/auth/mfa/disable", headers=headers4)
    assert disable.status_code == 200


def test_password_reset_request_always_ok(client):
    resp = client.post("/api/v1/auth/password-reset/request", json={"email": "nobody@example.com"})
    assert resp.status_code == 200  # no user enumeration


def test_password_reset_confirm_flow(client):
    # Create a reset row the same way the service does (token + hash),
    # then confirm with the raw token.
    import hashlib
    import secrets
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models.auth import PasswordReset
    from app.models.platform import User
    from tests.conftest import TEST_OWNER_URL

    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        from app.database import set_rls_context

        user = session.query(User).filter(User.email == "alice@acme.example.com").one()
        set_rls_context(session, None, user.id)
        token = secrets.token_urlsafe(32)
        session.add(
            PasswordReset(
                user_id=user.id,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=60),
            )
        )
        session.commit()
    finally:
        session.close()

    resp = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "NewDevPass123!@#"},
    )
    assert resp.status_code == 200, resp.text
    # The new password works, the old one does not.
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "alice@acme.example.com", "password": "NewDevPass123!@#"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "alice@acme.example.com", "password": DEV_PASSWORD}
        ).status_code
        == 401
    )
    # Reusing the token fails.
    assert (
        client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": token, "new_password": "AnotherPass123!@#"},
        ).status_code
        == 400
    )
    # Restore the fixture password for the rest of the suite.
    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        from app.database import set_rls_context
        from app.security import hash_password

        user = session.query(User).filter(User.email == "alice@acme.example.com").one()
        set_rls_context(session, None, user.id)
        user.password_hash = hash_password(DEV_PASSWORD)
        session.commit()
    finally:
        session.close()
