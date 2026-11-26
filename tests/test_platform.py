"""Platform-domain tests: two-domain separation, platform auth, admin
directory, platform roles, MFA step-up, support grants, platform audit.

All tests run against the real API + real PostgreSQL test database — no
mocks of the app layer. Tests are order-independent: they assert scoping
and membership, never exact counts on shared tables, and use unique
emails per test so parallel/previous runs cannot collide.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app.security import decode_local_token, issue_platform_access_token
from app.seed import DEV_PASSWORD

PLATFORM_LOGIN = "/api/v1/platform/auth/login"
PLATFORM_ME = "/api/v1/platform/auth/me"

# The six seeded platform role templates (app/permissions.py).
PLATFORM_ROLE_TEMPLATES = {
    "Platform Super Admin",
    "Platform Administrator",
    "Platform Support",
    "Security Administrator",
    "Billing Administrator",
    "Platform Auditor",
}

PLATFORM_ENDPOINTS = [
    "/api/v1/platform/admins",
    "/api/v1/platform/roles",
    "/api/v1/platform/tenants",
    "/api/v1/platform/audit",
    "/api/v1/platform/support-grants",
    "/api/v1/platform/permissions",
    "/api/v1/platform/auth/me",
]

ORG_ENDPOINTS = [
    "/api/v1/tickets",
    "/api/v1/roles",
    "/api/v1/audit",
    "/api/v1/users",
]


# --- helpers -----------------------------------------------------------------


def _uniq_email(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}@example.com"


def _platform_login(client, email: str, password: str = DEV_PASSWORD) -> dict:
    resp = client.post(PLATFORM_LOGIN, json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_platform_user(client, admin_headers, email: str | None = None) -> dict:
    email = email or _uniq_email("plat")
    resp = client.post(
        "/api/v1/platform/admins",
        json={"email": email, "full_name": "Test Platform User", "password": DEV_PASSWORD},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _platform_role_id(client, headers, name: str) -> str:
    roles = client.get("/api/v1/platform/roles", headers=headers).json()
    for role in roles:
        if role["name"] == name:
            return role["id"]
    raise AssertionError(f"platform role {name} not found")


def _assign_platform_role(client, admin_headers, user_id: str, role_id: str) -> None:
    resp = client.post(
        f"/api/v1/platform/admins/{user_id}/roles",
        json={"role_id": role_id},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text


def _future_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def _restore_super_admin_role(platform_user_id: str, super_admin_role_id: str) -> None:
    """Re-grant the Platform Super Admin role via the owner session.

    Used only as cleanup after the last-Super-Admin test deliberately
    revokes the fixture super admin's role (the API cannot restore it:
    no remaining caller holds the grant scope for the Super Admin role).
    The owner role bypasses RLS; the platform context is still set.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.database import set_rls_context
    from app.models.platform_admin import PlatformUserRole
    from tests.conftest import TEST_OWNER_URL

    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        set_rls_context(session, None, None, uuid.UUID(platform_user_id))
        session.add(
            PlatformUserRole(
                platform_user_id=uuid.UUID(platform_user_id),
                role_id=uuid.UUID(super_admin_role_id),
                granted_by_id=uuid.UUID(platform_user_id),
            )
        )
        session.commit()
    finally:
        session.close()


# --- 1. Domain separation ----------------------------------------------------


def test_org_token_rejected_on_every_platform_endpoint(client, acme_admin):
    for path in PLATFORM_ENDPOINTS:
        resp = client.get(path, headers=acme_admin["headers"])
        assert resp.status_code == 401, f"{path} -> {resp.status_code}: {resp.text}"
    # An org identity cannot log in through the platform login either.
    resp = client.post(PLATFORM_LOGIN, json={"email": "alice@acme.example.com", "password": DEV_PASSWORD})
    assert resp.status_code == 401, resp.text
    # No token at all is also rejected.
    assert client.get("/api/v1/platform/admins").status_code == 401


def test_platform_token_rejected_on_org_endpoints(client, platform_admin):
    for path in ORG_ENDPOINTS:
        resp = client.get(path, headers=platform_admin["headers"])
        assert resp.status_code == 401, f"{path} -> {resp.status_code}: {resp.text}"
    assert (
        client.post(
            "/api/v1/tickets",
            json={"title": "x"},
            headers=platform_admin["headers"],
        ).status_code
        == 401
    )


# --- 2. Platform login ---------------------------------------------------------


def test_platform_login_success_wrong_password_unknown_email(client):
    data = _platform_login(client, "platform@null.example.com")
    assert data["status"] == "ok"
    assert data["access_token"] and data["refresh_token"]
    # The dev super admin has no MFA enrolled, so its token is mfa=true
    # directly — there is nothing to step up from.
    claims = decode_local_token(data["access_token"], expected_type="platform_access")
    assert claims.mfa is True
    assert claims.email == "platform@null.example.com"
    # The platform token decodes as platform_access, never as org access.
    with pytest.raises(Exception):
        decode_local_token(data["access_token"], expected_type="access")

    wrong = client.post(PLATFORM_LOGIN, json={"email": "platform@null.example.com", "password": "WrongPass123!@#"})
    assert wrong.status_code == 401, wrong.text
    unknown = client.post(PLATFORM_LOGIN, json={"email": "nobody@null.example.com", "password": DEV_PASSWORD})
    assert unknown.status_code == 401, unknown.text


# --- 3/4. Org roles can never touch platform permissions ----------------------


def test_org_role_cannot_grant_platform_permissions(client, acme_admin):
    """POST /api/v1/roles with a platform:* code is rejected.

    Note on the status: the grant-scope check runs first — no org
    principal can hold a platform:* code, so the attempt is a 403
    ("Cannot grant permissions you do not hold"). The service-level
    ValueError (400, "Organization roles cannot grant platform
    permissions") is defense-in-depth behind it and is unreachable via
    the API; the rejection itself is what matters here.
    """
    resp = client.post(
        "/api/v1/roles",
        json={
            "name": f"Platform Grab-{secrets.token_hex(4)}",
            "permission_codes": ["platform:users:read"],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 403, resp.text
    # Same for a role named "Platform Super Admin" that grants platform codes.
    resp = client.post(
        "/api/v1/roles",
        json={
            "name": "Platform Super Admin",
            "permission_codes": ["platform:users:manage", "platform:roles:manage"],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 403, resp.text


def test_org_role_permissions_cannot_be_configured_with_platform_codes(client, acme_admin):
    roles = client.get("/api/v1/roles", headers=acme_admin["headers"]).json()
    role_id = next(r["id"] for r in roles if r["name"] == "Organization Administrator")
    resp = client.put(
        f"/api/v1/roles/{role_id}/permissions",
        json={"permission_codes": ["tickets:read", "platform:tenants:read"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 403, resp.text
    # The role is unchanged: still no platform:* permission.
    after = client.get(f"/api/v1/roles/{role_id}", headers=acme_admin["headers"]).json()
    assert not any(p.startswith("platform:") for p in after["permissions"])


def test_org_permission_catalog_contains_no_platform_codes(client, acme_admin):
    catalog = client.get("/api/v1/users/permissions/catalog", headers=acme_admin["headers"])
    assert catalog.status_code == 200, catalog.text
    assert catalog.json(), "org catalog must not be empty"
    assert not any(p["code"].startswith("platform:") for p in catalog.json())
    # The org roles list itself never grants a platform:* code either.
    roles = client.get("/api/v1/roles", headers=acme_admin["headers"]).json()
    assert roles
    assert not any(p.startswith("platform:") for role in roles for p in role["permissions"])


# --- 5. Org admin cannot access Platform Administration ------------------------


def test_org_admin_cannot_access_platform_administration(client, acme_admin, org_ids):
    for path in [
        "/api/v1/platform/admins",
        "/api/v1/platform/roles",
        "/api/v1/platform/tenants",
        "/api/v1/platform/audit",
        "/api/v1/platform/support-grants",
    ]:
        resp = client.get(path, headers=acme_admin["headers"])
        assert resp.status_code in (401, 403), f"{path} -> {resp.status_code}"
    # Even a single-tenant read is denied to the org token.
    resp = client.get(f"/api/v1/platform/tenants/{org_ids['acme']}", headers=acme_admin["headers"])
    assert resp.status_code in (401, 403), resp.text


# --- 6. No grant => no tenant users, and no leak via audit ---------------------


def test_platform_admin_without_grant_sees_no_tenant_users(client, platform_admin, org_ids):
    resp = client.get(
        f"/api/v1/platform/tenants/{org_ids['globex']}/users",
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == []  # indistinguishable from an org with no users
    # The audited read reveals nothing about the org's users either.
    audit = client.get(
        "/api/v1/platform/audit",
        params={"action": "platform.tenant_users_read", "organization_id": org_ids["globex"]},
        headers=platform_admin["headers"],
    )
    assert audit.status_code == 200, audit.text
    entries = [e for e in audit.json() if e["resource_id"] == org_ids["globex"]]
    assert entries, "the tenant-users read must be audited"
    for entry in entries:
        assert "@" not in str(entry["metadata"]), entry
        assert entry["metadata"].get("returned") == 0


# --- 7. Platform admin directory -------------------------------------------------


def test_platform_admin_directory(client, platform_admin):
    listing = client.get("/api/v1/platform/admins", headers=platform_admin["headers"])
    assert listing.status_code == 200, listing.text
    emails = [u["email"] for u in listing.json()]
    assert "platform@null.example.com" in emails

    email = _uniq_email("admin")
    created = _create_platform_user(client, platform_admin["headers"], email)
    assert created["email"] == email
    assert created["is_active"] is True
    assert created["mfa_enabled"] is False
    assert created["roles"] == []
    user_id = created["id"]

    # Single-admin read.
    got = client.get(f"/api/v1/platform/admins/{user_id}", headers=platform_admin["headers"])
    assert got.status_code == 200 and got.json()["email"] == email

    # Duplicate email fails.
    dup = client.post(
        "/api/v1/platform/admins",
        json={"email": email, "full_name": "Dup", "password": DEV_PASSWORD},
        headers=platform_admin["headers"],
    )
    assert dup.status_code == 400, dup.text

    # Suspend -> login refused -> reactivate -> login works again.
    suspended = client.patch(f"/api/v1/platform/admins/{user_id}/suspend", headers=platform_admin["headers"])
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["is_active"] is False
    denied = client.post(PLATFORM_LOGIN, json={"email": email, "password": DEV_PASSWORD})
    assert denied.status_code == 401, denied.text
    reactivated = client.post(f"/api/v1/platform/admins/{user_id}/reactivate", headers=platform_admin["headers"])
    assert reactivated.status_code == 200, reactivated.text
    assert reactivated.json()["is_active"] is True
    assert _platform_login(client, email)["status"] == "ok"

    # Self-suspend is refused.
    me = client.get(PLATFORM_ME, headers=platform_admin["headers"]).json()
    self_suspend = client.patch(
        f"/api/v1/platform/admins/{me['platform_user_id']}/suspend",
        headers=platform_admin["headers"],
    )
    assert self_suspend.status_code == 400, self_suspend.text


# --- 8. Platform roles -------------------------------------------------------------


def test_platform_roles(client, platform_admin):
    roles = client.get("/api/v1/platform/roles", headers=platform_admin["headers"])
    assert roles.status_code == 200, roles.text
    names = {r["name"] for r in roles.json()}
    assert PLATFORM_ROLE_TEMPLATES <= names
    # System templates are flagged as such.
    assert all(r["is_system"] for r in roles.json() if r["name"] in PLATFORM_ROLE_TEMPLATES)

    # The platform permission catalog is the platform:* namespace only.
    catalog = client.get("/api/v1/platform/permissions", headers=platform_admin["headers"])
    assert catalog.status_code == 200, catalog.text
    codes = [p["code"] for p in catalog.json()]
    assert len(codes) == 17
    assert all(c.startswith("platform:") for c in codes)
    assert "platform:roles:manage" in codes

    # Create a custom role with a subset, configure it, update it, delete it.
    name = f"Custom Reader-{secrets.token_hex(4)}"
    created = client.post(
        "/api/v1/platform/roles",
        json={
            "name": name,
            "description": "Read-only test role",
            "access_level": "Read-Only",
            "permission_codes": ["platform:tenants:read", "platform:health:read"],
        },
        headers=platform_admin["headers"],
    )
    assert created.status_code == 201, created.text
    assert set(created.json()["permissions"]) == {"platform:tenants:read", "platform:health:read"}
    role_id = created.json()["id"]

    configured = client.put(
        f"/api/v1/platform/roles/{role_id}/permissions",
        json={"permission_codes": ["platform:tenants:read"]},
        headers=platform_admin["headers"],
    )
    assert configured.status_code == 200, configured.text
    assert configured.json()["permissions"] == ["platform:tenants:read"]

    updated = client.patch(
        f"/api/v1/platform/roles/{role_id}",
        json={"description": "Updated description"},
        headers=platform_admin["headers"],
    )
    assert updated.status_code == 200 and updated.json()["description"] == "Updated description"

    got = client.get(f"/api/v1/platform/roles/{role_id}", headers=platform_admin["headers"])
    assert got.status_code == 200 and got.json()["name"] == name

    # A platform role cannot hold a non-platform permission. (Same
    # grant-scope-first ordering as the org side: the fixture holds all
    # platform:* codes but not "tickets:read", so the attempt is a 403;
    # the service-level 400 for non-platform codes is defense-in-depth
    # behind it.)
    bad = client.post(
        "/api/v1/platform/roles",
        json={
            "name": f"Bad Role-{secrets.token_hex(4)}",
            "permission_codes": ["tickets:read"],
        },
        headers=platform_admin["headers"],
    )
    assert bad.status_code == 403, bad.text

    deleted = client.delete(f"/api/v1/platform/roles/{role_id}", headers=platform_admin["headers"])
    assert deleted.status_code == 204, deleted.text
    # System roles cannot be deleted.
    super_admin_id = _platform_role_id(client, platform_admin["headers"], "Platform Super Admin")
    assert (
        client.delete(f"/api/v1/platform/roles/{super_admin_id}", headers=platform_admin["headers"]).status_code == 400
    )


def test_platform_administrator_cannot_create_roles_manage_role(client, platform_admin):
    """A Platform Administrator holds every platform permission EXCEPT
    platform:roles:manage, so grant scope blocks them from creating (or
    configuring) a role that holds it."""
    admin_user = _create_platform_user(client, platform_admin["headers"])
    _assign_platform_role(
        client,
        platform_admin["headers"],
        admin_user["id"],
        _platform_role_id(client, platform_admin["headers"], "Platform Administrator"),
    )
    admin_headers = _headers(_platform_login(client, admin_user["email"])["access_token"])

    attempt = client.post(
        "/api/v1/platform/roles",
        json={
            "name": f"Escalation-{secrets.token_hex(4)}",
            "permission_codes": ["platform:roles:manage", "platform:tenants:read"],
        },
        headers=admin_headers,
    )
    assert attempt.status_code == 403, attempt.text

    # Same boundary on configuring an existing custom role.
    custom = client.post(
        "/api/v1/platform/roles",
        json={
            "name": f"Target-{secrets.token_hex(4)}",
            "permission_codes": ["platform:tenants:read"],
        },
        headers=platform_admin["headers"],
    ).json()
    attempt2 = client.put(
        f"/api/v1/platform/roles/{custom['id']}/permissions",
        json={"permission_codes": ["platform:roles:manage"]},
        headers=admin_headers,
    )
    assert attempt2.status_code == 403, attempt2.text
    # Cleanup: the fixture super admin removes the custom role.
    assert client.delete(f"/api/v1/platform/roles/{custom['id']}", headers=platform_admin["headers"]).status_code == 204


def test_only_super_admin_can_assign_super_admin_role(client, platform_admin):
    target = _create_platform_user(client, platform_admin["headers"])
    admin_user = _create_platform_user(client, platform_admin["headers"])
    _assign_platform_role(
        client,
        platform_admin["headers"],
        admin_user["id"],
        _platform_role_id(client, platform_admin["headers"], "Platform Administrator"),
    )
    admin_headers = _headers(_platform_login(client, admin_user["email"])["access_token"])
    super_admin_id = _platform_role_id(client, platform_admin["headers"], "Platform Super Admin")

    # A Platform Administrator attempting the assignment gets 403.
    attempt = client.post(
        f"/api/v1/platform/admins/{target['id']}/roles",
        json={"role_id": super_admin_id},
        headers=admin_headers,
    )
    assert attempt.status_code == 403, attempt.text

    # The Super Admin can assign it — and revoke it again (not the last one).
    _assign_platform_role(client, platform_admin["headers"], target["id"], super_admin_id)
    listing = client.get(f"/api/v1/platform/admins/{target['id']}", headers=platform_admin["headers"]).json()
    assert "Platform Super Admin" in listing["roles"]
    revoked = client.delete(
        f"/api/v1/platform/admins/{target['id']}/roles/{super_admin_id}",
        headers=platform_admin["headers"],
    )
    assert revoked.status_code == 204, revoked.text

    # Nobody can assign a role to themselves.
    self_assign = client.post(
        f"/api/v1/platform/admins/{platform_admin['user_id']}/roles",
        json={"role_id": super_admin_id},
        headers=platform_admin["headers"],
    )
    assert self_assign.status_code == 400, self_assign.text


def test_revoke_last_super_admin_role_refused(client, platform_admin):
    """The last Platform Super Admin's role cannot be revoked.

    The actor here is NOT a Super Admin: a custom role holding
    platform:roles:manage + platform:users:manage can reach the
    last-holder check (a Super Admin actor could never hit it, since
    they would themselves be a remaining holder). The fixture's role
    is restored via the owner session afterwards — the API cannot
    restore it, because no remaining caller holds the grant scope.
    """
    super_admin_id = _platform_role_id(client, platform_admin["headers"], "Platform Super Admin")
    user_a = _create_platform_user(client, platform_admin["headers"])
    _assign_platform_role(client, platform_admin["headers"], user_a["id"], super_admin_id)

    manager_role = client.post(
        "/api/v1/platform/roles",
        json={
            "name": f"Scoped Role Manager-{secrets.token_hex(4)}",
            "description": "Holds roles:manage without being Super Admin",
            "access_level": "Privileged",
            "permission_codes": ["platform:roles:manage", "platform:users:manage"],
        },
        headers=platform_admin["headers"],
    )
    assert manager_role.status_code == 201, manager_role.text
    user_b = _create_platform_user(client, platform_admin["headers"])
    _assign_platform_role(client, platform_admin["headers"], user_b["id"], manager_role.json()["id"])
    manager_headers = _headers(_platform_login(client, user_b["email"])["access_token"])

    try:
        # Revoking the fixture's role succeeds while user A still holds it.
        revoked = client.delete(
            f"/api/v1/platform/admins/{platform_admin['user_id']}/roles/{super_admin_id}",
            headers=manager_headers,
        )
        assert revoked.status_code == 204, revoked.text
        # Revoking user A's role now would leave NO Super Admin: refused.
        last = client.delete(
            f"/api/v1/platform/admins/{user_a['id']}/roles/{super_admin_id}",
            headers=manager_headers,
        )
        assert last.status_code == 400, last.text
        assert "last" in last.json()["detail"].lower()
    finally:
        _restore_super_admin_role(platform_admin["user_id"], super_admin_id)
    # The fixture is a Super Admin again.
    assert client.get("/api/v1/platform/admins", headers=platform_admin["headers"]).status_code == 200


# --- 9. MFA step-up -------------------------------------------------------------


def test_mfa_step_up(client, platform_admin, org_ids):
    user = _create_platform_user(client, platform_admin["headers"])
    _assign_platform_role(
        client,
        platform_admin["headers"],
        user["id"],
        _platform_role_id(client, platform_admin["headers"], "Platform Support"),
    )
    login = _platform_login(client, user["email"])
    user_headers = _headers(login["access_token"])

    # Enroll TOTP via the API.
    enrolled = client.post("/api/v1/platform/auth/mfa-enroll", headers=user_headers)
    assert enrolled.status_code == 200, enrolled.text
    secret = enrolled.json()["secret"]
    assert enrolled.json()["otpauth_uri"].startswith("otpauth://")
    assert secret

    # A wrong code does not enable MFA.
    wrong = client.post("/api/v1/platform/auth/mfa-verify", json={"code": "000000"}, headers=user_headers)
    assert wrong.status_code == 400, wrong.text

    # The correct pyotp-generated code enables it.
    code = pyotp.TOTP(secret).now()
    verified = client.post("/api/v1/platform/auth/mfa-verify", json={"code": code}, headers=user_headers)
    assert verified.status_code == 200, verified.text
    assert verified.json()["mfa_enabled"] is True

    # Password-only login now returns mfa_required, with no access token.
    pending = client.post(PLATFORM_LOGIN, json={"email": user["email"], "password": DEV_PASSWORD})
    assert pending.status_code == 200, pending.text
    assert pending.json()["status"] == "mfa_required"
    assert pending.json()["access_token"] is None
    assert pending.json()["mfa_token"]

    # A wrong challenge code fails; the right one yields an mfa=true token.
    bad_challenge = client.post(
        "/api/v1/platform/auth/mfa-challenge",
        json={"mfa_token": pending.json()["mfa_token"], "code": "000000"},
    )
    assert bad_challenge.status_code == 401, bad_challenge.text
    challenged = client.post(
        "/api/v1/platform/auth/mfa-challenge",
        json={"mfa_token": pending.json()["mfa_token"], "code": pyotp.TOTP(secret).now()},
    )
    assert challenged.status_code == 200, challenged.text
    assert challenged.json()["status"] == "ok"
    claims = decode_local_token(challenged.json()["access_token"], expected_type="platform_access")
    assert claims.mfa is True

    # A token with mfa=false: read endpoints work, manage endpoints refuse.
    low_token = issue_platform_access_token(user["id"], user["email"], mfa=False)
    assert decode_local_token(low_token, expected_type="platform_access").mfa is False
    low_headers = _headers(low_token)
    assert client.get("/api/v1/platform/support-grants", headers=low_headers).status_code == 200
    manage = client.post(
        "/api/v1/platform/support-grants",
        json={
            "organization_id": org_ids["acme"],
            "purpose": "mfa=false must not manage",
            "expires_at": _future_expiry(),
        },
        headers=low_headers,
    )
    assert manage.status_code == 403, manage.text


# --- 10. Support grants + audit ---------------------------------------------------


def test_support_grants_and_audit(client, platform_admin, org_ids):
    support_user = _create_platform_user(client, platform_admin["headers"])
    _assign_platform_role(
        client,
        platform_admin["headers"],
        support_user["id"],
        _platform_role_id(client, platform_admin["headers"], "Platform Support"),
    )
    support_headers = _headers(_platform_login(client, support_user["email"])["access_token"])

    admin_user = _create_platform_user(client, platform_admin["headers"])
    _assign_platform_role(
        client,
        platform_admin["headers"],
        admin_user["id"],
        _platform_role_id(client, platform_admin["headers"], "Platform Administrator"),
    )
    admin_headers = _headers(_platform_login(client, admin_user["email"])["access_token"])

    # Request a grant for Acme (pending).
    grant = client.post(
        "/api/v1/platform/support-grants",
        json={
            "organization_id": org_ids["acme"],
            "purpose": "Investigate Acme ticket sync",
            "expires_at": _future_expiry(),
        },
        headers=support_headers,
    )
    assert grant.status_code == 201, grant.text
    assert grant.json()["status"] == "pending"
    grant_id = grant.json()["id"]

    # The requester cannot approve their own grant.
    self_approve = client.post(f"/api/v1/platform/support-grants/{grant_id}/approve", headers=support_headers)
    assert self_approve.status_code == 403, self_approve.text

    # A Platform Administrator approves it (active).
    approved = client.post(f"/api/v1/platform/support-grants/{grant_id}/approve", headers=admin_headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "active"
    assert approved.json()["approved_by_id"] == admin_user["id"]

    # The grant unlocks Acme's users for the grantee. (Membership, not
    # exact equality: other tests may invite extra users into Acme.)
    users = client.get(f"/api/v1/platform/tenants/{org_ids['acme']}/users", headers=support_headers)
    assert users.status_code == 200, users.text
    emails = {u["email"] for u in users.json()}
    assert {"alice@acme.example.com", "tom@acme.example.com"} <= emails
    returned_count = len(users.json())

    # The read wrote a platform audit event for that org.
    audit = client.get(
        "/api/v1/platform/audit",
        params={"action": "platform.tenant_users_read", "organization_id": org_ids["acme"]},
        headers=platform_admin["headers"],
    )
    assert audit.status_code == 200, audit.text
    assert any(
        e["resource_id"] == org_ids["acme"] and e["metadata"].get("returned") == returned_count for e in audit.json()
    ), audit.json()

    # A grant for Acme does NOT unlock Globex's users.
    globex_users = client.get(f"/api/v1/platform/tenants/{org_ids['globex']}/users", headers=support_headers)
    assert globex_users.status_code == 200, globex_users.text
    assert globex_users.json() == []

    # Revoke the grant -> the same users read returns [] again.
    revoked = client.post(f"/api/v1/platform/support-grants/{grant_id}/revoke", headers=admin_headers)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    users_after = client.get(f"/api/v1/platform/tenants/{org_ids['acme']}/users", headers=support_headers)
    assert users_after.status_code == 200, users_after.text
    assert users_after.json() == []
    # A revoked grant cannot be approved.
    assert client.post(f"/api/v1/platform/support-grants/{grant_id}/approve", headers=admin_headers).status_code == 400


# --- 11. Platform audit append-only ----------------------------------------------


def test_platform_audit_records_cannot_be_modified_via_db(client, platform_admin, app_db):
    """Direct UPDATE/DELETE on platform_audit_logs as the app role is
    denied: the RLS policy set contains no UPDATE or DELETE policy.

    Same PostgreSQL default-deny semantics as the org audit test — the
    commands affect ZERO rows rather than raising.
    """
    # Ensure at least one platform audit row exists (a login writes one).
    _platform_login(client, "platform@null.example.com")
    with app_db.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_platform_user_id', %s, false)",
            (platform_admin["user_id"],),
        )
        cur.execute("SELECT id FROM platform_audit_logs LIMIT 1")
        row = cur.fetchone()
        assert row is not None
        audit_id = row[0]
        cur.execute("UPDATE platform_audit_logs SET outcome = 'tampered' WHERE id = %s", (audit_id,))
        assert cur.rowcount == 0, "platform audit UPDATE must affect no rows (append-only)"
        cur.execute("DELETE FROM platform_audit_logs WHERE id = %s", (audit_id,))
        assert cur.rowcount == 0, "platform audit DELETE must affect no rows (append-only)"
        cur.execute("SELECT outcome FROM platform_audit_logs WHERE id = %s", (audit_id,))
        assert cur.fetchone()[0] != "tampered"


def test_no_platform_audit_write_api_endpoints(client, platform_admin):
    fake_id = str(uuid.uuid4())
    assert client.put(f"/api/v1/platform/audit/{fake_id}", json={}, headers=platform_admin["headers"]).status_code in (
        404,
        405,
    )
    assert client.delete(f"/api/v1/platform/audit/{fake_id}", headers=platform_admin["headers"]).status_code in (
        404,
        405,
    )
    assert client.patch(
        f"/api/v1/platform/audit/{fake_id}", json={}, headers=platform_admin["headers"]
    ).status_code in (404, 405)
    assert client.post("/api/v1/platform/audit", json={}, headers=platform_admin["headers"]).status_code in (404, 405)


# --- 12. Tenant isolation at the platform layer ------------------------------------


def test_platform_tenant_list_and_org_admin_cannot_list(client, platform_admin, acme_admin):
    tenants = client.get("/api/v1/platform/tenants", headers=platform_admin["headers"])
    assert tenants.status_code == 200, tenants.text
    by_slug = {t["slug"]: t for t in tenants.json()}
    assert {"acme", "globex"} <= set(by_slug)
    assert by_slug["acme"]["name"] == "Acme IT Services"
    assert by_slug["globex"]["name"] == "Globex Manufacturing"
    assert by_slug["acme"]["is_dev_fixture"] is True

    # Single-tenant read.
    acme_id = by_slug["acme"]["id"]
    got = client.get(f"/api/v1/platform/tenants/{acme_id}", headers=platform_admin["headers"])
    assert got.status_code == 200 and got.json()["slug"] == "acme"

    # An org admin's token cannot list tenants.
    assert client.get("/api/v1/platform/tenants", headers=acme_admin["headers"]).status_code in (
        401,
        403,
    )


# --- 13. Refresh rotation for platform sessions --------------------------------------


def test_platform_refresh_rotation_and_logout(client, platform_admin):
    user = _create_platform_user(client, platform_admin["headers"])
    login = _platform_login(client, user["email"])
    assert login["status"] == "ok"

    # Refresh returns a NEW token pair, preserving mfa=true. (The access
    # token is a second-granularity JWT, so one issued in the same second
    # as the login token may be byte-identical — the refresh token, being
    # opaque random, is the reliable "new token" check.)
    refreshed = client.post("/api/v1/platform/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["refresh_token"] != login["refresh_token"]
    claims = decode_local_token(refreshed.json()["access_token"], expected_type="platform_access")
    assert claims.mfa is True

    # The old refresh token is revoked: second use fails.
    reuse = client.post("/api/v1/platform/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert reuse.status_code == 401, reuse.text

    # An unknown refresh token fails too.
    assert (
        client.post(
            "/api/v1/platform/auth/refresh",
            json={"refresh_token": secrets.token_urlsafe(32)},
        ).status_code
        == 401
    )

    # Logout revokes the refresh token.
    headers = _headers(refreshed.json()["access_token"])
    logged_out = client.post(
        "/api/v1/platform/auth/logout",
        json={"refresh_token": refreshed.json()["refresh_token"]},
        headers=headers,
    )
    assert logged_out.status_code == 200, logged_out.text
    after_logout = client.post(
        "/api/v1/platform/auth/refresh",
        json={"refresh_token": refreshed.json()["refresh_token"]},
    )
    assert after_logout.status_code == 401, after_logout.text
