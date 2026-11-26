"""RBAC tests: permission enforcement and grant-scope limits."""

from __future__ import annotations

import uuid


def _get_role_id(client, headers, name):
    roles = client.get("/api/v1/roles", headers=headers).json()
    for role in roles:
        if role["name"] == name:
            return role["id"]
    raise AssertionError(f"role {name} not found")


def _get_user_id(client, headers, email):
    users = client.get("/api/v1/users", headers=headers).json()
    for user in users:
        if user["email"] == email:
            return user["id"]
    raise AssertionError(f"user {email} not found")


def test_technician_cannot_access_admin_functions(client, acme_tech):
    # Technician (Service Desk) may read tickets but not manage roles,
    # read the audit log, or manage the organization.
    assert client.get("/api/v1/tickets", headers=acme_tech["headers"]).status_code == 200
    assert client.get("/api/v1/roles", headers=acme_tech["headers"]).status_code == 403
    assert client.get("/api/v1/audit", headers=acme_tech["headers"]).status_code == 403
    assert (
        client.post(
            "/api/v1/roles", json={"name": "X", "permission_codes": []}, headers=acme_tech["headers"]
        ).status_code
        == 403
    )


def test_technician_can_create_and_resolve_tickets(client, acme_tech):
    created = client.post(
        "/api/v1/tickets",
        json={"title": "Tech-created ticket", "priority": "low"},
        headers=acme_tech["headers"],
    )
    assert created.status_code == 201, created.text
    ticket_id = created.json()["id"]
    updated = client.patch(f"/api/v1/tickets/{ticket_id}", json={"status": "resolved"}, headers=acme_tech["headers"])
    assert updated.status_code == 200
    assert updated.json()["status"] == "resolved"


def test_auditor_is_read_only(client):
    # Give the Acme technician the Auditor role in a fresh org instead of
    # mutating fixtures: create an org, invite-style assignment via API.
    # Simpler: use the fixture technician's existing permissions — an
    # Auditor role exists in the org; assign it to a new user through the
    # invitation flow and log in as them.
    import secrets

    from tests.factories import TEST_PASSWORD as DEV_PASSWORD

    # Create a fresh org with a no-org user, then create an Auditor-only user.
    email = f"auditor-{secrets.token_hex(4)}@example.com"
    from tests.conftest import make_user_with_no_org

    user = make_user_with_no_org(client, email)
    headers = {"Authorization": f"Bearer {user['access_token']}"}
    org = client.post("/api/v1/organizations", json={"name": "Audit Org"}, headers=headers)
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    # Log in again to get an org-scoped token.
    login = client.post("/api/v1/auth/login", json={"email": email, "password": DEV_PASSWORD}).json()
    assert login["status"] == "ok"
    owner_headers = {"Authorization": f"Bearer {login['access_token']}"}
    auditor_role_id = _get_role_id(client, owner_headers, "Auditor")
    # The owner invites the auditor user into the org is not possible for
    # themselves; instead assign Auditor to the owner is wrong. Use a
    # second no-org user as the auditor.
    email2 = f"auditor2-{secrets.token_hex(4)}@example.com"
    make_user_with_no_org(client, email2)
    invite = client.post(
        f"/api/v1/organizations/{org_id}/invitations",
        json={"email": email2, "role_ids": [auditor_role_id]},
        headers=owner_headers,
    )
    assert invite.status_code == 201, invite.text
    # Accept the invitation (fetch the token hash path via DB is not
    # possible; use the accept endpoint with a token from the DB).
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models.auth import Invitation
    from app.security import hash_token, new_opaque_token
    from tests.conftest import TEST_OWNER_URL

    # Retoken the API-created invitation row with a KNOWN token so the
    # test can accept it. Only one pending invitation per (org, email)
    # may exist (migration 0018 enforces it with a partial unique
    # index), so no second row is created — the API invite already
    # assigned the Auditor role.
    token = new_opaque_token()
    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        from app.database import set_rls_context

        set_rls_context(session, uuid.UUID(org_id), uuid.UUID(user["user_id"]))
        inv = session.get(Invitation, uuid.UUID(invite.json()["id"]))
        inv.token_hash = hash_token(token)
        session.commit()
    finally:
        session.close()
    accepted = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Audrey Auditor", "password": DEV_PASSWORD},
    )
    assert accepted.status_code == 200, accepted.text
    login2 = client.post("/api/v1/auth/login", json={"email": email2, "password": DEV_PASSWORD}).json()
    assert login2["status"] == "ok"
    auditor_headers = {"Authorization": f"Bearer {login2['access_token']}"}
    # Auditor can read tickets and the audit log...
    assert client.get("/api/v1/tickets", headers=auditor_headers).status_code == 200
    assert client.get("/api/v1/audit", headers=auditor_headers).status_code == 200
    # ...but cannot create tickets or roles (read-only).
    assert client.post("/api/v1/tickets", json={"title": "x"}, headers=auditor_headers).status_code == 403
    assert (
        client.post("/api/v1/roles", json={"name": "X", "permission_codes": []}, headers=auditor_headers).status_code
        == 403
    )


def test_admin_cannot_grant_permissions_beyond_scope(client, acme_admin):
    """A granter holding only Service Desk permissions cannot create a
    role (or assign a role) that includes permissions they do not hold."""
    # Build a limited granter: create a custom role with roles:manage +
    # tickets:* only, assign it to the Acme technician, and try to use it
    # to grant an endpoint permission.
    role = client.post(
        "/api/v1/roles",
        json={
            "name": "Limited Granter",
            "description": "Can manage roles but holds few permissions.",
            "access_level": "Least Privilege",
            "permission_codes": ["roles:manage", "tickets:read", "tickets:create"],
        },
        headers=acme_admin["headers"],
    )
    assert role.status_code == 201, role.text
    role_id = role.json()["id"]
    tech_id = _get_user_id(client, acme_admin["headers"], "tom@acme.example.com")
    assigned = client.post(
        "/api/v1/roles/assign",
        json={"user_id": tech_id, "role_id": role_id},
        headers=acme_admin["headers"],
    )
    assert assigned.status_code == 200, assigned.text

    from tests.factories import TEST_PASSWORD as DEV_PASSWORD

    tech_login = client.post(
        "/api/v1/auth/login", json={"email": "tom@acme.example.com", "password": DEV_PASSWORD}
    ).json()
    tech_headers = {"Authorization": f"Bearer {tech_login['access_token']}"}
    # The limited granter tries to create a role granting endpoints:deploy
    # (which they do not hold) -> 403.
    attempt = client.post(
        "/api/v1/roles",
        json={
            "name": "Escalation Attempt",
            "permission_codes": ["endpoints:deploy"],
        },
        headers=tech_headers,
    )
    assert attempt.status_code == 403, attempt.text
    # They also cannot assign the Administrator role (it grants everything).
    admin_role_id = _get_role_id(client, acme_admin["headers"], "Organization Administrator")
    attempt2 = client.post(
        "/api/v1/roles/assign",
        json={"user_id": tech_id, "role_id": admin_role_id},
        headers=tech_headers,
    )
    assert attempt2.status_code == 403, attempt2.text
    # Cleanup: the fixture admin revokes the limited role.
    revoked = client.post(
        "/api/v1/roles/revoke",
        json={"user_id": tech_id, "role_id": role_id},
        headers=acme_admin["headers"],
    )
    assert revoked.status_code == 200, revoked.text
